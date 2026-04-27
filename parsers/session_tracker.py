# ─────────────────────────────────────────────────────────────────────────────
# parsers/session_tracker.py
# Tiene traccia di:
#   • ogni connessione TCP (handshake COTP CR/CC fino al termine)
#   • dentro ogni connessione, le "transazioni" applicative
#     (richiesta S7+ → risposta S7+, accoppiate per function+session_id)
#
# Strategia di correlazione:
#   1. Una nuova connessione nasce quando arriva una COTP-CR.
#   2. Si chiude su FIN/RST oppure al termine del PCAP.
#   3. Le PDU S7+ con opcode 0x31 sono richieste; con 0x32 sono risposte.
#   4. Una richiesta è "aperta" finché non arriva la risposta con stessa
#      coppia (function_code, session_id).
#   5. In caso di richieste multiple con stessa key (raro ma possibile),
#      le accoppiamo FIFO.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from parsers.cotp    import COTPFrame
from parsers.s7comm_plus import S7PlusFrame
from parsers.s7comm  import S7Frame
from parsers.tcp_reassembler import FlowKey


@dataclass
class Transaction:
    """Una coppia richiesta-risposta correlata."""
    seq_no   : int                                  # progressivo nella sessione
    request_ts  : float
    request_frame  : Optional[S7PlusFrame | S7Frame] = None
    response_ts : Optional[float] = None
    response_frame : Optional[S7PlusFrame | S7Frame] = None

    @property
    def is_complete(self) -> bool:
        return self.response_frame is not None

    @property
    def latency_ms(self) -> Optional[float]:
        if self.response_ts is None:
            return None
        return (self.response_ts - self.request_ts) * 1000.0


@dataclass
class Session:
    """Una connessione TCP completa fra due endpoint."""
    forward_key  : FlowKey         # client → server (Tenable → PLC)
    started_at   : float
    ended_at     : Optional[float] = None
    cotp_cr      : Optional[COTPFrame] = None
    cotp_cc      : Optional[COTPFrame] = None
    closed_cleanly : bool = False

    transactions : list[Transaction] = field(default_factory=list)
    # richieste ancora in attesa di risposta, indicizzate per correlation_key
    _pending     : dict = field(default_factory=dict)

    def __post_init__(self):
        # forziamo che _pending sia vuoto e tipizzato
        self._pending = {}

    @property
    def reverse_key(self) -> FlowKey:
        return self.forward_key.reverse()

    @property
    def duration_ms(self) -> Optional[float]:
        if self.ended_at is None:
            return None
        return (self.ended_at - self.started_at) * 1000.0


class SessionTracker:
    """
    Mantiene tutte le sessioni in corso e completate.
    Riceve eventi dal parser e li dispatcha correttamente.
    """

    def __init__(self):
        # le sessioni sono indicizzate per "frozenset" delle due endpoint
        # così il lookup è simmetrico (qualunque direzione)
        self.sessions : dict[frozenset, Session] = {}
        self.completed : list[Session] = []

    @staticmethod
    def _bidirectional_key(key: FlowKey) -> frozenset:
        return frozenset([
            (key.src_ip, key.src_port),
            (key.dst_ip, key.dst_port),
        ])

    # ── Eventi COTP ──────────────────────────────────────────────────────────
    def on_cotp_cr(self, ts: float, key: FlowKey, frame: COTPFrame):
        """Connection Request: nasce una nuova sessione."""
        bk = self._bidirectional_key(key)
        # se c'è già una sessione vecchia con questa key, la chiudiamo
        if bk in self.sessions:
            old = self.sessions.pop(bk)
            old.ended_at = ts
            self.completed.append(old)

        self.sessions[bk] = Session(
            forward_key=key,
            started_at=ts,
            cotp_cr=frame,
        )

    def on_cotp_cc(self, ts: float, key: FlowKey, frame: COTPFrame):
        bk = self._bidirectional_key(key)
        sess = self.sessions.get(bk)
        if sess:
            sess.cotp_cc = frame

    def on_cotp_dr(self, ts: float, key: FlowKey):
        """Disconnect Request: chiude la sessione."""
        bk = self._bidirectional_key(key)
        if bk in self.sessions:
            sess = self.sessions.pop(bk)
            sess.ended_at = ts
            sess.closed_cleanly = True
            self.completed.append(sess)

    # ── Eventi applicativi (S7comm-Plus / S7comm) ────────────────────────────
    def on_app_frame(self, ts: float, key: FlowKey,
                     app_frame: S7PlusFrame | S7Frame):
        bk = self._bidirectional_key(key)
        sess = self.sessions.get(bk)
        if sess is None:
            # è arrivata una PDU senza handshake visibile: creiamo
            # comunque una sessione "implicita" per non perdere il dato
            sess = Session(forward_key=key, started_at=ts)
            self.sessions[bk] = sess

        # Solo S7+ ha la nostra logica di correlation; per S7 classico
        # registriamo la transazione "secca" senza accoppiamento
        if isinstance(app_frame, S7PlusFrame):
            self._handle_s7plus(sess, ts, app_frame)
        else:
            self._handle_s7classic(sess, ts, app_frame)

    def _handle_s7plus(self, sess: Session, ts: float, f: S7PlusFrame):
        ckey = f.correlation_key
        if f.is_request:
            tx = Transaction(
                seq_no=len(sess.transactions) + 1,
                request_ts=ts,
                request_frame=f,
            )
            sess.transactions.append(tx)
            if ckey is not None:
                sess._pending.setdefault(ckey, []).append(tx)

        elif f.is_response:
            # cerchiamo una richiesta in attesa con la stessa correlation key
            tx = None
            if ckey is not None and ckey in sess._pending and sess._pending[ckey]:
                tx = sess._pending[ckey].pop(0)
                if not sess._pending[ckey]:
                    del sess._pending[ckey]
            if tx is None:
                # risposta orfana: registriamo comunque una transazione
                tx = Transaction(
                    seq_no=len(sess.transactions) + 1,
                    request_ts=ts,
                )
                sess.transactions.append(tx)

            tx.response_ts = ts
            tx.response_frame = f

    def _handle_s7classic(self, sess: Session, ts: float, f: S7Frame):
        # Per S7comm classico usiamo PDU reference come correlation
        rosctr = f.header.rosctr
        if rosctr == 0x01 or rosctr == 0x07:    # Job o UserData (request)
            tx = Transaction(
                seq_no=len(sess.transactions) + 1,
                request_ts=ts,
                request_frame=f,
            )
            sess.transactions.append(tx)
            sess._pending.setdefault(("s7", f.header.pdu_ref), []).append(tx)
        elif rosctr in (0x02, 0x03, 0x07):
            ckey = ("s7", f.header.pdu_ref)
            tx = None
            if ckey in sess._pending and sess._pending[ckey]:
                tx = sess._pending[ckey].pop(0)
            if tx is None:
                tx = Transaction(
                    seq_no=len(sess.transactions) + 1,
                    request_ts=ts,
                )
                sess.transactions.append(tx)
            tx.response_ts = ts
            tx.response_frame = f

    # ── Finalize ─────────────────────────────────────────────────────────────
    def finalize(self):
        """Sposta tutte le sessioni ancora aperte in `completed`."""
        for sess in list(self.sessions.values()):
            self.completed.append(sess)
        self.sessions.clear()

    def all_sessions(self) -> list[Session]:
        return self.completed + list(self.sessions.values())