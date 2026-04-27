# ─────────────────────────────────────────────────────────────────────────────
# parsers/s7comm_plus.py
# S7comm-Plus – Protocol ID 0x72  (TIA Portal, S7-1200/1500)
#
# Struttura PDU (semplificata):
#   Byte 0      : Protocol ID  (0x72)
#   Byte 1      : Version      (0x01 / 0x02 / 0x03)
#   Bytes 2-3   : Data length
#   Byte 4      : Outer opcode (0x31 Request, 0x32 Response, 0x33 Notif, 0x20 IntegrityProtected)
#
# Se outer opcode è 0x20 (integrity-protected, ricorre con TIA Portal V13+):
#   Bytes 5..36 : 32 byte di integrity block (HMAC-like)
#   Byte 37     : Inner opcode (0x31 o 0x32)
#   Bytes 38... : Inner PDU vera e propria
#
# Per la inner PDU "normale" (0x31 / 0x32), dopo l'opcode segue:
#   Bytes 0     : opcode (0x31/0x32/0x33)
#   Bytes 1-2   : reserved (di solito 0x0000)
#   Bytes 3-4   : Function code  (0x04CA, 0x0586, ecc.)
#   Bytes 5-8   : Sequence number / Session ID  (32-bit)
#   Bytes 9...  : Item TLV stream
#
# La correlazione richiesta↔risposta avviene matchando function+session
# tra una PDU 0x31 e la successiva 0x32 sulla stessa connessione TCP.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Optional

from tables import (
    S7PLUS_PDU_TYPE, S7PLUS_FUNCTIONS, S7PLUS_INTEGRITY_BLOCK_LEN,
)

S7PLUS_PROTOCOL_ID = 0x72
INNER_OPCODES      = (0x31, 0x32, 0x33)


@dataclass
class S7PlusFrame:
    # ── header esterno ───────────────────────────────────────────────────────
    protocol_id  : int
    version      : int
    data_length  : int
    opcode       : int            # quello esterno: 0x31, 0x32, 0x33 o 0x20
    opcode_name  : str
    payload      : bytes          # tutto ciò che segue l'opcode esterno

    # ── integrity wrapper (se opcode esterno = 0x20) ─────────────────────────
    has_integrity_block : bool = False
    integrity_block     : Optional[bytes] = None
    inner_opcode        : Optional[int] = None
    inner_opcode_name   : Optional[str] = None

    # ── campi della PDU "interna" (sempre popolati quando estraibili) ────────
    function_code : Optional[int] = None
    function_name : Optional[str] = None
    session_id    : Optional[int] = None    # 32-bit, usato per correlation

    # ── informazioni euristiche ──────────────────────────────────────────────
    extracted_strings : list[str] = field(default_factory=list)

    valid : bool = True
    error : Optional[str] = None

    # ── proprietà ────────────────────────────────────────────────────────────
    @property
    def effective_opcode(self) -> int:
        """L'opcode 'logico': interno se è integrity-protected, altrimenti esterno."""
        return self.inner_opcode if self.has_integrity_block else self.opcode

    @property
    def is_request(self) -> bool:
        return self.effective_opcode == 0x31

    @property
    def is_response(self) -> bool:
        return self.effective_opcode == 0x32

    @property
    def correlation_key(self) -> Optional[tuple[int, int]]:
        """Chiave per matchare richiesta↔risposta: (function_code, session_id)."""
        if self.function_code is None or self.session_id is None:
            return None
        return (self.function_code, self.session_id)

    # ── output testuale ──────────────────────────────────────────────────────
    def describe(self) -> str:
        if not self.valid:
            return f"[S7comm-Plus] ERRORE: {self.error}"

        lines = [
            f"[S7comm-Plus] proto=0x72  v=0x{self.version:02X}  "
            f"len={self.data_length}  opcode=0x{self.opcode:02X} → {self.opcode_name}"
        ]

        if self.has_integrity_block:
            lines.append(
                f"   ⮡ integrity-block: {S7PLUS_INTEGRITY_BLOCK_LEN} byte  "
                f"→ inner opcode=0x{self.inner_opcode:02X} ({self.inner_opcode_name})"
            )

        if self.function_code is not None:
            lines.append(
                f"   ⮡ function=0x{self.function_code:04X} → {self.function_name}"
            )
        if self.session_id is not None:
            lines.append(
                f"   ⮡ session/seq=0x{self.session_id:08X} ({self.session_id})"
            )

        if self.extracted_strings:
            lines.append("   ⮡ stringhe rilevate nel payload:")
            for s in self.extracted_strings[:8]:
                lines.append(f"      • «{s}»")
        return "\n".join(lines)


# ─── Helpers ─────────────────────────────────────────────────────────────────
def _decode_inner_pdu(data: bytes, frame: S7PlusFrame) -> None:
    """
    Decodifica la 'inner PDU' di S7+ a partire dal byte di opcode interno.
    Riempie function_code, session_id e estrae stringhe.
    `data` deve iniziare con l'opcode (0x31/0x32/0x33).
    """
    if len(data) < 9:
        return  # troppo corto per avere function+session

    inner_op = data[0]
    if inner_op not in INNER_OPCODES:
        return

    # Layout: [opcode][reserved 2B][function 2B][session 4B][...items...]
    # `reserved` non è sempre 00 00: in alcune versioni contiene flag.
    # La function è BE a partire dall'offset 3.
    function_code = struct.unpack(">H", data[3:5])[0]
    session_id    = struct.unpack(">I", data[5:9])[0]

    frame.function_code = function_code
    frame.function_name = S7PLUS_FUNCTIONS.get(
        function_code, f"sconosciuta(0x{function_code:04X})"
    )
    frame.session_id = session_id


def _extract_strings(payload: bytes, min_len: int = 5) -> list[str]:
    """Estrazione naive di stringhe ASCII stampabili. Utile per S7+ inner data."""
    out = []
    run = bytearray()
    for b in payload:
        if 32 <= b < 127:
            run.append(b)
        else:
            if len(run) >= min_len:
                out.append(run.decode())
            run = bytearray()
    if len(run) >= min_len:
        out.append(run.decode())
    return out


# ─── Parser principale ───────────────────────────────────────────────────────
def parse(data: bytes) -> S7PlusFrame:
    if len(data) < 5 or data[0] != S7PLUS_PROTOCOL_ID:
        return S7PlusFrame(
            protocol_id=0, version=0, data_length=0, opcode=0,
            opcode_name="?", payload=b"",
            valid=False,
            error=f"Non è S7comm-Plus (byte0=0x{data[0]:02X})" if data else "vuoto",
        )

    version = data[1]
    dlen    = struct.unpack(">H", data[2:4])[0]
    opcode  = data[4]
    payload = data[5:5 + dlen] if 5 + dlen <= len(data) else data[5:]

    frame = S7PlusFrame(
        protocol_id=S7PLUS_PROTOCOL_ID,
        version=version,
        data_length=dlen,
        opcode=opcode,
        opcode_name=S7PLUS_PDU_TYPE.get(opcode, "?"),
        payload=payload,
    )

    # ── Caso A: PDU "in chiaro" (opcode = 0x31/0x32/0x33) ────────────────────
    if opcode in INNER_OPCODES:
        # data[4:] inizia con l'opcode, quindi ripartiamo da lì per coerenza
        _decode_inner_pdu(data[4:], frame)
        frame.extracted_strings = _extract_strings(payload)

    # ── Caso B: PDU integrity-protected (opcode = 0x20) ──────────────────────
    elif opcode == 0x20:
        frame.has_integrity_block = True
        # I prossimi 32 byte sono il digest, poi c'è la inner PDU
        if len(payload) >= S7PLUS_INTEGRITY_BLOCK_LEN + 9:
            frame.integrity_block = payload[:S7PLUS_INTEGRITY_BLOCK_LEN]
            inner = payload[S7PLUS_INTEGRITY_BLOCK_LEN:]

            inner_op = inner[0]
            if inner_op in INNER_OPCODES:
                frame.inner_opcode = inner_op
                frame.inner_opcode_name = S7PLUS_PDU_TYPE.get(inner_op, "?")
                _decode_inner_pdu(inner, frame)
                # estraiamo stringhe SOLO dal contenuto post-opcode
                frame.extracted_strings = _extract_strings(inner[9:])
            else:
                # disallineamento: la lunghezza del blocco integrity può variare
                # in versioni più recenti. Fallback: scansiona alla ricerca di
                # un opcode interno credibile nei primi 64 byte.
                for off in range(16, min(64, len(payload) - 9)):
                    if payload[off] in INNER_OPCODES:
                        frame.integrity_block = payload[:off]
                        frame.inner_opcode = payload[off]
                        frame.inner_opcode_name = S7PLUS_PDU_TYPE.get(payload[off], "?")
                        _decode_inner_pdu(payload[off:], frame)
                        frame.extracted_strings = _extract_strings(payload[off + 9:])
                        break

    return frame


def looks_like_s7plus(data: bytes) -> bool:
    return len(data) >= 1 and data[0] == S7PLUS_PROTOCOL_ID
