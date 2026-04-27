# ─────────────────────────────────────────────────────────────────────────────
# parsers/conversation_logger.py
# Trasforma le sessioni catturate dal SessionTracker in un file di testo
# leggibile come una conversazione fra Tenable e PLC.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import datetime
from pathlib import Path

from parsers.session_tracker import Session, Transaction
from parsers.s7comm_plus     import S7PlusFrame
from parsers.s7comm          import S7Frame


def _hr(ts: float | None) -> str:
    if ts is None:
        return "    --:--:--.---"
    return datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]


def _format_request_summary(f: S7PlusFrame | S7Frame) -> list[str]:
    out = []
    if isinstance(f, S7PlusFrame):
        if f.function_name:
            out.append(f"S7+ {f.function_name}")
        else:
            out.append(f"S7+ opcode 0x{f.opcode:02X}")
        if f.session_id is not None:
            out.append(f"sessione 0x{f.session_id:08X}")
        if f.has_integrity_block:
            out.append("integrity-protected")
    elif isinstance(f, S7Frame):
        out.append(f"S7 ROSCTR={f.header.rosctr_name}")
        if f.szl_request:
            out.append(f"SZL id=0x{f.szl_request.szl_id:04X}")
        if f.function_code is not None:
            out.append(f"func=0x{f.function_code:02X}")
    return out


def _format_payload_details(f: S7PlusFrame | S7Frame, label: str) -> list[str]:
    """Estrae le info "succose" da un frame e le formatta per il file."""
    out = []
    if isinstance(f, S7PlusFrame):
        if f.extracted_strings:
            out.append(f"          {label}:")
            for s in f.extracted_strings[:6]:
                # filtra noise: stringhe con troppi caratteri non-alfa
                alpha = sum(1 for c in s if c.isalnum() or c in '.-_:/ ')
                if alpha / max(len(s), 1) > 0.6:
                    out.append(f"            • {s}")
    elif isinstance(f, S7Frame):
        if f.szl_response:
            out.append(f"          {label}:")
            for line in f.szl_response.describe().split('\n'):
                out.append(f"            {line}")
        elif f.setup_comm:
            out.append(f"          {label}: {f.setup_comm.describe()}")
    return out


def write_conversation(sessions: list[Session], path: str | Path,
                       scanner_ip: str = "172.16.107.60") -> None:
    """Scrive l'intera conversazione in formato testo leggibile."""
    path = Path(path)
    lines : list[str] = []

    # ── Intestazione ─────────────────────────────────────────────────────────
    lines.append("=" * 78)
    lines.append("  CONVERSAZIONE Tenable ↔ PLC Siemens S7-1200")
    lines.append(f"  Generato il {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    lines.append(f"  Sessioni totali: {len(sessions)}")
    lines.append(f"  Scanner: {scanner_ip}")
    lines.append("=" * 78)
    lines.append("")

    # ── Statistiche globali ──────────────────────────────────────────────────
    n_complete    = sum(1 for s in sessions for t in s.transactions if t.is_complete)
    n_orphan_req  = sum(1 for s in sessions for t in s.transactions
                        if t.request_frame and not t.response_frame)
    n_orphan_resp = sum(1 for s in sessions for t in s.transactions
                        if t.response_frame and not t.request_frame)
    lines.append("── STATISTICHE ─────────────────────────────────────────────────────────────")
    lines.append(f"  Transazioni complete (req+resp): {n_complete}")
    lines.append(f"  Richieste senza risposta:        {n_orphan_req}")
    lines.append(f"  Risposte senza richiesta:        {n_orphan_resp}")
    lines.append("")

    # ── Una sezione per sessione ─────────────────────────────────────────────
    for idx, sess in enumerate(sessions, 1):
        lines.append("=" * 78)
        lines.append(f"SESSIONE #{idx}   {sess.forward_key}")
        lines.append(f"  inizio: {_hr(sess.started_at)}     "
                     f"fine: {_hr(sess.ended_at)}     "
                     f"durata: {sess.duration_ms:.1f} ms" if sess.duration_ms else
                     f"  inizio: {_hr(sess.started_at)}")
        lines.append("=" * 78)

        # — handshake COTP —
        if sess.cotp_cr:
            lines.append(f"[{_hr(sess.started_at)}]  Tenable apre la connessione (COTP CR)")
            for p in sess.cotp_cr.parameters:
                lines.append(f"    • {p.describe()}")
        if sess.cotp_cc:
            lines.append(f"               PLC accetta (COTP CC)")

        if not sess.transactions:
            lines.append("    (nessuna transazione applicativa registrata)")
            lines.append("")
            continue

        lines.append("")

        # — transazioni —
        for tx in sess.transactions:
            lines.append(f"  ─── Transazione #{tx.seq_no} "
                         f"{'─' * (66 - len(str(tx.seq_no)))}")

            # Richiesta
            if tx.request_frame:
                summary = _format_request_summary(tx.request_frame)
                role = "Tenable → PLC" if isinstance(tx.request_frame, (S7PlusFrame, S7Frame)) else ""
                lines.append(f"  [{_hr(tx.request_ts)}]  ▶ {role}: "
                             f"{' | '.join(summary) if summary else '(richiesta)'}")
                lines.extend(_format_payload_details(tx.request_frame, "richiesta"))
            else:
                lines.append(f"  [{_hr(tx.request_ts)}]  ▶ (nessuna richiesta visibile)")

            # Risposta
            if tx.response_frame:
                summary = _format_request_summary(tx.response_frame)
                lat = f"  Δ {tx.latency_ms:.1f} ms" if tx.latency_ms else ""
                lines.append(f"  [{_hr(tx.response_ts)}]  ◀ PLC → Tenable: "
                             f"{' | '.join(summary) if summary else '(risposta)'}{lat}")
                lines.extend(_format_payload_details(tx.response_frame, "risposta"))
            else:
                lines.append(f"  [{_hr(None)}]  ◀ (in attesa di risposta — possibile timeout)")

            lines.append("")

    # ── Footer ───────────────────────────────────────────────────────────────
    lines.append("=" * 78)
    lines.append("  Fine della conversazione")
    lines.append("=" * 78)

    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n📝 Conversazione esportata in: {path.resolve()}")
    print(f"   ({len(lines)} righe, {path.stat().st_size:,} byte)")