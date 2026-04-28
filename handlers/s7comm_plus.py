# ─────────────────────────────────────────────────────────────────────────────
# handlers/s7comm_plus.py
# S7comm-Plus (proto 0x72, TIA Portal).
#
# Strategia: REPLAY dei template registrati dal pcap. Cambiamo solo
#   • le stringhe di identità nel template InitSession
#   • il session_id per matchare quello richiesto dal client
#
# La firma HMAC NON viene verificata da Tenable in fase di asset discovery
# (verrebbe verificata solo per write/upload di blocchi). Quindi il replay
# è sufficiente per essere identificati come PLC TIA Portal-compatibile.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import struct
import logging
from pathlib import Path
from typing import Optional
import scan_logger
from identity import PLCIdentity

log = logging.getLogger("honeypot.s7comm_plus")

s7comm_plus_PROTO = 0x72
RECORDED_DIR = Path(__file__).parent.parent / "recorded"


def _load(name: str) -> Optional[bytes]:
    p = RECORDED_DIR / f"{name}.bin"
    return p.read_bytes() if p.exists() else None


# Mappa: (outer_opcode_della_response, function_code) → file template
TEMPLATES = {
    (0x32, 0x04CA): "s7comm_plus_initsession_response",
    (0x32, 0x0542): "s7comm_plus_setvarsubstreamed_response",
    (0x20, 0x0586): "s7comm_plus_ip_0586_response",
    (0x20, 0x04D4): "s7comm_plus_ip_04D4_response",
    #(0x20, 0x04BB): "s7comm_plus_ip_04BB_response",
    #The honeypot disables S7+ Explore responses (function 0x04BB) by default to
    #prevent scanners from enumerating phantom modules of the captured PLC's
    #backplane. To re-enable for scenarios where you want to advertise a
    #specific module configuration, add the entry to TEMPLATES in
    #handlers/s7comm_plus.py and provide a matching template file in recorded/ (see s7comm_plus_ip_04BB_response.bin for an example).
}


def _patch_init_response(template: bytes, identity: PLCIdentity) -> bytes:
    """
    Patch in-place delle stringhe identità nel template InitSession.
    Usiamo SOLO sostituzioni di pari lunghezza per non rompere offset.
    Le identità in identity.py sono bytes; le confrontiamo con i marker
    fissi del pcap originale.
    """
    out = bytearray(template)

    # Marker → nuovo valore (TUTTI bytes, padded alla stessa lunghezza)
    pairs = [
        (b"6ES7 214-1HG40-0XB0",       identity.article_number.rstrip()[:19].ljust(19, b' ')),
        (b"V4.6",                       identity.firmware[:4].ljust(4, b' ')),
        (b"01:BD426B091F08731A",        identity.serial_number[:19].ljust(19, b' ')),
    ]

    for marker, replacement in pairs:
        if len(marker) != len(replacement):
            continue
        idx = out.find(marker)
        while idx != -1:
            out[idx:idx + len(marker)] = replacement
            idx = out.find(marker, idx + 1)

    return bytes(out)


def _patch_session_id(response: bytes, new_session_id: int,
                      has_integrity: bool) -> bytes:
    """
    Sostituisce il session_id nella inner PDU della risposta.

    Layout:
       [0x72][version][len][outer_opcode]
       se outer_opcode == 0x20: 32 byte di integrity, poi inner PDU
       inner PDU: [op][reserved 2B][function 2B][session 4B]
    """
    out = bytearray(response)
    if len(out) < 5:
        return bytes(out)

    if out[4] == 0x20 and has_integrity:
        sess_offset = 5 + 32 + 5      # header + integrity + (op+reserved+function)
    elif out[4] in (0x31, 0x32, 0x33):
        sess_offset = 5 + 5
    else:
        return bytes(out)

    if sess_offset + 4 > len(out):
        return bytes(out)

    out[sess_offset:sess_offset + 4] = struct.pack(">I", new_session_id)
    return bytes(out)


def handle(payload: bytes, identity: PLCIdentity) -> Optional[bytes]:
    """
    Riceve il payload S7+ (dopo COTP-DT) e ritorna una risposta replay.
    """
    if len(payload) < 5 or payload[0] != s7comm_plus_PROTO:
        return None

    opcode = payload[4]
    function_code = None
    session_id    = None

    if opcode in (0x31, 0x32, 0x33):
        if len(payload) >= 14:
            function_code = struct.unpack(">H", payload[7:9])[0]
            session_id    = struct.unpack(">I", payload[9:13])[0]
        response_outer = 0x32
    elif opcode == 0x20:
        if len(payload) >= 5 + 32 + 9:
            inner = payload[5 + 32:]
            if inner[0] in (0x31, 0x32, 0x33):
                function_code = struct.unpack(">H", inner[3:5])[0]
                session_id    = struct.unpack(">I", inner[5:9])[0]
        response_outer = 0x20
    else:
        return None

    if function_code is None:
        log.debug(f"S7+ opcode 0x{opcode:02X}: function code non estraibile")
        return None

    # ── Log della richiesta S7+ ──────────────────────────────────────────────
    log_details: dict = {
        "opcode"     : f"0x{opcode:02X}",
        "function"   : f"0x{function_code:04X}",
        "session_id" : f"0x{session_id:08X}" if session_id else None,
    }

    # Estrazione stringhe identificative del client (solo per InitSession request)
    if function_code == 0x04CA and opcode == 0x31:
        strings = []
        run = bytearray()
        for b in payload[14:]:
            if 32 <= b < 127:
                run.append(b)
            else:
                if len(run) >= 5:
                    strings.append(run.decode())
                run = bytearray()
        if len(run) >= 5:
            strings.append(run.decode())
        # Filtra il rumore: stringhe con troppi caratteri non-alfa
        clean_strings = []
        for s in strings:
            alpha = sum(1 for c in s if c.isalnum() or c in '.-_:/ ')
            if alpha / max(len(s), 1) > 0.6:
                clean_strings.append(s)
        if clean_strings:
            log_details["client_strings"] = clean_strings[:10]

    scan_logger.log_event(
        layer="s7plus", event_type="request",
        details=log_details,
    )

    tpl_key = (response_outer, function_code)
    if tpl_key not in TEMPLATES:
        log.warning(f"S7+ func=0x{function_code:04X} (op=0x{response_outer:02X}) "
                    f"nessun template")
        return None

    template = _load(TEMPLATES[tpl_key])
    if not template:
        log.error(f"Template '{TEMPLATES[tpl_key]}.bin' mancante in {RECORDED_DIR}")
        return None

    if function_code == 0x04CA:
        template = _patch_init_response(template, identity)

    response = _patch_session_id(template, session_id,
                                 has_integrity=(response_outer == 0x20))

    log.info(f"S7+ replay: func=0x{function_code:04X} "
             f"session=0x{session_id:08X} → {len(response)}B")
    return response