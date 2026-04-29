# ─────────────────────────────────────────────────────────────────────────────
# handlers/s7comm.py
# S7comm classico (proto 0x32).
#
# Gestisce:
#   • Setup Communication       (function 0xF0)               [sync]
#   • Read SZL via UserData     (subfunction 0x44 0x01)      [sync]
#       SZL 0x0011 → modello CPU         ★ fingerprint Tenable
#       SZL 0x001C → identificazione     ★ fingerprint Tenable
#       SZL 0x0037 → stato CPU
#       SZL 0x0013 → memory card
#       SZL 0x0111 → all module identification
#       SZL 0x0131 → communication capabilities
#       SZL 0x0132 → communication status
#       SZL 0x0424 → mode transition (RUN/STOP)
#   • Read Variable             (function 0x04)              [async, TODO A.3]
#   • Write Variable            (function 0x05)              [async, TODO A.4]
#
# Dispatcher async (`handle`):
#   • Read/Write Variable → richiedono MemoryModel async, dispatchati su
#     `_handle_rw_variable`
#   • Tutto il resto (SZL, Setup, ecc.) → sync, dispatchato su
#     `_handle_sync_classic` (codice legacy, intoccato)
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import struct
import logging
from typing import Optional, TYPE_CHECKING

import scan_logger
from identity import PLCIdentity

if TYPE_CHECKING:
    # Import solo per type-hinting, evita import circolare a runtime
    from memory import MemoryModel

log = logging.getLogger("honeypot.s7comm")

S7_PROTO = 0x32


# ═════════════════════════════════════════════════════════════════════════════
#                     DISPATCHER PRINCIPALE (async)
# ═════════════════════════════════════════════════════════════════════════════

async def handle(payload: bytes, identity: PLCIdentity,
                 memory: "MemoryModel | None" = None) -> Optional[bytes]:
    """
    Entry-point unificato per tutto il protocollo S7 classico.

    Smista le richieste sync (SZL, Setup) e async (Read/Write Variable).
    Restituisce la risposta S7 raw (senza COTP/TPKT), oppure None se non gestita.
    """
    # Validazione preliminare: header minimo
    if len(payload) < 10 or payload[0] != S7_PROTO:
        return None

    rosctr    = payload[1]
    param_len = struct.unpack(">H", payload[6:8])[0]
    param     = payload[10:10 + param_len]
    if not param:
        return None

    function_code = param[0]

    # ── Read Variable / Write Variable: gestione async via MemoryModel ──────
    if rosctr == 0x01 and function_code in (0x04, 0x05):
        if memory is None:
            log.warning(f"Function 0x{function_code:02X} richiede MemoryModel "
                        f"ma non disponibile, ignoro")
            return None
        return await _handle_rw_variable(payload, memory)

    # ── Tutto il resto: gestione sync (codice legacy intoccato) ────────────
    return _handle_sync_classic(payload, identity)


# ═════════════════════════════════════════════════════════════════════════════
#                     READ/WRITE VARIABLE (async)  [TODO A.3, A.4]
# ═════════════════════════════════════════════════════════════════════════════

async def _handle_rw_variable(payload: bytes,
                               memory: "MemoryModel") -> Optional[bytes]:
    """
    Handler delle function S7 0x04 (Read Variable) e 0x05 (Write Variable).

    Iterazione corrente: SKELETON. Logga la ricezione e ritorna None.
    Sarà implementato in:
        A.3.1 — decoder degli item della richiesta
        A.3.2 — encoder della risposta
        A.3.3 — wiring con MemoryModel
        A.4   — Write Variable
    """
    function_code = payload[10]
    pdu_ref       = payload[4:6]

    log.info(f"S7 Read/Write Variable (func=0x{function_code:02X}) "
             f"PDU#{pdu_ref.hex()} → SKELETON, non ancora implementato")

    scan_logger.log_event(
        layer="s7", event_type="rw_variable_request_unhandled",
        details={
            "function": f"0x{function_code:02X}",
            "pdu_ref":  pdu_ref.hex(),
            "note":     "skeleton, da implementare in A.3/A.4",
        },
    )
    return None   # nessuna risposta → il client vedrà timeout, è ok per ora


# ═════════════════════════════════════════════════════════════════════════════
#                     CODICE LEGACY SYNC (intoccato)
# ═════════════════════════════════════════════════════════════════════════════

# ─── Helper di serializzazione ───────────────────────────────────────────────
def _pad(data: bytes, length: int) -> bytes:
    """Pad/trunca a lunghezza fissa con NUL (convenzione Siemens nei record SZL)."""
    return data[:length].ljust(length, b"\x00")


def _build_s7_header(rosctr: int, pdu_ref: bytes,
                     param_len: int, data_len: int,
                     err_class: int = 0, err_code: int = 0) -> bytes:
    """
    Header S7comm: 10 byte (job/userdata) o 12 byte (ack-data).
    `pdu_ref` deve essere già 2 byte (l'eco di quello del client).
    """
    base = struct.pack(">BB", S7_PROTO, rosctr)
    base += b"\x00\x00"
    base += pdu_ref
    base += struct.pack(">HH", param_len, data_len)
    if rosctr in (0x02, 0x03):
        base += struct.pack(">BB", err_class, err_code)
    return base


# ─── Setup Communication response ────────────────────────────────────────────
def build_setup_response(req_pdu_ref: bytes, pdu_size: int = 240,
                         max_amq: int = 1) -> bytes:
    param = struct.pack(">BBHHH", 0xF0, 0x00, max_amq, max_amq, pdu_size)
    header = _build_s7_header(rosctr=0x03, pdu_ref=req_pdu_ref,
                              param_len=len(param), data_len=0)
    return header + param


# ─── SZL response builder generico ───────────────────────────────────────────
def _build_szl_response(req_pdu_ref: bytes, seq_num: int,
                        szl_id: int, szl_index: int,
                        records: bytes, rec_size: int, rec_count: int) -> bytes:
    szl_data = struct.pack(">HHHH", szl_id, szl_index, rec_size, rec_count)
    szl_data += records
    s7_data = bytes([0xFF, 0x09]) + struct.pack(">H", len(szl_data)) + szl_data
    s7_param = bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x84,
                      0x01, seq_num & 0xFF, 0x00, 0x00, 0x00, 0x00])
    header = _build_s7_header(rosctr=0x07, pdu_ref=req_pdu_ref,
                              param_len=len(s7_param), data_len=len(s7_data))
    return header + s7_param + s7_data


# ─── SZL builders specifici ──────────────────────────────────────────────────
def build_szl_0011(req_pdu_ref: bytes, seq_num: int, identity: PLCIdentity) -> bytes:
    mlfb = _pad(identity.article_number, 20)
    def rec(idx_val, version_bytes):
        return struct.pack(">H", idx_val) + mlfb + b"\x00\x00" + version_bytes
    records = (
        rec(0x0001, identity.hw_version_bytes) +
        rec(0x0006, identity.hw_version_bytes) +
        rec(0x0007, identity.fw_version_bytes)
    )
    return _build_szl_response(req_pdu_ref, seq_num, 0x0011, 0x0000,
                                records, rec_size=28, rec_count=3)


def build_szl_001c(req_pdu_ref: bytes, seq_num: int, identity: PLCIdentity) -> bytes:
    components = [
        (0x0001, identity.module_name),
        (0x0002, identity.module_name),
        (0x0003, identity.plant_id),
        (0x0004, identity.copyright_str),
        (0x0005, identity.serial_number),
        (0x0007, identity.module_type),
        (0x0009, identity.vendor),
    ]
    records = b""
    for idx, val in components:
        records += struct.pack(">H", idx) + _pad(val, 24)
    return _build_szl_response(req_pdu_ref, seq_num, 0x001C, 0x0000,
                                records, rec_size=26, rec_count=len(components))


def build_szl_0037(req_pdu_ref: bytes, seq_num: int) -> bytes:
    record = struct.pack(">HH", 0x0008, 0x0000)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0037, 0x0000,
                                record, rec_size=4, rec_count=1)


def build_szl_0013(req_pdu_ref: bytes, seq_num: int) -> bytes:
    record = struct.pack(">HHI", 0x0001, 0x0001, 0x00100000)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0013, 0x0000,
                                record, rec_size=8, rec_count=1)


def build_szl_0111(req_pdu_ref: bytes, seq_num: int, identity: PLCIdentity) -> bytes:
    mlfb = _pad(identity.article_number, 20)
    record = (struct.pack(">H", 0x0001) + mlfb + b"\x00\x00"
              + identity.hw_version_bytes)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0111, 0x0000,
                                record, rec_size=28, rec_count=1)


def build_szl_0131(req_pdu_ref: bytes, seq_num: int) -> bytes:
    record = struct.pack(">H", 0x0001) + struct.pack(">HHHH", 480, 8, 1, 1)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0131, 0x0000,
                                record, rec_size=len(record), rec_count=1)


def build_szl_0132(req_pdu_ref: bytes, seq_num: int) -> bytes:
    record = struct.pack(">H", 0x0004) + struct.pack(">HHHH", 0, 0, 0, 0x0008)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0132, 0x0000,
                                record, rec_size=len(record), rec_count=1)


def build_szl_0424(req_pdu_ref: bytes, seq_num: int) -> bytes:
    record = struct.pack(">H", 0x0000) + struct.pack(">HH", 0x0008, 0x0000)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0424, 0x0000,
                                record, rec_size=len(record), rec_count=1)


SZL_HANDLERS = {
    0x0011: build_szl_0011,
    0x001C: build_szl_001c,
    0x0037: lambda pr, sn, _id: build_szl_0037(pr, sn),
    0x0013: lambda pr, sn, _id: build_szl_0013(pr, sn),
    0x0111: build_szl_0111,
    0x0131: lambda pr, sn, _id: build_szl_0131(pr, sn),
    0x0132: lambda pr, sn, _id: build_szl_0132(pr, sn),
    0x0424: lambda pr, sn, _id: build_szl_0424(pr, sn),
}


def _handle_sync_classic(payload: bytes,
                          identity: PLCIdentity) -> Optional[bytes]:
    """
    Gestione SYNC delle function S7 che NON richiedono MemoryModel.

    Rinominata da `handle` durante il refactor di Iterazione A.
    Il comportamento è identico alla versione precedente: stesso input,
    stesso output, stessi log, stessi eventi scan_logger.
    """
    rosctr    = payload[1]
    pdu_ref   = payload[4:6]
    param_len = struct.unpack(">H", payload[6:8])[0]
    param     = payload[10:10 + param_len]

    # ── Setup Communication (function 0xF0) ─────────────────────────────────
    if rosctr == 0x01 and param[0] == 0xF0:
        log.info(f"S7 Setup Comm, PDU#{pdu_ref.hex()} → ACK")
        scan_logger.log_event(
            layer="s7", event_type="setup_communication",
            details={"pdu_ref": pdu_ref.hex()},
        )
        return build_setup_response(pdu_ref)

    # ── UserData / Read SZL (ROSCTR=0x07) ────────────────────────────────────
    if rosctr == 0x07 and len(param) >= 8 and param[:3] == b"\x00\x01\x12":
        seq_num   = param[7]
        funcgroup = param[5] & 0x0F
        subfunc   = param[6]

        if funcgroup == 0x04 and subfunc == 0x01:
            data = payload[10 + param_len:]
            if len(data) < 8:
                return None
            szl_id    = struct.unpack(">H", data[4:6])[0]
            szl_index = struct.unpack(">H", data[6:8])[0]
            szl_id_base = szl_id & 0x0FFF

            scan_logger.log_event(
                layer="s7", event_type="szl_request",
                details={"function": f"SZL_0x{szl_id_base:04X}",
                         "szl_index": f"0x{szl_index:04X}",
                         "pdu_ref": pdu_ref.hex()},
            )

            handler = SZL_HANDLERS.get(szl_id_base)
            if handler:
                log.info(f"S7 Read SZL 0x{szl_id:04X} idx 0x{szl_index:04X} "
                         f"seq={seq_num} → rispondo")
                return handler(pdu_ref, seq_num, identity)
            else:
                log.warning(f"S7 SZL 0x{szl_id:04X} non implementata, rispondo vuoto")
                return _build_szl_response(pdu_ref, seq_num, szl_id, szl_index,
                                            b"", 0, 0)

        log.debug(f"S7 UserData funcgroup={funcgroup} subfunc={subfunc} non gestito")
        return None

    log.debug(f"S7 ROSCTR=0x{rosctr:02X} non gestito")
    return None