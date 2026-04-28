# ─────────────────────────────────────────────────────────────────────────────
# handlers/s7comm.py
# S7comm classico (proto 0x32).
#
# Gestisce:
#   • Setup Communication       (function 0xF0)
#   • Read SZL via UserData     (subfunction 0x44 0x01)
#       SZL 0x0011 → modello CPU         ★ fingerprint Tenable
#       SZL 0x001C → identificazione     ★ fingerprint Tenable
#       SZL 0x0037 → stato CPU
#       SZL 0x0013 → memory card
#       SZL 0x0111 → all module identification
#       SZL 0x0131 → communication capabilities
#       SZL 0x0132 → communication status
#       SZL 0x0424 → mode transition (RUN/STOP)
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import struct
import logging
from typing import Optional
import scan_logger
from identity import PLCIdentity

log = logging.getLogger("honeypot.s7comm")

S7_PROTO = 0x32


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
    base = struct.pack(">BB", S7_PROTO, rosctr)         # proto + ROSCTR
    base += b"\x00\x00"                                  # redundancy
    base += pdu_ref                                      # PDU ref (eco)
    base += struct.pack(">HH", param_len, data_len)
    if rosctr in (0x02, 0x03):
        base += struct.pack(">BB", err_class, err_code)
    return base


# ─── Setup Communication response ────────────────────────────────────────────
def build_setup_response(req_pdu_ref: bytes, pdu_size: int = 240,
                         max_amq: int = 1) -> bytes:
    """
    Risposta a Setup Communication (function 0xF0).
    Default pdu_size=240 e max_amq=1 sono i valori tipici di un S7-1200.
    """
    # Parameter: F0 00 max_calling(2) max_called(2) pdu_length(2) = 8 byte
    param = struct.pack(">BBHHH", 0xF0, 0x00, max_amq, max_amq, pdu_size)
    header = _build_s7_header(rosctr=0x03, pdu_ref=req_pdu_ref,
                              param_len=len(param), data_len=0)
    return header + param


# ─── SZL response builder generico ───────────────────────────────────────────
def _build_szl_response(req_pdu_ref: bytes, seq_num: int,
                        szl_id: int, szl_index: int,
                        records: bytes, rec_size: int, rec_count: int) -> bytes:
    """
    Risposta UserData / Read SZL (function group 0x44, subfunction 0x01).
    `records` è la concatenazione di tutti i record (ognuno di rec_size byte).
    Il sequence number della richiesta viene echeggiato (più realistico).
    """
    # SZL data area: szl_id(2) szl_index(2) rec_size(2) rec_count(2) [records]
    szl_data = struct.pack(">HHHH", szl_id, szl_index, rec_size, rec_count)
    szl_data += records

    # S7 data area: FF (success) + 09 (octet-string) + length(2) + szl_data
    s7_data = bytes([0xFF, 0x09]) + struct.pack(">H", len(szl_data)) + szl_data

    # Parameter UserData response (12 byte):
    # 00 01 12 08 12 84 01 [seq_num] 00 00 00 00
    #         |  |  |  |
    #         |  |  |  +-- subfunction = 0x01 (Read SZL)
    #         |  |  +----- functional group response = 0x84 (0x80 | 0x04)
    #         |  +-------- length of remaining param = 0x08
    #         +----------- type "Userdata data unit" = 0x12
    s7_param = bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x84,
                      0x01, seq_num & 0xFF, 0x00, 0x00, 0x00, 0x00])

    header = _build_s7_header(rosctr=0x07, pdu_ref=req_pdu_ref,
                              param_len=len(s7_param), data_len=len(s7_data))
    return header + s7_param + s7_data


# ─── SZL 0x0011: Module identification (★ fingerprint principale) ────────────
def build_szl_0011(req_pdu_ref: bytes, seq_num: int, identity: PLCIdentity) -> bytes:
    """
    Layout di ciascun record (28 byte):
       index(2) + MLFB(20) + reserved(2) + ausbg(2) + ausbe(2)
    Tre record (idx 0x0001, 0x0006, 0x0007) come nel pcap di riferimento.
    Tenable legge la stringa MLFB e identifica il PLC dalla famiglia.
    """
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


# ─── SZL 0x001C: Component identification ────────────────────────────────────
def build_szl_001c(req_pdu_ref: bytes, seq_num: int, identity: PLCIdentity) -> bytes:
    """
    Record da 26 byte: index(2) + name(24).
    Tenable legge i campi: station name, module name, vendor, copyright, ecc.
    """
    components = [
        (0x0001, identity.module_name),     # System name / module
        (0x0002, identity.module_name),     # Module name
        (0x0003, identity.plant_id),        # Plant designation
        (0x0004, identity.copyright_str),   # Copyright
        (0x0005, identity.serial_number),   # Serial number
        (0x0007, identity.module_type),     # Module type name
        (0x0009, identity.vendor),          # Manufacturer
    ]
    records = b""
    for idx, val in components:
        records += struct.pack(">H", idx) + _pad(val, 24)

    return _build_szl_response(req_pdu_ref, seq_num, 0x001C, 0x0000,
                                records, rec_size=26, rec_count=len(components))


# ─── SZL 0x0037: CPU operating state ─────────────────────────────────────────
def build_szl_0037(req_pdu_ref: bytes, seq_num: int) -> bytes:
    """1 record da 4 byte: mode(2) reserved(2). 0x0008 = RUN."""
    record = struct.pack(">HH", 0x0008, 0x0000)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0037, 0x0000,
                                record, rec_size=4, rec_count=1)


# ─── SZL 0x0013: Memory card identification ──────────────────────────────────
def build_szl_0013(req_pdu_ref: bytes, seq_num: int) -> bytes:
    """Memory card: 1 record da 8 byte. Annunciamo 1 MB di SD."""
    record = struct.pack(">HHI", 0x0001, 0x0001, 0x00100000)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0013, 0x0000,
                                record, rec_size=8, rec_count=1)


# ─── SZL 0x0111: Module identification (all modules) ─────────────────────────
def build_szl_0111(req_pdu_ref: bytes, seq_num: int, identity: PLCIdentity) -> bytes:
    """
    Restituisce 1 modulo (la CPU stessa). Stesso formato di 0x0011 (28 byte).
    """
    mlfb = _pad(identity.article_number, 20)
    record = (struct.pack(">H", 0x0001) + mlfb + b"\x00\x00"
              + identity.hw_version_bytes)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0111, 0x0000,
                                record, rec_size=28, rec_count=1)


# ─── SZL 0x0131: Communication capabilities ──────────────────────────────────
def build_szl_0131(req_pdu_ref: bytes, seq_num: int) -> bytes:
    """
    1 record con 4 word: max_pdu_size, max_blocks, max_sessions, max_user.
    Valori convenzionali per S7-1200 (480 PDU max, 8 blocchi, 1 session, 1 user).
    """
    record = struct.pack(">H", 0x0001) + struct.pack(">HHHH", 480, 8, 1, 1)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0131, 0x0000,
                                record, rec_size=len(record), rec_count=1)


# ─── SZL 0x0132: Communication status ────────────────────────────────────────
def build_szl_0132(req_pdu_ref: bytes, seq_num: int) -> bytes:
    """
    Stato comunicazione. 0x0008 indica "comunicazione attiva".
    """
    record = struct.pack(">H", 0x0004) + struct.pack(">HHHH", 0, 0, 0, 0x0008)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0132, 0x0000,
                                record, rec_size=len(record), rec_count=1)


# ─── SZL 0x0424: Mode transition info ────────────────────────────────────────
def build_szl_0424(req_pdu_ref: bytes, seq_num: int) -> bytes:
    """Mode transition: 0x0008 = RUN."""
    record = struct.pack(">H", 0x0000) + struct.pack(">HH", 0x0008, 0x0000)
    return _build_szl_response(req_pdu_ref, seq_num, 0x0424, 0x0000,
                                record, rec_size=len(record), rec_count=1)


# ─── Dispatch principale ─────────────────────────────────────────────────────
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


def handle(payload: bytes, identity: PLCIdentity) -> Optional[bytes]:
    """
    Riceve il payload S7 (dopo COTP-DT) e ritorna la risposta S7 raw,
    o None se non gestita.
    """
    if len(payload) < 10 or payload[0] != S7_PROTO:
        return None

    rosctr   = payload[1]
    pdu_ref  = payload[4:6]                        # 2 byte raw da echeggiare
    param_len = struct.unpack(">H", payload[6:8])[0]
    param    = payload[10:10 + param_len]

    if not param:
        return None

    # ── Setup Communication (function 0xF0) ──────────────────────────────────
    if rosctr == 0x01 and param[0] == 0xF0:
        log.info(f"S7 Setup Comm, PDU#{pdu_ref.hex()} → ACK")
        scan_logger.log_event(
            layer="s7", event_type="setup_communication",
            details={"pdu_ref": pdu_ref.hex()},
        )
        return build_setup_response(pdu_ref)

    # ── UserData / Read SZL (ROSCTR=0x07) ────────────────────────────────────
    # Pattern parameter: 00 01 12 08 12 84/04 01 seq ...
    # offset 5 = function group (0x84/0x04 = SZL ufficiale)
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
            szl_id_base = szl_id & 0x0FFF      # alcuni client usano flag negli high bit

            # ── Log dell'evento ──────────────────────────────────────────────
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