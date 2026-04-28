# ─────────────────────────────────────────────────────────────────────────────
# handlers/modbus.py
# Modbus TCP (porta 502).
#
# Tenable scansiona Modbus per:
#   • Read Holding Registers (FC 0x03)  → verifica vivibilità
#   • Read Device Identification (FC 0x2B/0x0E) → vendor, product, version
#
# Una S7-1200 risponde NATIVAMENTE Modbus solo se l'utente ha caricato un
# blocco MB_SERVER nel programma. Tuttavia molti scanner si aspettano una
# risposta "minimale" su 502 anche da PLC Siemens, e la sua presenza
# rinforza il fingerprint come "PLC industriale completo".
#
# Struttura Modbus TCP frame:
#   MBAP header: TID(2) ProtoID(2)=0 Length(2) UnitID(1)
#   PDU:         FunctionCode(1) [Data...]
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import struct
import logging
from typing import Optional
import scan_logger
from identity import PLCIdentity

log = logging.getLogger("honeypot.modbus")


# ─── Helper costruzione risposta MBAP ────────────────────────────────────────
def _build_response(tid: bytes, uid: bytes, pdu: bytes) -> bytes:
    """
    Costruisce un frame Modbus TCP completo.
    `tid`/`uid` sono bytes di 2/1 byte rispettivamente.
    `pdu` è la PDU (function code + data).
    Length = UnitID (1B) + PDU.
    """
    return tid + b"\x00\x00" + struct.pack(">H", 1 + len(pdu)) + uid + pdu


def _exception(tid: bytes, uid: bytes, fc: int, exc_code: int) -> bytes:
    """Risposta di eccezione: FC | 0x80, exc_code."""
    return _build_response(tid, uid, bytes([fc | 0x80, exc_code]))


# ─── FC 0x03: Read Holding Registers ─────────────────────────────────────────
def _handle_read_holding(tid, uid, fc, body) -> bytes:
    """
    Body: starting_addr(2) reg_count(2)
    Rispondiamo con `reg_count` registri tutti a zero. Comportamento legittimo:
    "i registri esistono ma valgono 0", coerente con un PLC senza programma.
    """
    if len(body) < 4:
        return _exception(tid, uid, fc, 0x03)   # illegal data value
    reg_count = struct.unpack(">H", body[2:4])[0]
    if not (1 <= reg_count <= 125):
        return _exception(tid, uid, fc, 0x03)
    byte_count = reg_count * 2
    pdu = bytes([fc, byte_count]) + bytes(byte_count)
    return _build_response(tid, uid, pdu)


# ─── FC 0x2B / sub 0x0E: Read Device Identification ──────────────────────────
def _handle_read_device_id(tid, uid, fc, identity: PLCIdentity) -> bytes:
    """
    Risponde con i 3 oggetti "basic": vendor (0x00), product (0x01),
    version (0x02). Tenable estrae questi e li mette nel fingerprint.
    """
    v   = identity.modbus_vendor
    p   = identity.modbus_product
    ver = identity.modbus_version

    objects = (
        bytes([0x00, len(v)])   + v +
        bytes([0x01, len(p)])   + p +
        bytes([0x02, len(ver)]) + ver
    )

    # PDU MEI Encapsulated:
    #   FC=0x2B, MEI=0x0E, ReadDeviceIDCode=0x01 (basic),
    #   ConformityLevel=0x01, MoreFollows=0x00, NextObjectID=0x00,
    #   NumObjects=0x03, [Objects...]
    pdu = bytes([fc, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x03]) + objects
    return _build_response(tid, uid, pdu)


# ─── Dispatch principale ─────────────────────────────────────────────────────
def handle(frame: bytes, identity: PLCIdentity) -> Optional[bytes]:
    """
    Riceve un frame Modbus TCP (con MBAP header) e ritorna il frame di risposta.
    """
    if len(frame) < 8:
        return None

    tid    = frame[0:2]
    proto  = frame[2:4]
    length = struct.unpack(">H", frame[4:6])[0]
    uid    = frame[6:7]
    fc     = frame[7]
    body   = frame[8:6 + length]    # UnitID già consumato

    if proto != b"\x00\x00":
        log.warning(f"Modbus protocol id non zero ({proto.hex()})")
        return None

    log.info(f"Modbus FC=0x{fc:02X} TID={tid.hex()}")

    # ── Log dell'evento ──────────────────────────────────────────────────────
    scan_logger.log_event(
        layer="modbus", event_type="request",
        details={"function": f"0x{fc:02X}", "tid": tid.hex()},
    )

    if fc == 0x03:
        return _handle_read_holding(tid, uid, fc, body)
    if fc == 0x2B:
        return _handle_read_device_id(tid, uid, fc, identity)

    # Funzione non supportata: rispondi con illegal function (0x01)
    return _exception(tid, uid, fc, 0x01)