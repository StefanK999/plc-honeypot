# ─────────────────────────────────────────────────────────────────────────────
# handlers/cotp.py
# Handler per COTP (ISO 8073).
#
# Espone due primitive usate dal server:
#   • build_cc_from_raw(cotp_payload, our_src_ref) → bytes (CC payload)
#   • build_dt(payload, eot=True, tpdu_nr=0)       → bytes (DT wrapper)
#
# La CC echeggia tutti i parametri della CR (TPDU-Size, TSAP-Calling, TSAP-Called)
# e scambia dst_ref/src_ref. È il comportamento di un PLC reale: accetta
# qualunque TSAP che gli viene chiesto.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import struct
import logging

log = logging.getLogger("honeypot.cotp")


def build_cc_from_raw(cotp_payload: bytes, our_src_ref: int = 0x000C) -> bytes:
    """
    Costruisce un Connection Confirm a partire dal payload COTP raw di una CR.
    Si aspetta `cotp_payload` che inizi con il byte LI (ovvero senza TPKT).

    Layout CR atteso:
       LI(1) PDU=0xE0 dst_ref(2)=0 src_ref(2) class(1) [params...]
    """
    if len(cotp_payload) < 7 or (cotp_payload[1] & 0xF0) != 0xE0:
        raise ValueError("Non è una Connection Request COTP valida")

    li           = cotp_payload[0]
    cr_src_ref   = cotp_payload[4:6]               # bytes raw, da echeggiare
    class_option = cotp_payload[6]

    # Estraggo tutti i TLV dei parametri così come sono e li riemetto
    params_buf = bytearray()
    offset = 7
    end    = 1 + li
    while offset + 2 <= end and offset + 2 <= len(cotp_payload):
        code = cotp_payload[offset]
        plen = cotp_payload[offset + 1]
        val  = cotp_payload[offset + 2:offset + 2 + plen]
        params_buf.append(code)
        params_buf.append(plen)
        params_buf.extend(val)
        offset += 2 + plen

    # Header CC: LI(1) PDU(1)=0xD0 dst_ref(2) src_ref(2) class(1) [params]
    li_cc = 6 + len(params_buf)
    cc = struct.pack(">BB", li_cc, 0xD0)
    cc += cr_src_ref                                # dst_ref = src del client
    cc += struct.pack(">H", our_src_ref)            # nostro src_ref
    cc += struct.pack(">B", class_option)
    cc += bytes(params_buf)

    log.debug(f"CC: dst_ref={cr_src_ref.hex()} our_src_ref=0x{our_src_ref:04X} "
              f"params={len(params_buf)}B")
    return cc


def build_dt(payload: bytes, eot: bool = True, tpdu_nr: int = 0) -> bytes:
    """
    Costruisce un COTP Data Transfer (per incapsulare risposte S7/S7+).
    Header DT: LI=0x02  PDU=0xF0  TPDU/EOT(1)
    """
    eot_bit = 0x80 if eot else 0x00
    return bytes([0x02, 0xF0, eot_bit | (tpdu_nr & 0x7F)]) + payload