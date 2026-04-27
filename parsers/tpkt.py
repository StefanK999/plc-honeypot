# ─────────────────────────────────────────────────────────────────────────────
# parsers/tpkt.py
# RFC 1006 – ISO Transport Service on top of the TCP
#
# Struttura TPKT (4 byte fissi):
#   Byte 0  : Version  → sempre 0x03
#   Byte 1  : Reserved → sempre 0x00
#   Bytes 2-3: Length  → lunghezza totale (header incluso), big-endian
#
# Nota: un TPKT può "spaccarsi" su più segmenti TCP.
# Il tcp_reassembler.py gestisce la ricostruzione prima di chiamare questo.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Optional


TPKT_HEADER_LEN = 4
TPKT_VERSION    = 0x03


@dataclass
class TPKTFrame:
    version  : int
    reserved : int
    length   : int          # lunghezza totale dichiarata (header + payload)
    payload  : bytes        # contenuto grezzo dopo i 4 byte TPKT

    # ── risultato interpretato ───────────────────────────────────────────────
    valid    : bool = True
    error    : Optional[str] = None

    @property
    def payload_len(self) -> int:
        return len(self.payload)

    def summary(self) -> dict:
        return {
            "layer"   : "TPKT",
            "version" : f"0x{self.version:02X}",
            "length"  : self.length,
            "payload_bytes": self.payload_len,
            "valid"   : self.valid,
            "error"   : self.error,
        }

    def describe(self) -> str:
        if not self.valid:
            return f"[TPKT] ERRORE: {self.error}"
        return (
            f"[TPKT] RFC-1006 | lunghezza totale={self.length} byte "
            f"| payload COTP={self.payload_len} byte"
        )


def parse(data: bytes) -> TPKTFrame:
    """
    Parsa i 4 byte TPKT e restituisce un TPKTFrame.
    `data` deve contenere ALMENO il messaggio completo (header + payload).
    """
    if len(data) < TPKT_HEADER_LEN:
        return TPKTFrame(0, 0, 0, b"", valid=False,
                         error=f"Troppo corto ({len(data)} byte, minimo 4)")

    version, reserved, length = struct.unpack(">BBH", data[:4])
    payload = data[4:length]   # tronchiamo al length dichiarato

    errors = []
    if version != TPKT_VERSION:
        errors.append(f"version attesa 0x03 trovata 0x{version:02X}")
    if reserved != 0x00:
        errors.append(f"reserved atteso 0x00 trovato 0x{reserved:02X}")
    if length < TPKT_HEADER_LEN:
        errors.append(f"length {length} < 4 (impossibile)")
    if len(data) < length:
        errors.append(f"payload incompleto: attesi {length - 4} byte, "
                      f"disponibili {len(data) - 4}")

    valid = len(errors) == 0
    error = "; ".join(errors) if errors else None

    return TPKTFrame(version=version, reserved=reserved,
                     length=length, payload=payload,
                     valid=valid, error=error)


def split_tpkt_messages(stream: bytes) -> list[bytes]:
    """
    Spacca uno stream TCP continuo in messaggi TPKT individuali.
    Gestisce il caso in cui più TPKT siano stati accodati nello stesso
    buffer TCP (es. ritrasmissioni o pipelining).
    Restituisce una lista di bytes, ognuno un messaggio TPKT completo.
    """
    messages = []
    offset = 0
    while offset < len(stream):
        if len(stream) - offset < TPKT_HEADER_LEN:
            break  # header incompleto, attendiamo altri dati
        _, _, length = struct.unpack(">BBH", stream[offset:offset + 4])
        if length < TPKT_HEADER_LEN:
            break  # corrotto, usciamo
        end = offset + length
        if end > len(stream):
            break  # messaggio incompleto (spezzato su più segmenti TCP)
        messages.append(stream[offset:end])
        offset = end
    return messages
