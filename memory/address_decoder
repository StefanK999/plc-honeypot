# ─────────────────────────────────────────────────────────────────────────────
# memory/address_decoder.py
# Parser e formattatore degli indirizzi S7 in stile Siemens.
#
# Sintassi supportata:
#   DB1.DBB0      byte  0 di DB1
#   DB1.DBW2      word  agli offset 2-3 di DB1 (big-endian)
#   DB1.DBD4      dword agli offset 4-7 di DB1
#   DB1.DBX5.3    bit   3 del byte 5 di DB1
#   M0            byte  0 dell'area Merker (flag)
#   M0.5          bit   5 del byte 0 Merker
#   I0.0 / Q0.0   bit di Input / Output
#
# Note di design:
#   • Restituiamo dataclass perché vogliamo pattern matching strutturato a
#     valle, non manipolazione di stringhe.
#   • L'AreaCode usa i codici di area S7comm "ufficiali" (li riusiamo nel
#     handler S7 per costruire risposte protocollo-compliant).
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import re
from dataclasses import dataclass
from enum import IntEnum


class AreaCode(IntEnum):
    """Codici di area S7comm (cfr. Wireshark dissector packet-s7comm.c)."""
    INPUTS       = 0x81    # I (process inputs)
    OUTPUTS      = 0x82    # Q (process outputs)
    FLAGS        = 0x83    # M (Merker / flag)
    DATA_BLOCK   = 0x84    # DB
    INSTANCE_DB  = 0x85    # DI (rare, non gestito qui)
    LOCAL        = 0x86    # L  (rare, non gestito qui)


# Mappatura simbolica → AreaCode (usata dal parser)
_AREA_LETTERS = {
    "DB": AreaCode.DATA_BLOCK,
    "M":  AreaCode.FLAGS,
    "I":  AreaCode.INPUTS,
    "Q":  AreaCode.OUTPUTS,
}


@dataclass(frozen=True)
class S7Address:
    """Rappresentazione decodificata di un indirizzo S7."""
    area        : AreaCode
    db_number   : int           # 0 se non DB
    byte_offset : int
    bit_offset  : int | None    # None se non bit
    size        : str           # "BIT", "BYTE", "WORD", "DWORD"

    @property
    def length_bytes(self) -> int:
        """Quanti byte servono per leggere/scrivere questo indirizzo."""
        return {"BIT": 1, "BYTE": 1, "WORD": 2, "DWORD": 4}[self.size]

    def redis_key(self) -> str:
        """Chiave Redis del HASH che contiene i byte di quest'area."""
        if self.area == AreaCode.DATA_BLOCK:
            return f"plc:memory:DB{self.db_number}"
        if self.area == AreaCode.FLAGS:    return "plc:memory:M"
        if self.area == AreaCode.INPUTS:   return "plc:memory:I"
        if self.area == AreaCode.OUTPUTS:  return "plc:memory:Q"
        raise ValueError(f"Area non gestita: {self.area}")


# ─────────────────────────────────────────────────────────────────────────────
# Parser
#
# Casi:
#   "DB1.DBW2"      → DB1, byte_offset=2, size=WORD
#   "DB10.DBX5.3"   → DB10, byte_offset=5, bit_offset=3, size=BIT
#   "M0.5"          → M, byte_offset=0, bit_offset=5, size=BIT
#   "M3"            → M, byte_offset=3, size=BYTE   (default per M senza bit)
#   "I0.0", "Q1.7"  → BIT
#
# Le regex sono volutamente ancorate (^...$) e parlanti per leggibilità.
# ─────────────────────────────────────────────────────────────────────────────

_RE_DB_TYPED = re.compile(
    r"^DB(?P<db>\d+)\.DB(?P<type>[BWDX])(?P<byte>\d+)(?:\.(?P<bit>\d+))?$"
)
_RE_NONDB = re.compile(
    r"^(?P<area>[MIQ])(?P<byte>\d+)(?:\.(?P<bit>\d+))?$"
)

_DB_TYPE_TO_SIZE = {"B": "BYTE", "W": "WORD", "D": "DWORD", "X": "BIT"}


def parse(addr_str: str) -> S7Address:
    """
    Parsa un indirizzo S7 in formato Siemens. Solleva ValueError se invalido.
    """
    addr_str = addr_str.strip().upper()

    # ── DB1.DBW2 / DB1.DBX5.3 / DB1.DBB0 / DB1.DBD4 ──────────────────────────
    m = _RE_DB_TYPED.match(addr_str)
    if m:
        size = _DB_TYPE_TO_SIZE[m.group("type")]
        bit  = m.group("bit")
        if size == "BIT" and bit is None:
            raise ValueError(f"Indirizzo BIT senza offset di bit: {addr_str}")
        if size != "BIT" and bit is not None:
            raise ValueError(f"Offset di bit non valido per {size}: {addr_str}")
        return S7Address(
            area        = AreaCode.DATA_BLOCK,
            db_number   = int(m.group("db")),
            byte_offset = int(m.group("byte")),
            bit_offset  = int(bit) if bit is not None else None,
            size        = size,
        )

    # ── M0 / M0.5 / I0.0 / Q1.7 ──────────────────────────────────────────────
    m = _RE_NONDB.match(addr_str)
    if m:
        area_code = _AREA_LETTERS[m.group("area")]
        bit = m.group("bit")
        if bit is not None and not (0 <= int(bit) <= 7):
            raise ValueError(f"Bit offset fuori range 0-7: {addr_str}")
        return S7Address(
            area        = area_code,
            db_number   = 0,
            byte_offset = int(m.group("byte")),
            bit_offset  = int(bit) if bit is not None else None,
            size        = "BIT" if bit is not None else "BYTE",
        )

    raise ValueError(f"Indirizzo S7 non riconosciuto: '{addr_str}'")