# ─────────────────────────────────────────────────────────────────────────────
# parsers/cotp.py
# ISO 8073 / X.224 – Connection-Oriented Transport Protocol
#
# COTP viaggia DENTRO il payload TPKT.
# Esistono due "famiglie" di PDU che ci interessano:
#
#  ┌──────────────────────────────────────────────────────────────────────┐
#  │  CR / CC / DR / DC / ER  →  PDU di SEGNALAZIONE (apertura/chiusura) │
#  │  DT                       →  PDU DATI (dentro c'è il payload S7)    │
#  └──────────────────────────────────────────────────────────────────────┘
#
# Struttura comune:
#   Byte 0   : Length Indicator (LI)  → lunghezza header esclusi questo byte
#   Byte 1   : PDU Type (high nibble) | Credit (low nibble, solo CR/CC/DT)
#   ...      : campi specifici del tipo
#
# Nel PCAP osservato i tipi presenti sono CR (0xE0), CC (0xD0), DT (0xF0).
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Optional

from tables import COTP_PDU_TYPES, COTP_PARAM_CODES, TPDU_SIZES, TSAP_MEANINGS


@dataclass
class COTPParameter:
    code     : int
    length   : int
    value    : bytes

    def describe(self) -> str:
        name = COTP_PARAM_CODES.get(self.code, f"Unknown(0x{self.code:02X})")
        if self.code == 0xC0 and self.length == 1:
            size = TPDU_SIZES.get(self.value[0], "?")
            return f"{name} = {size} byte (codice 0x{self.value[0]:02X})"
        if self.code in (0xC1, 0xC2):
            try:
                txt = self.value.decode('ascii')
                meaning = TSAP_MEANINGS.get(self.value, "")
                if not meaning and txt.isprintable():
                    meaning = f"TSAP testuale '{txt}'"
                return f"{name} = {self.value.hex(' ').upper()} {f'({meaning})' if meaning else ''}"
            except UnicodeDecodeError:
                meaning = TSAP_MEANINGS.get(self.value, "")
                return f"{name} = {self.value.hex(' ').upper()} {f'({meaning})' if meaning else ''}"
        return f"{name} = {self.value.hex(' ').upper()}"


@dataclass
class COTPFrame:
    length_indicator : int
    pdu_type         : int          # high nibble del byte 1 (0xE0, 0xD0, 0xF0...)
    pdu_type_name    : str
    raw_byte1        : int          # byte 1 grezzo (PDU type | credit)

    # Campi specifici per CR/CC/DR
    dst_ref          : Optional[int] = None
    src_ref          : Optional[int] = None
    class_option     : Optional[int] = None

    # Campo specifico per DT
    tpdu_nr          : Optional[int] = None
    eot              : Optional[bool] = None  # End-of-Transmission

    parameters       : list[COTPParameter] = field(default_factory=list)
    payload          : bytes = b""            # solo per DT: dentro c'è S7

    valid            : bool = True
    error            : Optional[str] = None

    def is_data(self) -> bool:
        """True se è una PDU di tipo DT (contiene payload applicativo S7)."""
        return self.pdu_type == 0xF0

    def is_connect(self) -> bool:
        return self.pdu_type in (0xE0, 0xD0)

    def describe(self) -> str:
        if not self.valid:
            return f"[COTP] ERRORE: {self.error}"

        lines = [f"[COTP] {self.pdu_type_name}  (LI={self.length_indicator})"]

        if self.is_connect():
            lines.append(
                f"   dst_ref=0x{self.dst_ref:04X}  "
                f"src_ref=0x{self.src_ref:04X}  "
                f"class/option=0x{self.class_option:02X}"
            )
            for p in self.parameters:
                lines.append(f"   • {p.describe()}")

        elif self.is_data():
            lines.append(
                f"   TPDU#={self.tpdu_nr}  "
                f"EOT={'sì' if self.eot else 'no'}  "
                f"payload={len(self.payload)} byte"
            )

        return "\n".join(lines)


def parse(data: bytes) -> COTPFrame:
    """
    Parsa il payload di un TPKT e restituisce un COTPFrame.
    """
    if len(data) < 2:
        return COTPFrame(0, 0, "?", 0, valid=False,
                         error=f"COTP troppo corto ({len(data)} byte)")

    li = data[0]
    byte1 = data[1]
    pdu_type = byte1 & 0xF0   # high nibble
    pdu_name = COTP_PDU_TYPES.get(pdu_type, f"Unknown(0x{pdu_type:02X})")

    frame = COTPFrame(
        length_indicator=li,
        pdu_type=pdu_type,
        pdu_type_name=pdu_name,
        raw_byte1=byte1,
    )

    # ── Connection Request / Confirm / Disconnect Request ────────────────────
    if pdu_type in (0xE0, 0xD0, 0x80):
        if len(data) < 7:
            frame.valid = False
            frame.error = "Header CR/CC troppo corto"
            return frame
        # bytes 2-3: dst_ref, 4-5: src_ref, 6: class/option
        frame.dst_ref, frame.src_ref, frame.class_option = struct.unpack(
            ">HHB", data[2:7]
        )
        # parametri variabili dal byte 7 fino a (1 + LI)
        params_end = 1 + li
        offset = 7
        while offset + 2 <= params_end and offset + 2 <= len(data):
            code = data[offset]
            plen = data[offset + 1]
            value = data[offset + 2:offset + 2 + plen]
            frame.parameters.append(COTPParameter(code, plen, value))
            offset += 2 + plen

    # ── Data Transfer ────────────────────────────────────────────────────────
    elif pdu_type == 0xF0:
        if len(data) < 3:
            frame.valid = False
            frame.error = "Header DT troppo corto"
            return frame
        tpdu_byte = data[2]
        frame.eot = bool(tpdu_byte & 0x80)
        frame.tpdu_nr = tpdu_byte & 0x7F
        # il payload S7 inizia dopo l'header completo (1 + LI byte)
        frame.payload = data[1 + li:]

    else:
        # tipo non gestito esplicitamente
        frame.payload = data[1 + li:] if (1 + li) <= len(data) else b""

    return frame
