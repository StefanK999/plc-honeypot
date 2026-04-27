# ─────────────────────────────────────────────────────────────────────────────
# parsers/s7comm.py
# S7comm "classico" – Protocol ID 0x32
#
# È il payload trasportato dentro COTP-DT.
# Struttura header (10 o 12 byte a seconda del ROSCTR):
#
#   Byte 0      : Protocol ID            (sempre 0x32)
#   Byte 1      : ROSCTR (msg type)      (0x01 Job, 0x02 Ack, 0x03 AckData, 0x07 UD)
#   Bytes 2-3   : Redundancy ID          (di solito 0x0000)
#   Bytes 4-5   : Protocol Data Unit Ref (PDU reference, contatore di sessione)
#   Bytes 6-7   : Parameter length       (lunghezza area "parametri")
#   Bytes 8-9   : Data length            (lunghezza area "dati")
#   Bytes 10-11 : (solo se ROSCTR=2 o 3) Error class + Error code
#
# Dopo l'header arrivano:
#   • PARAMETER area (lunga `parameter_length` byte) → contiene la "domanda"
#   • DATA area      (lunga `data_length`)           → payload effettivo
#
# Ho ricostruito la struttura confrontando il PCAP con la documentazione
# pubblica di Wireshark (epan/dissectors/packet-s7comm.c) e con
# il progetto open snap7.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Optional

from tables import (
    S7_ROSCTR, S7_FUNCTIONS, S7_USERDATA_TYPE, S7_USERDATA_FUNCGROUP,
    SZL_IDS, SZL_INDEX_DESC, S7_TRANSPORT_SIZE, S7_RETURN_CODES,
)

S7_PROTOCOL_ID = 0x32


# ─── Strutture decodificate ──────────────────────────────────────────────────
@dataclass
class S7Header:
    protocol_id   : int
    rosctr        : int
    rosctr_name   : str
    redundancy_id : int
    pdu_ref       : int
    param_len     : int
    data_len      : int
    error_class   : Optional[int] = None
    error_code    : Optional[int] = None


@dataclass
class S7SetupCommunication:
    max_amq_calling : int
    max_amq_called  : int
    pdu_length      : int

    def describe(self) -> str:
        return (
            f"Setup-Communication: PDU max={self.pdu_length} byte, "
            f"jobs paralleli (calling/called)={self.max_amq_calling}/{self.max_amq_called}"
        )


@dataclass
class SZLRequest:
    """Richiesta UserData con functional group 0x44 (Read SZL)."""
    szl_id    : int
    szl_index : int

    def describe(self) -> str:
        id_meaning  = SZL_IDS.get(self.szl_id, f"SZL sconosciuta")
        idx_meaning = SZL_INDEX_DESC.get(self.szl_index, "")
        idx_str = f", index=0x{self.szl_index:04X}"
        if idx_meaning:
            idx_str += f" ({idx_meaning})"
        return (f"Read SZL  id=0x{self.szl_id:04X} ({id_meaning}){idx_str}")


@dataclass
class SZLResponse:
    szl_id        : int
    szl_index     : int
    partial_count : int
    items         : list[bytes]    # blob crudi

    def describe(self) -> str:
        id_meaning = SZL_IDS.get(self.szl_id, "?")
        text_hits = []
        for item in self.items:
            # estraiamo testo ASCII >=4 caratteri come euristica
            run = bytearray()
            for b in item:
                if 32 <= b < 127:
                    run.append(b)
                else:
                    if len(run) >= 4:
                        text_hits.append(run.decode())
                    run = bytearray()
            if len(run) >= 4:
                text_hits.append(run.decode())
        out = [f"Read SZL response  id=0x{self.szl_id:04X} ({id_meaning}), "
               f"{self.partial_count} record"]
        for t in text_hits[:5]:
            out.append(f"   ⮡ stringa estratta: «{t.strip()}»")
        return "\n".join(out)


@dataclass
class S7Frame:
    header  : S7Header
    parameter_raw : bytes
    data_raw      : bytes

    # interpretazioni opzionali
    setup_comm   : Optional[S7SetupCommunication] = None
    szl_request  : Optional[SZLRequest]  = None
    szl_response : Optional[SZLResponse] = None
    function_code: Optional[int] = None

    valid : bool = True
    error : Optional[str] = None

    def describe(self) -> str:
        if not self.valid:
            return f"[S7comm] ERRORE: {self.error}"

        h = self.header
        lines = [
            f"[S7comm] proto=0x{h.protocol_id:02X}  "
            f"ROSCTR=0x{h.rosctr:02X} → {h.rosctr_name}  "
            f"PDU#{h.pdu_ref}  "
            f"param_len={h.param_len}  data_len={h.data_len}"
        ]
        if h.error_class is not None:
            err = S7_RETURN_CODES.get(h.error_code, "?")
            lines.append(
                f"   error class=0x{h.error_class:02X} "
                f"code=0x{h.error_code:02X} ({err})"
            )

        if self.function_code is not None:
            fname = S7_FUNCTIONS.get(self.function_code,
                                     f"sconosciuta(0x{self.function_code:02X})")
            lines.append(f"   funzione=0x{self.function_code:02X} → {fname}")

        if self.setup_comm:
            lines.append(f"   ⮡ {self.setup_comm.describe()}")
        if self.szl_request:
            lines.append(f"   ⮡ {self.szl_request.describe()}")
        if self.szl_response:
            for ln in self.szl_response.describe().split("\n"):
                lines.append(f"   ⮡ {ln}")

        return "\n".join(lines)


# ─── Parsing ─────────────────────────────────────────────────────────────────
def parse(data: bytes) -> S7Frame:
    """
    Parsa il payload di un COTP-DT come messaggio S7comm classico (0x32).
    """
    if len(data) < 10 or data[0] != S7_PROTOCOL_ID:
        return S7Frame(
            header=S7Header(0, 0, "?", 0, 0, 0, 0),
            parameter_raw=b"", data_raw=b"",
            valid=False,
            error=(f"Non è S7comm classico "
                   f"(byte0=0x{data[0]:02X}, len={len(data)})"
                   if data else "vuoto"),
        )

    rosctr = data[1]
    redundancy = struct.unpack(">H", data[2:4])[0]
    pdu_ref    = struct.unpack(">H", data[4:6])[0]
    param_len  = struct.unpack(">H", data[6:8])[0]
    data_len   = struct.unpack(">H", data[8:10])[0]

    header = S7Header(
        protocol_id=S7_PROTOCOL_ID,
        rosctr=rosctr,
        rosctr_name=S7_ROSCTR.get(rosctr, "?"),
        redundancy_id=redundancy,
        pdu_ref=pdu_ref,
        param_len=param_len,
        data_len=data_len,
    )

    offset = 10
    if rosctr in (0x02, 0x03):    # ack / ack-data hanno 2 byte di errore extra
        if len(data) < 12:
            return S7Frame(header=header, parameter_raw=b"", data_raw=b"",
                           valid=False, error="Header ack troncato")
        header.error_class = data[10]
        header.error_code  = data[11]
        offset = 12

    if len(data) < offset + param_len + data_len:
        # tronchiamo a quello che abbiamo, ma segnaliamo
        param = data[offset:offset + param_len]
        rest  = data[offset + param_len:]
    else:
        param = data[offset:offset + param_len]
        rest  = data[offset + param_len:offset + param_len + data_len]

    frame = S7Frame(header=header, parameter_raw=param, data_raw=rest)

    # ── interpretazione del Parameter Header ─────────────────────────────────
    if param_len >= 1:
        func_code = param[0]
        frame.function_code = func_code

        # Setup Communication (0xF0): 8 byte di parametri totali
        if func_code == 0xF0 and param_len >= 8:
            # Layout: F0 00 max_amq_calling(2) max_amq_called(2) pdu_length(2)
            max_calling = struct.unpack(">H", param[2:4])[0]
            max_called  = struct.unpack(">H", param[4:6])[0]
            pdu_length  = struct.unpack(">H", param[6:8])[0]
            frame.setup_comm = S7SetupCommunication(
                max_amq_calling=max_calling,
                max_amq_called=max_called,
                pdu_length=pdu_length,
            )

        # UserData (ROSCTR=0x07) → di solito Read SZL
        elif rosctr == 0x07 and param_len >= 8:
            # Parameter UserData: 00 01 12 [paramlen_hi paramlen_lo] type_funcgroup subfunc seqnum ...
            # Gli ultimi byte indicano type/funcgroup. La data area contiene SZL ID/Index.
            #
            # Nel PCAP della cattura:
            #   parametro: 00 01 12 04 11 44 01 00
            #                          ^^ ^^ ^^ ^^
            #                          |  |  |  +- sequence number
            #                          |  |  +---- subfunction (0x01 = read SZL)
            #                          |  +------- functional group (0x44 = SZL)
            #                          +---------- type/funcgroup (0x11 = CPU diagnostic)
            type_byte    = param[5] if len(param) > 5 else 0
            funcgroup    = (param[5] & 0x0F) if len(param) > 5 else 0
            subfunction  = param[6] if len(param) > 6 else 0

            # Data area: return_code(1) transport_size(1) length(2) [SZL_ID(2) SZL_INDEX(2) ...]
            if rest and len(rest) >= 8 and rest[0] == 0xFF:
                # Risposta: payload SZL valido
                szl_id    = struct.unpack(">H", rest[4:6])[0]
                szl_index = struct.unpack(">H", rest[6:8])[0]
                # gli SZL records iniziano dopo: 4 byte di header (id/index)
                # + 2 byte length record + 2 byte n_records.
                if len(rest) >= 12:
                    rec_len   = struct.unpack(">H", rest[8:10])[0]
                    n_records = struct.unpack(">H", rest[10:12])[0]
                    items = []
                    cur = 12
                    for _ in range(n_records):
                        items.append(rest[cur:cur + rec_len])
                        cur += rec_len
                    frame.szl_response = SZLResponse(
                        szl_id=szl_id, szl_index=szl_index,
                        partial_count=n_records, items=items,
                    )
                else:
                    frame.szl_response = SZLResponse(szl_id, szl_index, 0, [])
            elif rest and len(rest) >= 8:
                # Richiesta: nei dati abbiamo SZL_ID e SZL_INDEX
                szl_id    = struct.unpack(">H", rest[4:6])[0]
                szl_index = struct.unpack(">H", rest[6:8])[0]
                frame.szl_request = SZLRequest(szl_id=szl_id, szl_index=szl_index)

    return frame


def looks_like_s7comm(data: bytes) -> bool:
    """Controllo rapido: protocol ID 0x32 al primo byte?"""
    return len(data) >= 1 and data[0] == S7_PROTOCOL_ID
