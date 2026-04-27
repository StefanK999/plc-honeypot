# ─────────────────────────────────────────────────────────────────────────────
# parsers/tcp_reassembler.py
# Riassemblaggio TCP minimale per il nostro caso d'uso.
#
# PROBLEMA che risolve:
#   Un singolo segmento TCP può contenere:
#     a) un solo TPKT          → caso facile
#     b) più TPKT accodati     → bisogna spezzarli
#     c) un TPKT spezzato a metà → bisogna aspettare il prossimo segmento
#
# Esempio reale dal nostro PCAP: il pacchetto 80-byte
#   "03 00 00 16 ... 03 00 00 19 ...  03 00 00 21 ..."
# contiene TRE messaggi TPKT consecutivi nello stesso segmento TCP.
#
# Questa classe accumula i byte di una direzione di flusso e ne estrae
# i messaggi TPKT completi man mano che diventano disponibili.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator

from parsers.tpkt import TPKT_HEADER_LEN


@dataclass
class FlowKey:
    """Identifica una direzione di un flusso TCP (4-tuple)."""
    src_ip   : str
    src_port : int
    dst_ip   : str
    dst_port : int

    def __hash__(self):
        return hash((self.src_ip, self.src_port, self.dst_ip, self.dst_port))

    def reverse(self) -> "FlowKey":
        return FlowKey(self.dst_ip, self.dst_port, self.src_ip, self.src_port)

    def __str__(self):
        return f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}"


class TCPReassembler:
    """
    Mantiene un buffer di byte per ogni direzione di flusso e produce
    messaggi TPKT completi su richiesta.
    """

    def __init__(self):
        self._buffers : dict[FlowKey, bytearray] = defaultdict(bytearray)

    def feed(self, key: FlowKey, payload: bytes) -> list[bytes]:
        """
        Aggiunge `payload` al buffer del flusso `key` ed estrae tutti i
        messaggi TPKT completi che si possono ottenere.
        Restituisce la lista di messaggi (ognuno è un TPKT intero, header+payload).
        """
        buf = self._buffers[key]
        buf.extend(payload)

        out = []
        while len(buf) >= TPKT_HEADER_LEN:
            # Controllo veloce di sanità: byte 0 deve essere 0x03
            if buf[0] != 0x03:
                # disallineamento — gettiamo via un byte e riproviamo
                # (questo capita solo se i dati sono corrotti)
                buf.pop(0)
                continue

            length = struct.unpack(">H", bytes(buf[2:4]))[0]
            if length < TPKT_HEADER_LEN or length > 65535:
                # length impossibile, scartiamo un byte
                buf.pop(0)
                continue

            if len(buf) < length:
                # messaggio non ancora completo, attendiamo
                break

            # estraiamo il messaggio completo
            out.append(bytes(buf[:length]))
            del buf[:length]

        return out

    def reset(self, key: FlowKey | None = None):
        if key is None:
            self._buffers.clear()
        else:
            self._buffers.pop(key, None)
