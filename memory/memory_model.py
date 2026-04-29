# ─────────────────────────────────────────────────────────────────────────────
# memory/memory_model.py
# Memory model del PLC virtuale, con persistenza in Redis.
#
# Granularità sul backend: BYTE.
#   plc:memory:DB1   HASH   chiave="0","1",... valore=int 0-255
#   plc:memory:M     HASH   idem
#   plc:memory:I     HASH   idem
#   plc:memory:Q     HASH   idem
#
# API:
#   • read_bytes / write_bytes  → primitive raw che useranno gli handler S7
#   • read_word / write_word    → comode per debug/test/inizializzazione
#   • read_bit / write_bit      → idem
#   • initialize_db             → pre-popola un DB a zero
#
# Endianness: S7 è BIG-ENDIAN. Una WORD 0x1234 a DB1.DBW0 → byte 0 = 0x12,
# byte 1 = 0x34.
#
# Notification: ogni write pubblica un evento sul canale "plc:memory:writes".
# È il "trigger" pubsub che useranno elevator_runner / scan_logger / ecc.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import json
import logging
import struct
import time
from typing import Any

from .address_decoder import S7Address, parse, AreaCode

log = logging.getLogger("plc.memory")

WRITE_NOTIFY_CHANNEL = "plc:memory:writes"


class MemoryModel:
    """
    Astrazione di alto livello sopra Redis. Tutto async perché il honeypot
    è async: un singolo client Redis condiviso tra handler.
    """

    def __init__(self, async_redis_client):
        """
        async_redis_client: istanza di redis.asyncio.Redis (decode_responses=False).
        Usiamo decode_responses=False perché ragioniamo a byte raw, non stringhe.
        """
        self._r = async_redis_client

    # ── Helpers privati ──────────────────────────────────────────────────────
    @staticmethod
    def _redis_key_for(area: AreaCode, db_number: int = 0) -> str:
        """Chiave Redis di un'area di memoria."""
        if area == AreaCode.DATA_BLOCK: return f"plc:memory:DB{db_number}"
        if area == AreaCode.FLAGS:      return "plc:memory:M"
        if area == AreaCode.INPUTS:     return "plc:memory:I"
        if area == AreaCode.OUTPUTS:    return "plc:memory:Q"
        raise ValueError(f"Area non gestita: {area}")

    async def _notify_write(self, area: AreaCode, db_number: int,
                            offset: int, length: int) -> None:
        """Pubblica una notifica di scrittura sul canale pubsub."""
        try:
            payload = json.dumps({
                "area"        : area.name,
                "db_number"   : db_number,
                "byte_offset" : offset,
                "length"      : length,
                "ts"          : f"{time.time():.3f}",
            })
            await self._r.publish(WRITE_NOTIFY_CHANNEL, payload)
        except Exception as e:
            # Best-effort: una notifica fallita non deve bloccare la scrittura
            log.debug(f"notify_write failed: {e}")

    # ── API raw (byte-level) ─────────────────────────────────────────────────
    async def read_bytes(self, area: AreaCode, db_number: int,
                         offset: int, length: int) -> bytes:
        """
        Legge `length` byte sequenziali da `offset` nell'area indicata.
        Byte non inizializzati vengono trattati come 0x00 (comportamento PLC).
        """
        key = self._redis_key_for(area, db_number)
        # HMGET in batch: una sola roundtrip a Redis per N byte
        fields = [str(i).encode() for i in range(offset, offset + length)]
        values = await self._r.hmget(key, fields)
        out = bytearray(length)
        for i, v in enumerate(values):
            if v is not None:
                # v è bytes tipo b"171" (rappresentazione decimale stringa)
                # Memorizziamo come stringa decimale per leggibilità con redis-cli HGETALL
                out[i] = int(v) & 0xFF
        return bytes(out)

    async def write_bytes(self, area: AreaCode, db_number: int,
                          offset: int, data: bytes) -> None:
        """
        Scrive `data` a partire da `offset` nell'area indicata.
        Operazione atomica via pipeline (anche se più HSET).
        """
        key = self._redis_key_for(area, db_number)
        if not data:
            return
        # Costruiamo mapping field→value per HSET multi-field
        mapping = {str(offset + i): str(b) for i, b in enumerate(data)}
        # In redis-py async: hset accetta un dict via mapping=... in versioni recenti.
        # Per compatibilità: usiamo pipeline con HSET multi-field (HSET key f1 v1 f2 v2 ...).
        async with self._r.pipeline(transaction=True) as pipe:
            pipe.hset(key, mapping=mapping)
            pipe.hset("plc:memory:meta", "last_write_ts",     f"{time.time():.3f}")
            pipe.hset("plc:memory:meta", "last_write_area",   area.name)
            pipe.hset("plc:memory:meta", "last_write_db",     str(db_number))
            pipe.hset("plc:memory:meta", "last_write_offset", str(offset))
            pipe.hset("plc:memory:meta", "last_write_length", str(len(data)))
            await pipe.execute()
        await self._notify_write(area, db_number, offset, len(data))

    # ── API "simbolica" (utile per debug e inizializzazione) ─────────────────
    async def read_word(self, addr_str: str) -> int:
        """Legge una WORD (2 byte big-endian) all'indirizzo simbolico."""
        addr = parse(addr_str)
        if addr.size != "WORD":
            raise ValueError(f"{addr_str} non è una WORD")
        data = await self.read_bytes(addr.area, addr.db_number,
                                     addr.byte_offset, 2)
        return struct.unpack(">H", data)[0]

    async def write_word(self, addr_str: str, value: int) -> None:
        addr = parse(addr_str)
        if addr.size != "WORD":
            raise ValueError(f"{addr_str} non è una WORD")
        data = struct.pack(">H", value & 0xFFFF)
        await self.write_bytes(addr.area, addr.db_number,
                               addr.byte_offset, data)

    async def read_dword(self, addr_str: str) -> int:
        addr = parse(addr_str)
        if addr.size != "DWORD":
            raise ValueError(f"{addr_str} non è una DWORD")
        data = await self.read_bytes(addr.area, addr.db_number,
                                     addr.byte_offset, 4)
        return struct.unpack(">I", data)[0]

    async def write_dword(self, addr_str: str, value: int) -> None:
        addr = parse(addr_str)
        if addr.size != "DWORD":
            raise ValueError(f"{addr_str} non è una DWORD")
        data = struct.pack(">I", value & 0xFFFFFFFF)
        await self.write_bytes(addr.area, addr.db_number,
                               addr.byte_offset, data)

    async def read_byte(self, addr_str: str) -> int:
        addr = parse(addr_str)
        if addr.size not in ("BYTE", "BIT"):
            raise ValueError(f"{addr_str} non è un BYTE")
        data = await self.read_bytes(addr.area, addr.db_number,
                                     addr.byte_offset, 1)
        return data[0]

    async def write_byte(self, addr_str: str, value: int) -> None:
        addr = parse(addr_str)
        if addr.size != "BYTE":
            raise ValueError(f"{addr_str} non è un BYTE puro")
        await self.write_bytes(addr.area, addr.db_number,
                               addr.byte_offset, bytes([value & 0xFF]))

    async def read_bit(self, addr_str: str) -> bool:
        """Legge un singolo bit (read-modify-style)."""
        addr = parse(addr_str)
        if addr.size != "BIT":
            raise ValueError(f"{addr_str} non è un BIT")
        data = await self.read_bytes(addr.area, addr.db_number,
                                     addr.byte_offset, 1)
        return bool((data[0] >> addr.bit_offset) & 0x01)

    async def write_bit(self, addr_str: str, value: bool) -> None:
        """
        Scrive un singolo bit. Sequenza read-modify-write su Redis.
        Non è atomica al 100% (race se due writer toccano stesso byte
        contemporaneamente), ma per il caso d'uso PLC honeypot è OK.
        """
        addr = parse(addr_str)
        if addr.size != "BIT":
            raise ValueError(f"{addr_str} non è un BIT")
        current = await self.read_bytes(addr.area, addr.db_number,
                                        addr.byte_offset, 1)
        b = current[0]
        mask = 1 << addr.bit_offset
        b = (b | mask) if value else (b & ~mask & 0xFF)
        await self.write_bytes(addr.area, addr.db_number,
                               addr.byte_offset, bytes([b]))

    # ── Inizializzazione ─────────────────────────────────────────────────────
    async def initialize_db(self, db_number: int, size_bytes: int,
                            force: bool = False) -> bool:
        """
        Inizializza un DB a zero, se non già presente.

        Args:
            force: se True, sovrascrive anche se il DB esiste già.

        Returns:
            True se il DB è stato (re)inizializzato, False se esisteva già.
        """
        key = self._redis_key_for(AreaCode.DATA_BLOCK, db_number)
        existed = await self._r.exists(key)
        if existed and not force:
            log.info(f"DB{db_number} già inizializzato, skip")
            return False

        if existed:
            await self._r.delete(key)

        # Scriviamo size_bytes byte tutti a zero
        zeros = bytes(size_bytes)
        await self.write_bytes(AreaCode.DATA_BLOCK, db_number, 0, zeros)
        log.info(f"DB{db_number} inizializzato con {size_bytes} byte a zero")
        return True