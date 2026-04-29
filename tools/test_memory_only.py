#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# tools/test_memory_only.py
# Test del memory model in isolamento: niente protocollo S7, solo Redis.
#
# Richiede Redis raggiungibile. Configura via env REDIS_URL.
#
# Uso:    python3 tools/test_memory_only.py
# ─────────────────────────────────────────────────────────────────────────────
import asyncio
import os
import sys
from pathlib import Path

# Importa il package memory dalla root del progetto
sys.path.insert(0, str(Path(__file__).parent.parent))

from redis.asyncio import Redis
from memory import MemoryModel, parse


REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")


async def main():
    print(f"📡 Connetto a {REDIS_URL}")
    r = Redis.from_url(REDIS_URL, decode_responses=False)
    await r.ping()
    mm = MemoryModel(r)

    # Pulizia preventiva delle aree di test
    await r.delete("plc:memory:DB1", "plc:memory:DB2",
                   "plc:memory:M", "plc:memory:meta")

    # ── Test 1: address decoder ─────────────────────────────────────────────
    print("\n[1] Address decoder")
    cases = [
        ("DB1.DBW0",   "WORD",  1, 0,    None),
        ("DB1.DBX5.3", "BIT",   1, 5,    3),
        ("DB10.DBD4",  "DWORD", 10, 4,   None),
        ("M0.5",       "BIT",   0, 0,    5),
        ("M3",         "BYTE",  0, 3,    None),
    ]
    for addr_str, exp_size, exp_db, exp_byte, exp_bit in cases:
        a = parse(addr_str)
        ok = (a.size == exp_size and a.db_number == exp_db
              and a.byte_offset == exp_byte and a.bit_offset == exp_bit)
        print(f"  {'✓' if ok else '✗'} parse('{addr_str}') → "
              f"size={a.size}, db={a.db_number}, byte={a.byte_offset}, bit={a.bit_offset}")
        assert ok

    # ── Test 2: inizializzazione ────────────────────────────────────────────
    print("\n[2] Inizializzazione DB1 (256 byte)")
    created = await mm.initialize_db(1, 256)
    print(f"  ✓ DB1 inizializzato: created={created}")
    assert created
    val = await mm.read_byte("M0") if False else await mm.read_word("DB1.DBW0")
    assert val == 0, f"DB1.DBW0 dovrebbe essere 0, è {val}"
    print(f"  ✓ DB1.DBW0 = 0 (atteso 0)")

    # idempotenza
    again = await mm.initialize_db(1, 256)
    assert not again, "init duplicata non dovrebbe rifare nulla"
    print(f"  ✓ DB1 idempotenza confermata (già esistente, skip)")

    # ── Test 3: WORD R/W con endianness ─────────────────────────────────────
    print("\n[3] WORD read/write big-endian")
    await mm.write_word("DB1.DBW10", 0x1234)
    val = await mm.read_word("DB1.DBW10")
    assert val == 0x1234, f"atteso 0x1234, ottenuto 0x{val:04X}"
    print(f"  ✓ Write/Read DB1.DBW10 = 0x{val:04X}")

    # Verifica byte raw: deve essere 0x12, 0x34 (big-endian)
    raw = await mm.read_bytes(parse("DB1.DBW10").area, 1, 10, 2)
    assert raw == b'\x12\x34', f"endianness sbagliata: {raw.hex()}"
    print(f"  ✓ Byte order big-endian: byte10=0x{raw[0]:02X} byte11=0x{raw[1]:02X}")

    # ── Test 4: DWORD ───────────────────────────────────────────────────────
    print("\n[4] DWORD read/write")
    await mm.write_dword("DB1.DBD20", 0xDEADBEEF)
    val = await mm.read_dword("DB1.DBD20")
    assert val == 0xDEADBEEF
    print(f"  ✓ DB1.DBD20 = 0x{val:08X}")

    # ── Test 5: BIT ─────────────────────────────────────────────────────────
    print("\n[5] BIT read/write (read-modify-write)")
    await mm.write_byte("DB1.DBB30", 0)   # azzera byte
    await mm.write_bit("DB1.DBX30.0", True)
    await mm.write_bit("DB1.DBX30.3", True)
    await mm.write_bit("DB1.DBX30.7", True)

    b = await mm.read_byte("DB1.DBB30")
    expected = 0b10001001       # bit 0, 3, 7
    assert b == expected, f"atteso 0b{expected:08b}, ottenuto 0b{b:08b}"
    print(f"  ✓ DB1.DBB30 = 0b{b:08b} (bit 0,3,7 settati)")

    # toglie bit 3
    await mm.write_bit("DB1.DBX30.3", False)
    b = await mm.read_byte("DB1.DBB30")
    assert b == 0b10000001
    print(f"  ✓ Dopo write_bit(3, False): 0b{b:08b}")

    bit3 = await mm.read_bit("DB1.DBX30.3")
    bit7 = await mm.read_bit("DB1.DBX30.7")
    assert bit3 is False and bit7 is True
    print(f"  ✓ read_bit DB1.DBX30.3 = {bit3}, DB1.DBX30.7 = {bit7}")

    # ── Test 6: aree non-DB (M, I, Q) ───────────────────────────────────────
    print("\n[6] Aree M/I/Q")
    from memory import AreaCode
    await mm.write_bytes(AreaCode.FLAGS, 0, 0, b"\xAA\xBB\xCC")
    raw = await mm.read_bytes(AreaCode.FLAGS, 0, 0, 3)
    assert raw == b"\xAA\xBB\xCC"
    print(f"  ✓ M area write/read: {raw.hex()}")

    # ── Test 7: notifica pubsub ─────────────────────────────────────────────
    print("\n[7] Notifica pubsub on write")
    pubsub = r.pubsub()
    await pubsub.subscribe("plc:memory:writes")

    # Drena il messaggio di conferma "subscribe": è il primo che arriva sempre
    # quando ci si iscrive, e va consumato per assicurarci che la sub sia attiva
    # PRIMA della publish.
    await asyncio.wait_for(
        pubsub.get_message(ignore_subscribe_messages=False, timeout=2.0),
        timeout=2.0,
    )

    # Adesso siamo certi che il subscribe è registrato lato Redis.
    await mm.write_word("DB1.DBW40", 0xCAFE)

    # Aspetta il messaggio dati (con timeout generoso)
    msg = None
    deadline = asyncio.get_event_loop().time() + 2.0
    while asyncio.get_event_loop().time() < deadline:
        msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.5)
        if msg is not None:
            break

    if msg is None:
        print(f"  ✗ Nessuna notifica ricevuta entro 2s")
        assert False, "atteso evento pubsub"

    import json
    ev = json.loads(msg["data"])
    ok = (ev["area"] == "DATA_BLOCK" and ev["db_number"] == 1
          and ev["byte_offset"] == 40 and ev["length"] == 2)
    print(f"  {'✓' if ok else '✗'} evento ricevuto: {ev}")
    assert ok

    await pubsub.unsubscribe()
    await pubsub.aclose()

    # ── Test 8: meta ────────────────────────────────────────────────────────
    print("\n[8] Meta info dell'ultima scrittura")
    meta = await r.hgetall("plc:memory:meta")
    print(f"  ✓ meta: {dict(meta)}")
    assert b"last_write_ts" in meta

    # ── Cleanup finale ──────────────────────────────────────────────────────
    await r.aclose()

    print("\n" + "═" * 50)
    print("  Tutti i test memory_only PASSATI ✓")
    print("═" * 50)


if __name__ == "__main__":
    asyncio.run(main())