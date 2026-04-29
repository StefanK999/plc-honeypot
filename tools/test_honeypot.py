#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# test_honeypot.py
# Test end-to-end del honeypot.
#
# Verifica che, dato un PLC virtuale in ascolto, le query tipiche di
# Tenable producano risposte che contengano i marker di fingerprint:
#   • SZL 0x0011 → MLFB "6ES7 214-1HG40-0XB0"
#   • SZL 0x001C → "S7-1200" e "Siemens"
#   • Modbus FC 0x2B → "Siemens" / "S7-1200" / "4.6.0"
#
# Si aspetta l' honeypot in esecuzione su 127.0.0.1.
# Avvio:    python3 test_honeypot.py [host] [s7_port] [modbus_port]
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import asyncio
import socket
import struct
import sys


def hex_dump_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Estrazione naive di stringhe ASCII dal blob."""
    out, run = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            run.append(b)
        else:
            if len(run) >= min_len:
                out.append(run.decode())
            run = bytearray()
    if len(run) >= min_len:
        out.append(run.decode())
    return out


# ─── S7 ────────────────────────────────────────────────────────────────────
def wrap_tpkt(p): return struct.pack(">BBH", 0x03, 0x00, 4 + len(p)) + p
def wrap_dt(s):   return wrap_tpkt(bytes([0x02, 0xF0, 0x80]) + s)


def build_cr() -> bytes:
    tsap_dst = b"SIMATIC-ROOT-ES"
    params  = bytes([0xC0, 0x01, 0x0A])
    params += bytes([0xC1, 0x02, 0x01, 0x00])
    params += bytes([0xC2, len(tsap_dst)]) + tsap_dst
    li = 6 + len(params)
    cotp = struct.pack(">BBHHB", li, 0xE0, 0x0000, 0x0001, 0x00) + params
    return wrap_tpkt(cotp)


def build_setup() -> bytes:
    s7 = bytes([0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00,
                0xF0, 0x00, 0x00, 0x08, 0x00, 0x08, 0x01, 0xE0])
    return wrap_dt(s7)


def build_szl_request(szl_id: int, szl_index: int = 0,
                      pdu_ref: int = 2, seq_num: int = 0x42) -> bytes:
    """Read SZL via UserData (ROSCTR=0x07)."""
    data = bytes([0xFF, 0x09, 0x00, 0x04]) + struct.pack(">HH", szl_id, szl_index)
    param = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, seq_num])
    s7 = struct.pack(">BBHHHH",
                     0x32, 0x07, 0x0000, pdu_ref, len(param), len(data))
    s7 += param + data
    return wrap_dt(s7)


async def read_tpkt(reader):
    hdr = await reader.readexactly(4)
    total = struct.unpack(">H", hdr[2:4])[0]
    return hdr + await reader.readexactly(total - 4)


async def test_s7(host: str, port: int):
    print(f"\n══ TEST S7 su {host}:{port} ══")
    reader, writer = await asyncio.open_connection(host, port)

    # 1. CR → CC
    writer.write(build_cr()); await writer.drain()
    msg = await read_tpkt(reader)
    pdu = msg[5] & 0xF0
    assert pdu == 0xD0, f"Atteso CC (0xD0), ricevuto 0x{pdu:02X}"
    print("✓ COTP CR → CC")

    # 2. Setup Communication
    writer.write(build_setup()); await writer.drain()
    msg = await read_tpkt(reader)
    assert msg[7] == 0x32 and msg[8] == 0x03, \
        f"Atteso S7 AckData (proto=0x32, ROSCTR=0x03), ricevuto {msg[7:10].hex()}"
    print("✓ S7 Setup Communication → AckData")

    # 3. SZL queries: verifichiamo che i marker siano presenti
    targets = {
        0x0011: ["6ES7 214-1HG40-0XB0"],
        0x001C: ["S7-1200", "Siemens"],
        0x0037: [],
        0x0013: [],
        0x0111: ["6ES7 214-1HG40-0XB0"],
        0x0131: [],
        0x0132: [],
        0x0424: [],
    }
    for szl_id, expected_markers in targets.items():
        writer.write(build_szl_request(szl_id, pdu_ref=szl_id, seq_num=szl_id & 0xFF))
        await writer.drain()
        msg = await read_tpkt(reader)
        strings = hex_dump_strings(msg)
        ok = all(any(m in s for s in strings) for m in expected_markers)
        marker_str = ", ".join(expected_markers) if expected_markers else "(nessun marker richiesto)"
        result = "✓" if ok else "✗"
        print(f"{result} SZL 0x{szl_id:04X} → strings: {strings[:3]}  [cerco: {marker_str}]")
        if not ok:
            return False

    writer.close()
    await writer.wait_closed()
    print("✓ Test S7 completato")
    return True


# ─── Modbus ────────────────────────────────────────────────────────────────
async def test_modbus(host: str, port: int):
    print(f"\n══ TEST Modbus su {host}:{port} ══")
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except (ConnectionRefusedError, OSError):
        print("✗ Modbus non in ascolto (skip)")
        return False

    # FC 0x03: Read Holding Registers (10 reg da indirizzo 0)
    pdu = bytes([0x03]) + struct.pack(">HH", 0, 10)
    frame = struct.pack(">HHH", 0x0001, 0x0000, 1 + len(pdu)) + b"\x01" + pdu
    writer.write(frame); await writer.drain()
    hdr = await reader.readexactly(7)
    length = struct.unpack(">H", hdr[4:6])[0]
    body = await reader.readexactly(length - 1)
    assert body[0] == 0x03, f"Atteso FC 0x03, ricevuto 0x{body[0]:02X}"
    byte_count = body[1]
    assert byte_count == 20, f"Atteso 20 byte di dati, ricevuti {byte_count}"
    print(f"✓ Modbus FC 0x03: 10 registri restituiti ({byte_count} byte)")

    # FC 0x2B: Read Device Identification
    pdu = bytes([0x2B, 0x0E, 0x01, 0x00])
    frame = struct.pack(">HHH", 0x0002, 0x0000, 1 + len(pdu)) + b"\x01" + pdu
    writer.write(frame); await writer.drain()
    hdr = await reader.readexactly(7)
    length = struct.unpack(">H", hdr[4:6])[0]
    body = await reader.readexactly(length - 1)
    strings = hex_dump_strings(body)
    print(f"✓ Modbus FC 0x2B: strings = {strings}")
    expected = ["Siemens", "S7-1200", "4.6.0"]
    ok = all(any(m in s for s in strings) for m in expected)
    assert ok, f"Manca uno dei marker {expected}"
    print(f"✓ Tutti i marker {expected} presenti")

    writer.close()
    await writer.wait_closed()
    print("✓ Test Modbus completato")
    return True


async def main():
    host        = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    s7_port     = int(sys.argv[2]) if len(sys.argv) > 2 else 102
    modbus_port = int(sys.argv[3]) if len(sys.argv) > 3 else 502

    s7_ok = await test_s7(host, s7_port)
    mb_ok = await test_modbus(host, modbus_port)

    print()
    print("═" * 50)
    print(f"  S7      : {'PASS' if s7_ok else 'FAIL'}")
    print(f"  Modbus  : {'PASS' if mb_ok else 'FAIL/SKIP'}")
    print(f"  PROFINET: skip (richiede raw socket / scanner DCP)")
    print("═" * 50)


if __name__ == "__main__":
    asyncio.run(main())