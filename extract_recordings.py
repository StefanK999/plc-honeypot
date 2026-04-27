#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# extract_recordings.py
# Tool OFFLINE: estrae dal pcap i template di risposta del PLC reale e li
# salva in recorded/ per il replay del honeypot.
#
# Va eseguito UNA SOLA VOLTA, sul PC di sviluppo. Sul Pi 4 non serve.
# Richiede `dpkt` (pip install dpkt).
#
# Uso:    python3 extract_recordings.py path/a/file.pcapng
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import sys
import socket
from pathlib import Path

import dpkt

# Importa i parsers locali (nella sottocartella parsers/)
HERE = Path(__file__).parent.resolve()
sys.path.insert(0, str(HERE))

from parsers import tpkt, cotp, s7comm, s7comm_plus
from parsers.tcp_reassembler import TCPReassembler, FlowKey


# Default: PLC del pcap di esempio, IP di esempio.
DEFAULT_PCAP   = "YourPath/a/file.pcapng"
DEFAULT_PLC_IP = "192.168.1.100"
OUT_DIR        = HERE / "recorded"


def save_unique(name: str, data: bytes, registry: dict) -> bool:
    """Salva il blob solo se non già visto (oppure se più recente/diverso)."""
    if name in registry and registry[name] == data:
        return False
    registry[name] = data
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / f"{name}.bin").write_bytes(data)
    return True


def extract(pcap_path: str, plc_ip: str = DEFAULT_PLC_IP):
    print(f"📂 Apro {pcap_path}")
    print(f"🎯 Filtro PLC IP = {plc_ip}")

    reass = TCPReassembler()
    saved = {}
    s7_setup_resp_seen = False

    with open(pcap_path, 'rb') as f:
        if pcap_path.endswith('.pcapng'):
            reader = dpkt.pcapng.Reader(f)
        else:
            reader = dpkt.pcap.Reader(f)

        for ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip  = eth.data
                if not isinstance(ip, dpkt.ip.IP): continue
                tcp = ip.data
                if not isinstance(tcp, dpkt.tcp.TCP) or not tcp.data: continue

                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)

                # solo risposte del PLC (src == PLC IP)
                if src != plc_ip: continue
                if 102 not in (tcp.sport, tcp.dport): continue

                key = FlowKey(src, tcp.sport, dst, tcp.dport)
                for msg in reass.feed(key, bytes(tcp.data)):
                    t = tpkt.parse(msg)
                    if not t.valid: continue
                    c = cotp.parse(t.payload)

                    # COTP CC (template generico, raramente usato)
                    if c.pdu_type == 0xD0:
                        save_unique("cotp_cc_template", t.payload, saved)
                        continue

                    if not c.is_data() or not c.payload:
                        continue

                    # ── S7 classico (proto 0x32) ─────────────────────────────
                    if s7comm.looks_like_s7comm(c.payload):
                        f7 = s7comm.parse(c.payload)
                        if not f7.valid: continue

                        if f7.function_code == 0xF0 and not s7_setup_resp_seen:
                            save_unique("s7_setup_response", c.payload, saved)
                            s7_setup_resp_seen = True

                        if f7.szl_response:
                            sid = f7.szl_response.szl_id
                            save_unique(f"s7_szl_{sid:04X}_response",
                                        c.payload, saved)

                    # ── S7comm-Plus (proto 0x72) ─────────────────────────────
                    elif s7comm_plus.looks_like_s7plus(c.payload):
                        fp = s7comm_plus.parse(c.payload)
                        if not fp.valid or not fp.is_response: continue

                        # InitSession (cleartext)
                        if fp.opcode == 0x32 and fp.function_code == 0x04CA:
                            save_unique("s7plus_initsession_response",
                                        c.payload, saved)
                        elif fp.opcode == 0x32 and fp.function_code == 0x0542:
                            save_unique("s7plus_setvarsubstreamed_response",
                                        c.payload, saved)
                        elif fp.opcode == 0x20 and fp.function_code is not None:
                            save_unique(
                                f"s7plus_ip_{fp.function_code:04X}_response",
                                c.payload, saved
                            )

            except Exception:
                continue

    print(f"\n✓ Estratti {len(saved)} template in {OUT_DIR}")
    for name in sorted(saved):
        size = len(saved[name])
        print(f"   • {name}.bin  ({size} byte)")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        pcap = sys.argv[1]
    else:
        pcap = DEFAULT_PCAP
        if not Path(pcap).exists():
            print(f"⚠ Nessun pcap fornito e {pcap} non esiste.")
            print(f"  Uso: python3 extract_recordings.py [path/al/file.pcapng] [PLC_IP]")
            sys.exit(1)

    plc_ip = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PLC_IP
    extract(pcap, plc_ip)
