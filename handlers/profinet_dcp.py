# ─────────────────────────────────────────────────────────────────────────────
# handlers/profinet_dcp.py
# PROFINET DCP — Discovery and Configuration Protocol (raw Layer 2).
#
# DCP è un protocollo Layer-2 (sopra Ethernet, EtherType 0x8892) che
# scanner ICS come Tenable usano per scoprire device PROFINET senza IP.
# Risponde a Identify Request con:
#   • NameOfStation       (0x02 0x02)
#   • Device ID           (0x02 0x01) - vendor + device class
#   • Device Role         (0x02 0x03)
#   • IP Parameters       (0x01 0x01)
#
# Servono privilegi raw socket: CAP_NET_RAW o root.
#
# NOTA: AF_PACKET esiste solo su Linux. Su Windows/Mac il modulo va in noop.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import os
import socket
import struct
import logging
import threading
from typing import Optional

from identity import PLCIdentity

# AF_PACKET è disponibile solo su Linux. Su Windows/macOS il modulo si
# auto-disabilita: la funzione run() torna subito senza errori.
HAS_AF_PACKET = hasattr(socket, "AF_PACKET")

log = logging.getLogger("honeypot.dcp")

PROFINET_ETHERTYPE = 0x8892


# ─── Auto-detection dell'interfaccia ─────────────────────────────────────────
def auto_iface() -> str:
    """
    Trova l'interfaccia con default route. Fallback a eth0/wlan0.
    """
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.strip().split()
                if p[1] == "00000000":     # destination 0.0.0.0 = default route
                    return p[0]
    except Exception:
        pass
    for candidate in ("eth0", "wlan0", "ens18", "ens19", "ens20"):
        if os.path.exists(f"/sys/class/net/{candidate}"):
            return candidate
    return "eth0"


def get_iface_mac(iface: str) -> bytes:
    """Legge il MAC dell'interfaccia da /sys/class/net."""
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac_str = f.read().strip()
        return bytes.fromhex(mac_str.replace(":", ""))
    except Exception:
        log.warning(f"Impossibile leggere MAC di {iface}, uso default")
        return bytes.fromhex("020000000001")


# ─── Helpers di costruzione blocchi DCP ──────────────────────────────────────
def _block(option: int, suboption: int, data: bytes) -> bytes:
    """
    Costruisce un blocco DCP. Header 4 byte + dati. Padding a multipli di 2.

    Layout: option(1) suboption(1) blocklength(2 BE) [BlockInfo(2) Data...]
    Il padding mantiene il successivo blocco allineato a 2 byte.
    """
    # NOTA: per Identify Response i blocchi includono il "BlockInfo" (2 byte)
    # in testa al campo data; lo lasciamo a zero (è la convenzione standard).
    block_info = b"\x00\x00"
    payload = block_info + data
    header = bytes([option, suboption]) + struct.pack(">H", len(payload))
    block = header + payload
    if len(block) % 2:
        block += b"\x00"
    return block


def build_identify_response(req_src_mac: bytes, our_mac: bytes,
                            xid: bytes, frame_id: int,
                            identity: PLCIdentity) -> bytes:
    """
    Costruisce un frame Ethernet completo con DCP Identify Response.
    """
    our_ip      = socket.inet_aton(identity.advertised_ip)
    our_mask    = socket.inet_aton(identity.advertised_netmask)
    our_gateway = socket.inet_aton(identity.advertised_gateway)

    blocks = (
        _block(0x02, 0x02, identity.station_name) +    # NameOfStation
        _block(0x02, 0x01, identity.device_id) +       # DeviceID (vendor+class)
        _block(0x02, 0x03, identity.device_role) +     # DeviceRole
        _block(0x01, 0x01, our_ip + our_mask + our_gateway)   # IPParameter
    )

    # DCP header (10 byte):
    #   FrameID(2) ServiceID(1) ServiceType(1) Xid(4) Reserved(2) DCPDataLen(2)
    # ServiceID=0x05 (Identify), ServiceType=0x01 (Response)
    dcp_header = (
        struct.pack(">H", frame_id) +
        bytes([0x05, 0x01]) +
        xid +
        struct.pack(">HH", 0, len(blocks))
    )
    dcp_pdu = dcp_header + blocks

    # Padding minimo Ethernet: il frame DEVE essere ≥ 60 byte (escluso CRC).
    # 14 (eth header) + DCP. Se troppo corto, padding a zero.
    eth_header = req_src_mac + our_mac + struct.pack(">H", PROFINET_ETHERTYPE)
    full = eth_header + dcp_pdu
    if len(full) < 60:
        full += b"\x00" * (60 - len(full))
    return full


# ─── Listener loop ───────────────────────────────────────────────────────────
def run(identity: PLCIdentity, stop_event: Optional[threading.Event] = None):
    """
    Loop bloccante che ascolta DCP Identify Request e risponde.
    Da chiamare in un thread separato.
    """
    if not HAS_AF_PACKET:
        log.warning("PROFINET DCP non disponibile su questa piattaforma "
                    "(AF_PACKET richiede Linux). DCP disabilitato.")
        return
    iface = identity.dcp_iface or auto_iface()

    if identity.advertised_mac:
        our_mac = bytes.fromhex(identity.advertised_mac.replace(":", ""))
    else:
        our_mac = get_iface_mac(iface)

    log.info(f"PROFINET DCP attivo su {iface} (MAC {our_mac.hex(':')})")
    log.info(f"  Annuncio: name='{identity.station_name.decode()}' "
             f"IP={identity.advertised_ip}")

    try:
        sk = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                        socket.htons(PROFINET_ETHERTYPE)) #socket.AF_PACKET è Linux-only
        sk.bind((iface, 0))
        sk.settimeout(1.0)   # per consentire stop pulito
    except PermissionError:
        log.error("DCP: serve root o CAP_NET_RAW. Disabilita enable_dcp "
                  "in identity.py se non puoi alzare i privilegi.")
        return
    except OSError as e:
        log.error(f"DCP: impossibile aprire raw socket su {iface}: {e}")
        return

    while stop_event is None or not stop_event.is_set():
        try:
            frame, _ = sk.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception as e:
            log.error(f"DCP recv: {e}")
            continue

        try:
            _process_frame(sk, frame, our_mac, identity)
        except Exception as e:
            log.exception(f"DCP processing: {e}")


def _process_frame(sk: socket.socket, frame: bytes,
                   our_mac: bytes, identity: PLCIdentity):
    """Parsa un frame DCP entrante e risponde se è una Identify Request."""
    if len(frame) < 22:
        return

    src_mac = frame[6:12]
    if src_mac == our_mac:
        return    # ignora i nostri stessi frame

    # Skip eventuale tag VLAN (0x8100)
    et_offset = 12
    if struct.unpack(">H", frame[12:14])[0] == 0x8100:
        et_offset = 16

    if struct.unpack(">H", frame[et_offset:et_offset + 2])[0] != PROFINET_ETHERTYPE:
        return

    # PROFINET frame
    pn_start = et_offset + 2
    if len(frame) < pn_start + 10:
        return

    frame_id     = struct.unpack(">H", frame[pn_start:pn_start + 2])[0]
    service_id   = frame[pn_start + 2]
    service_type = frame[pn_start + 3]
    xid          = frame[pn_start + 4:pn_start + 8]

    # Identify Request: ServiceID=0x05, ServiceType=0x00
    if service_id == 0x05 and service_type == 0x00:
        log.info(f"DCP Identify Request da {src_mac.hex(':')} (xid={xid.hex()})")
        response = build_identify_response(
            src_mac, our_mac, xid, frame_id, identity
        )
        sk.send(response)
        log.info("DCP Identify Response inviato")