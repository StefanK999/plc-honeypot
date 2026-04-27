# ─────────────────────────────────────────────────────────────────────────────
# identity.py
# Identità del PLC virtuale.
#
# Una comoda interfaccia per cambiare i valori chiave per impersonare PLC diversi (S7-1200/1500, FW diversi).
# Tutti i campi sono read da Tenable durante il fingerprinting.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path


# ─── Mini parser .env (zero dipendenze) ──────────────────────────────────────
def _load_dotenv(path: Path) -> None:
    """
    Carica un file .env nel processo. NON sovrascrive variabili già
    presenti in os.environ (così systemd / docker / shell vincono sul .env).
    Formato supportato: KEY=value, # commenti, righe vuote, valori quotati.
    """
    if not path.is_file():
        return
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        value = value.strip()
        # Rimuove eventuali quote esterne (singole o doppie)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        # Le variabili già nell'env hanno la priorità
        os.environ.setdefault(key, value)


# Carica .env dalla cartella del progetto, una volta sola all'import
_load_dotenv(Path(__file__).parent / ".env")


# ─── Helpers di lettura tipizzata ────────────────────────────────────────────
def _env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _env_bytes(key: str, default: bytes) -> bytes:
    """Per i campi che la dataclass aspetta come bytes (SZL records)."""
    val = os.environ.get(key)
    return val.encode('ascii') if val is not None else default


def _env_hex_bytes(key: str, default: bytes) -> bytes:
    """Per campi binari espressi come stringa esadecimale (es. '00 0E 20 20')."""
    val = os.environ.get(key)
    if val is None:
        return default
    return bytes.fromhex(val.replace(" ", "").replace(":", ""))


def _env_bool(key: str, default: bool) -> bool:
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() in ('1', 'true', 'yes', 'on')


def _env_int(key: str, default: int) -> int:
    val = os.environ.get(key)
    return int(val) if val is not None else default


# ─── Dataclass identità ──────────────────────────────────────────────────────
@dataclass
class PLCIdentity:
    # ── Identità "vetrina" S7 SZL ────────────────────────────────────────────
    article_number : bytes = _env_bytes("PLC_ARTICLE_NUMBER", b"6ES7 000-0XX00-0XX0 ")
    module_name    : bytes = _env_bytes("PLC_MODULE_NAME",    b"DEMO PLC honeypot   ")
    module_type    : bytes = _env_bytes("PLC_MODULE_TYPE",    b"DEMO-FAMILY")
    plant_id       : bytes = _env_bytes("PLC_PLANT_ID",       b"DEMO_PLANT")
    serial_number  : bytes = _env_bytes("PLC_SERIAL",         b"S X-XXXXXXXX")
    firmware       : bytes = _env_bytes("PLC_FIRMWARE",       b"V0.0.0")
    copyright_str  : bytes = _env_bytes("PLC_COPYRIGHT",      b"Honeypot demo build")
    vendor         : bytes = _env_bytes("PLC_VENDOR",         b"DEMO")

    hw_version_bytes : bytes = _env_hex_bytes("PLC_HW_VERSION_BYTES", b"\x00\x00\x00\x00")
    fw_version_bytes : bytes = _env_hex_bytes("PLC_FW_VERSION_BYTES", b"\x00\x00\x00\x00")

    # ── PROFINET DCP identity ────────────────────────────────────────────────
    station_name : bytes = _env_bytes("DCP_STATION_NAME", b"demo-plc")
    device_id    : bytes = _env_hex_bytes("DCP_DEVICE_ID",   b"\x00\x00\x00\x00")
    device_role  : bytes = _env_hex_bytes("DCP_DEVICE_ROLE", b"\x00\x00")

    advertised_ip      : str = _env_str("DCP_ADVERTISED_IP",      "192.0.2.42")
    advertised_netmask : str = _env_str("DCP_ADVERTISED_NETMASK", "255.255.255.0")
    advertised_gateway : str = _env_str("DCP_ADVERTISED_GATEWAY", "192.0.2.1")
    advertised_mac     : str | None = _env_str("DCP_ADVERTISED_MAC", "") or None

    # ── Modbus identity (FC 0x2B) ────────────────────────────────────────────
    modbus_vendor  : bytes = _env_bytes("MODBUS_VENDOR",  b"DEMO")
    modbus_product : bytes = _env_bytes("MODBUS_PRODUCT", b"DEMO-PLC")
    modbus_version : bytes = _env_bytes("MODBUS_VERSION", b"0.0.0")

    # ── Network listeners ────────────────────────────────────────────────────
    listen_host : str = _env_str("LISTEN_HOST", "0.0.0.0")
    s7_port     : int = _env_int("S7_PORT",     102)
    modbus_port : int = _env_int("MODBUS_PORT", 502)
    dcp_iface   : str | None = _env_str("DCP_IFACE", "") or None

    # ── Comportamento ────────────────────────────────────────────────────────
    log_level     : str = _env_str("LOG_LEVEL", "INFO")
    add_jitter_ms : int = _env_int("JITTER_MS", 30)

    # ── Toggle layer ─────────────────────────────────────────────────────────
    enable_s7classic : bool = _env_bool("ENABLE_S7CLASSIC", True)
    enable_s7plus    : bool = _env_bool("ENABLE_S7PLUS",    True)
    enable_modbus    : bool = _env_bool("ENABLE_MODBUS",    True)
    enable_dcp       : bool = _env_bool("ENABLE_DCP",       True)


DEFAULT_IDENTITY = PLCIdentity()