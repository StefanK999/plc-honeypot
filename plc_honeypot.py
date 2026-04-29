#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# plc_honeypot.py
# Server principale del honeypot. Avvia 3 servizi in parallelo:
#
#   • S7comm + S7+   sulla porta 102  (asyncio)
#   • Modbus TCP     sulla porta 502  (asyncio)
#   • PROFINET DCP   raw L2 (thread separato, raw socket = bloccante)
#
# Compatibile anche con Raspberry Pi 4 e superiori (asyncio è leggero, niente librerie C).
# Avvio:    sudo python3 plc_honeypot.py
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import asyncio
import logging
import struct
import sys
import threading
from pathlib import Path
import random
import scan_logger

# Path locale per import handlers/identity senza pacchetto installato
HERE = Path(__file__).parent.resolve()
sys.path.insert(0, str(HERE))

from identity import DEFAULT_IDENTITY
from handlers import cotp as cotp_h
from handlers import s7comm, s7comm_plus, modbus, profinet_dcp


# ─── Logging setup ───────────────────────────────────────────────────────────
def setup_logging(level: str = "INFO"):
    logging.basicConfig(
        format='%(asctime)s.%(msecs)03d  %(name)-22s  %(levelname)-7s %(message)s',
        datefmt='%H:%M:%S',
        level=getattr(logging, level.upper(), logging.INFO),
    )

log = logging.getLogger("honeypot.server")


# ─── Helpers TPKT ────────────────────────────────────────────────────────────
def wrap_tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 0x03, 0x00, 4 + len(payload)) + payload


# ─── Mini-parser COTP per i campi che ci servono qui ─────────────────────────
class _CotpView:
    """View read-only su un payload COTP, abbastanza per il dispatcher."""
    __slots__ = ('pdu_type', 'src_ref', 'parameters', 'payload')

    def __init__(self, data: bytes):
        self.pdu_type   = 0
        self.src_ref    = 0
        self.parameters = []     # lista di (code, length, value)
        self.payload    = b""

        if len(data) < 2:
            return
        li = data[0]
        self.pdu_type = data[1] & 0xF0

        if self.pdu_type in (0xE0, 0xD0, 0x80) and len(data) >= 7:
            # CR/CC/DR: dst_ref(2) src_ref(2) class(1) [params]
            self.src_ref = struct.unpack(">H", data[4:6])[0]
            offset = 7
            end = 1 + li
            while offset + 2 <= end and offset + 2 <= len(data):
                code = data[offset]
                plen = data[offset + 1]
                val  = data[offset + 2:offset + 2 + plen]
                self.parameters.append((code, plen, val))
                offset += 2 + plen
        elif self.pdu_type == 0xF0:
            # DT: 2 byte di header (LI=02) + EOT byte
            self.payload = data[1 + li:]


# ─── Connection handler S7 ───────────────────────────────────────────────────
class S7Connection:
    """Singola connessione TCP/102, mantiene stato COTP."""

    def __init__(self, reader, writer, identity):
        self.reader   = reader
        self.writer   = writer
        self.identity = identity
        self.peer     = writer.get_extra_info('peername')
        self.cotp_open = False

    async def serve(self):
        log.info(f"╭─ [S7] Connessione da {self.peer[0]}:{self.peer[1]}")

        # Peer nel ContextVar di scan_logger
        with scan_logger.peer_context(self.peer[0], self.peer[1]):
            await scan_logger.log_event_async(
                layer="tcp", event_type="connection_open",
                details={"port": "s7"},
            )
            try:
                while True:
                    hdr = await self._read_exact(4)
                    if hdr is None:
                        break
                    if hdr[0] != 0x03:
                        log.warning(f"  byte 0 non TPKT (0x{hdr[0]:02X}), chiudo")
                        break

                    total_len = struct.unpack(">H", hdr[2:4])[0]
                    if total_len < 4 or total_len > 65535:
                        break
                    rest = await self._read_exact(total_len - 4)
                    if rest is None:
                        break

                    full_msg = bytes(hdr) + rest
                    await self._handle_tpkt(full_msg)

            except asyncio.CancelledError:
                pass
            except Exception as e:
                log.exception(f"  errore: {e}")
            finally:
                await scan_logger.log_event_async(
                    layer="tcp", event_type="connection_close",
                    details={"port": "s7"},
                )
                self.writer.close()
                try:
                    await self.writer.wait_closed()
                except Exception:
                    pass
                log.info(f"╰─ [S7] Chiuso {self.peer[0]}:{self.peer[1]}")

    async def _read_exact(self, n: int):
        try:
            return await self.reader.readexactly(n)
        except asyncio.IncompleteReadError:
            return None

    async def _handle_tpkt(self, msg: bytes):
        if len(msg) < 5:
            return
        cotp_data = msg[4:]
        view = _CotpView(cotp_data)

        # ── Connection Request → Connection Confirm ──────────────────────────
        if view.pdu_type == 0xE0:
            # ── Strumentazione diagnostica: dumpa TSAP raw ───────────────────
            tsap_calling_raw = None
            tsap_called_raw  = None
            tpdu_size_raw    = None
            for code, plen, val in view.parameters:
                if   code == 0xC1: tsap_calling_raw = val
                elif code == 0xC2: tsap_called_raw  = val
                elif code == 0xC0: tpdu_size_raw    = val

            calling_hex = tsap_calling_raw.hex(':') if tsap_calling_raw else "?"
            called_hex  = tsap_called_raw.hex(':')  if tsap_called_raw  else "?"

            # Decodifica "umana" del CalledTSAP per leggibilità nel log:
            # se è 2 byte numerici (es. 02:00) lo mostriamo così;
            # se è ASCII stampabile (es. SIMATIC-ROOT-ES) lo decodifichiamo.
            called_human = called_hex
            if tsap_called_raw:
                try:
                    s = tsap_called_raw.decode('ascii')
                    if all(32 <= ord(c) < 127 for c in s):
                        called_human = f'"{s}"'
                except UnicodeDecodeError:
                    pass

            log.info(f"  [S7] CR  calling={calling_hex}  called={called_human}  "
                     f"(called_raw={called_hex})")

            # Telemetria persistente
            await scan_logger.log_event_async(
                layer="s7",
                event_type="cotp_connection_request",
                details={
                    "tsap_calling_raw" : calling_hex,
                    "tsap_called_raw"  : called_hex,
                    "tsap_called_human": called_human,
                    "tpdu_size_raw"    : tpdu_size_raw.hex() if tpdu_size_raw else None,
                    "src_ref"          : f"0x{view.src_ref:04X}",
                },
            )

            # Comportamento invariato: rispondi con CC a tutto
            cc = cotp_h.build_cc_from_raw(cotp_data, our_src_ref=0x000C)
            await self._send(wrap_tpkt(cc))
            self.cotp_open = True
            return

        if view.pdu_type == 0x80:
            log.info("  [S7] COTP Disconnect Request")
            return

        # Data Transfer
        if view.pdu_type == 0xF0 and view.payload:
            await self._handle_application(view.payload)
            return

    @staticmethod
    def _called_tsap(view: _CotpView) -> str:
        for code, _, val in view.parameters:
            if code == 0xC2:
                try:
                    return val.decode('ascii')
                except UnicodeDecodeError:
                    return val.hex()
        return "?"

    async def _handle_application(self, payload: bytes):
        first = payload[0]
        response = None

        if first == 0x32 and self.identity.enable_s7classic:
            response = s7comm.handle(payload, self.identity)
        elif first == 0x72 and self.identity.enable_s7plus:
            response = s7comm_plus.handle(payload, self.identity)
        else:
            log.debug(f"  [S7] payload byte0=0x{first:02X} non riconosciuto")
            return

        if response is None:
            return

        if self.identity.add_jitter_ms > 0:
            jitter = random.uniform(
                self.identity.add_jitter_ms * 0.3,
                self.identity.add_jitter_ms * 3.0,
            )
            await asyncio.sleep(jitter / 1000.0)

        cotp_msg = cotp_h.build_dt(response, eot=True)
        await self._send(wrap_tpkt(cotp_msg))

    async def _send(self, data: bytes):
        self.writer.write(data)
        await self.writer.drain()


# ─── Connection handler Modbus ───────────────────────────────────────────────
class ModbusConnection:
    """Connessione TCP/502 per Modbus."""

    def __init__(self, reader, writer, identity):
        self.reader   = reader
        self.writer   = writer
        self.identity = identity
        self.peer     = writer.get_extra_info('peername')

    async def serve(self):
        log.info(f"╭─ [Modbus] Connessione da {self.peer[0]}:{self.peer[1]}")

        with scan_logger.peer_context(self.peer[0], self.peer[1]):
            await scan_logger.log_event_async(
                layer="tcp", event_type="connection_open",
                details={"port": "modbus"},
            )
            try:
                while True:
                    hdr = await self.reader.readexactly(7)
                    length = struct.unpack(">H", hdr[4:6])[0]
                    if length < 1 or length > 256:
                        break
                    pdu = await self.reader.readexactly(length - 1)
                    frame = hdr + pdu

                    response = modbus.handle(frame, self.identity)
                    if response:
                        self.writer.write(response)
                        await self.writer.drain()

            except asyncio.IncompleteReadError:
                pass
            except Exception as e:
                log.exception(f"  errore: {e}")
            finally:
                await scan_logger.log_event_async(
                    layer="tcp", event_type="connection_close",
                    details={"port": "modbus"},
                )
                self.writer.close()
                try:
                    await self.writer.wait_closed()
                except Exception:
                    pass
                log.info(f"╰─ [Modbus] Chiuso {self.peer[0]}:{self.peer[1]}")


# ─── Server bootstrap (asyncio main) ─────────────────────────────────────────
async def main_async(identity):
    servers = []

    if identity.enable_s7classic or identity.enable_s7plus:
        s7 = await asyncio.start_server(
            lambda r, w: S7Connection(r, w, identity).serve(),
            host=identity.listen_host, port=identity.s7_port,
        )
        servers.append(s7)
        log.info(f"S7  listener attivo su {identity.listen_host}:{identity.s7_port}")

    if identity.enable_modbus:
        mb = await asyncio.start_server(
            lambda r, w: ModbusConnection(r, w, identity).serve(),
            host=identity.listen_host, port=identity.modbus_port,
        )
        servers.append(mb)
        log.info(f"Modbus listener attivo su {identity.listen_host}:{identity.modbus_port}")

    if not servers:
        log.error("Nessun servizio TCP abilitato in identity.py, esco")
        return

    try:
        await asyncio.gather(*[s.serve_forever() for s in servers])
    except asyncio.CancelledError:
        pass
    finally:
        for s in servers:
            s.close()


# ─── Main entry ──────────────────────────────────────────────────────────────
def main():
    setup_logging(DEFAULT_IDENTITY.log_level)

    log.info("─" * 70)
    log.info("  PLC Honeypot — Siemens S7-1200")
    log.info(f"    Article : {DEFAULT_IDENTITY.article_number.decode().strip()}")
    log.info(f"    Module  : {DEFAULT_IDENTITY.module_name.decode().strip()}")
    log.info(f"    Firmware: {DEFAULT_IDENTITY.firmware.decode().strip()}")
    log.info(f"    Serial  : {DEFAULT_IDENTITY.serial_number.decode().strip()}")
    log.info(f"    Layers  : "
             f"s7comm={'ON' if DEFAULT_IDENTITY.enable_s7classic else 'OFF'}  "
             f"S7+={'ON' if DEFAULT_IDENTITY.enable_s7plus else 'OFF'}  "
             f"Modbus={'ON' if DEFAULT_IDENTITY.enable_modbus else 'OFF'}  "
             f"DCP={'ON' if DEFAULT_IDENTITY.enable_dcp else 'OFF'}")
    log.info("─" * 70)

    # Configurazione scan_logger
    scan_logger.configure(
        redis_url=DEFAULT_IDENTITY.redis_url or None,
        fallback_file=DEFAULT_IDENTITY.scan_log_fallback_file,
        stream_maxlen=DEFAULT_IDENTITY.scan_log_stream_maxlen,
    )

    # PROFINET DCP gira in thread separato (raw socket bloccante)
    dcp_stop = threading.Event()
    dcp_thread = None
    if DEFAULT_IDENTITY.enable_dcp:
        dcp_thread = threading.Thread(
            target=profinet_dcp.run,
            args=(DEFAULT_IDENTITY, dcp_stop),
            name="DCP-listener",
            daemon=True,
        )
        dcp_thread.start()

    try:
        asyncio.run(main_async(DEFAULT_IDENTITY))
    except KeyboardInterrupt:
        log.info("Ctrl+C ricevuto, fermo il honeypot")
    except PermissionError:
        log.error(f"Impossibile bindarsi alle porte privilegiate. "
                  f"Avvia con sudo, oppure imposta porte > 1024 in identity.py")
    finally:
        dcp_stop.set()
        if dcp_thread:
            dcp_thread.join(timeout=2)


if __name__ == "__main__":
    main()