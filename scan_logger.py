# ─────────────────────────────────────────────────────────────────────────────
# scan_logger.py
# Telemetria persistente delle scansioni ricevute dal honeypot.
#
# Backend principale: Redis Streams (XADD su honeypot:scans).
# Backend di fallback: file JSONL (se Redis non disponibile o fallisce).
#
# Mantiene aggregati vivi per query rapide (oltre allo stream):
#   • honeypot:peer:{ip}                  HASH  first_seen, last_seen, n_events
#   • honeypot:peer:{ip}:strings          SET   stringhe identificative del client
#   • honeypot:peer:{ip}:functions        SET   function code S7+/S7 visti
#   • honeypot:peers_seen                 ZSET  IP indicizzati per last_seen
#
# Filosofia:
#   • Best-effort: errori sul backend non devono mai bloccare il honeypot
#   • Async-aware: due API parallele, una asyncio (S7/Modbus), una sync (DCP)
#   • Schema-light: campi flat, niente nesting (semplicità su Redis Streams)
#   • Peer info recuperata via ContextVar per asyncio, ContextManager per thread
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import asyncio
import contextvars
import json
import logging
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

log = logging.getLogger("honeypot.scan_logger")


# ─── Stato globale di configurazione ─────────────────────────────────────────
_REDIS_URL : str | None = None
_FALLBACK_FILE : Path | None = None
_STREAM_KEY = "honeypot:scans"
_STREAM_MAXLEN = 100_000

_async_redis = None       # redis.asyncio.Redis  (lazy init)
_sync_redis  = None       # redis.Redis           (lazy init)
_file_lock = threading.Lock()


# ─── Peer context (asyncio + thread DCP) ─────────────────────────────────────
# In asyncio, ogni Task eredita una copia del Context. Quindi se un handler
# S7Connection imposta il peer all'inizio di serve(), tutti i task figli
# (chiamate a s7classic.handle, s7plus.handle, ecc.) lo vedono automaticamente.
_peer_ctx: contextvars.ContextVar[tuple[str, int] | None] = \
    contextvars.ContextVar("honeypot_peer", default=None)

# Per il thread DCP usiamo un thread-local equivalente.
_peer_local = threading.local()


def set_peer(ip: str, port: int) -> contextvars.Token:
    """
    Imposta il peer corrente nel ContextVar (per asyncio).
    Restituisce un token da passare a reset_peer() per ripristinare.
    """
    return _peer_ctx.set((ip, port))


def reset_peer(token: contextvars.Token) -> None:
    """Ripristina il valore precedente del ContextVar."""
    _peer_ctx.reset(token)


@contextmanager
def peer_context(ip: str, port: int):
    """
    Context manager unificato: usa ContextVar in asyncio,
    threading.local altrimenti. I handler chiamano log_event(...)
    senza dover passare peer esplicitamente.
    """
    try:
        # Se siamo in asyncio, usa ContextVar
        asyncio.get_running_loop()
        token = _peer_ctx.set((ip, port))
        try:
            yield
        finally:
            _peer_ctx.reset(token)
    except RuntimeError:
        # Nessun event loop attivo → siamo in thread (DCP)
        prev = getattr(_peer_local, "peer", None)
        _peer_local.peer = (ip, port)
        try:
            yield
        finally:
            _peer_local.peer = prev


def _current_peer() -> tuple[str | None, int | None]:
    """
    Restituisce (ip, port) del peer corrente, dovunque siamo in esecuzione.
    Cerca prima nel ContextVar (asyncio), poi nel thread-local (DCP).
    Restituisce (None, None) se nessun peer impostato.
    """
    p = _peer_ctx.get()
    if p is not None:
        return p
    p = getattr(_peer_local, "peer", None)
    if p is not None:
        return p
    return (None, None)


# ─── Configurazione iniziale ─────────────────────────────────────────────────
def configure(redis_url: str | None = None,
              fallback_file: str | Path | None = "scan_log.jsonl",
              stream_maxlen: int = 100_000) -> None:
    """
    Da chiamare una volta all'avvio del server.

    Args:
        redis_url: es. "redis://localhost:6379/0". None disabilita Redis.
        fallback_file: path del file JSONL usato quando Redis non risponde.
        stream_maxlen: cap del Redis Stream (auto-trim alle ultime N entries).
    """
    global _REDIS_URL, _FALLBACK_FILE, _STREAM_MAXLEN
    _REDIS_URL = redis_url
    _FALLBACK_FILE = Path(fallback_file) if fallback_file else None
    _STREAM_MAXLEN = stream_maxlen

    if _FALLBACK_FILE:
        _FALLBACK_FILE.parent.mkdir(parents=True, exist_ok=True)

    log.info(f"scan_logger configurato: redis={_REDIS_URL or 'OFF'}  "
             f"fallback={_FALLBACK_FILE or 'OFF'}  stream_maxlen={_STREAM_MAXLEN}")


# ─── Lazy init dei client Redis ──────────────────────────────────────────────
async def _get_async_redis():
    global _async_redis
    if _async_redis is None and _REDIS_URL:
        try:
            from redis.asyncio import Redis
            _async_redis = Redis.from_url(_REDIS_URL, decode_responses=True)
            await _async_redis.ping()
            log.debug("Redis async client inizializzato")
        except Exception as e:
            log.warning(f"Redis async non disponibile: {e}. Fallback su file.")
            _async_redis = False  # marker per non riprovare ad ogni evento
    return _async_redis if _async_redis is not False else None


def _get_sync_redis():
    global _sync_redis
    if _sync_redis is None and _REDIS_URL:
        try:
            import redis
            _sync_redis = redis.Redis.from_url(_REDIS_URL, decode_responses=True)
            _sync_redis.ping()
            log.debug("Redis sync client inizializzato")
        except Exception as e:
            log.warning(f"Redis sync non disponibile: {e}. Fallback su file.")
            _sync_redis = False
    return _sync_redis if _sync_redis is not False else None


# ─── Costruzione e fallback ──────────────────────────────────────────────────
def _build_event(layer: str, event_type: str,
                 peer_ip: str | None, peer_port: int | None,
                 details: dict[str, Any] | None) -> dict[str, str]:
    """
    Costruisce un evento normalizzato.
    Redis Streams accetta solo campi flat (key→str). Serializziamo `details`
    come JSON per non perdere struttura ma restare compatibili.
    """
    return {
        "ts"        : f"{time.time():.3f}",
        "layer"     : layer,
        "event"     : event_type,
        "peer_ip"   : peer_ip or "",
        "peer_port" : str(peer_port) if peer_port is not None else "",
        "details"   : json.dumps(details or {}, ensure_ascii=False, default=str),
    }


def _write_fallback(event: dict[str, str]) -> None:
    """Scrive l'evento sul file .jsonl. Best-effort."""
    if not _FALLBACK_FILE:
        return
    try:
        with _file_lock:
            with _FALLBACK_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as e:
        log.debug(f"fallback file write failed: {e}")


def _build_pipeline_ops(event: dict[str, str], details: dict[str, Any] | None):
    """
    Costruisce la lista di operazioni Redis da eseguire per un evento.
    Restituisce una lista di tuple (method_name, args, kwargs).
    Riusata sia da async che da sync, per evitare duplicazione.
    """
    peer_ip = event["peer_ip"]
    ts = event["ts"]
    ops = [
        ("xadd", (_STREAM_KEY, event), {"maxlen": _STREAM_MAXLEN, "approximate": True}),
    ]
    if peer_ip:
        peer_key = f"honeypot:peer:{peer_ip}"
        ops.extend([
            ("hsetnx",  (peer_key, "first_seen", ts), {}),
            ("hset",    (peer_key, "last_seen",  ts), {}),
            ("hincrby", (peer_key, "n_events", 1),    {}),
            ("zadd",    ("honeypot:peers_seen", {peer_ip: float(ts)}), {}),
        ])
        if details:
            fc = details.get("function")
            if fc:
                ops.append(("sadd", (f"{peer_key}:functions", fc), {}))
            for s in (details.get("client_strings") or []):
                ops.append(("sadd", (f"{peer_key}:strings", s), {}))
    return ops


# ─── API asincrona (per asyncio: S7, S7+, Modbus) ────────────────────────────
async def log_event_async(*, layer: str, event_type: str,
                          details: dict[str, Any] | None = None,
                          peer_ip: str | None = None,
                          peer_port: int | None = None) -> None:
    """
    Logga un evento dal contesto asyncio.
    Se peer_ip/peer_port non sono passati, vengono presi dal ContextVar.
    """
    if peer_ip is None or peer_port is None:
        ctx_ip, ctx_port = _current_peer()
        peer_ip = peer_ip or ctx_ip
        peer_port = peer_port if peer_port is not None else ctx_port

    event = _build_event(layer, event_type, peer_ip, peer_port, details)
    rdb = await _get_async_redis()

    if rdb is None:
        _write_fallback(event)
        return

    try:
        async with rdb.pipeline(transaction=False) as pipe:
            for method, args, kwargs in _build_pipeline_ops(event, details):
                getattr(pipe, method)(*args, **kwargs)
            await pipe.execute()
    except Exception as e:
        log.debug(f"redis async write failed: {e}, fallback su file")
        _write_fallback(event)


# ─── API sincrona (per il thread DCP) ────────────────────────────────────────
def log_event_sync(*, layer: str, event_type: str,
                   details: dict[str, Any] | None = None,
                   peer_ip: str | None = None,
                   peer_port: int | None = None) -> None:
    """
    Logga un evento dal contesto thread.
    Se peer_ip/peer_port non sono passati, vengono presi dal thread-local.
    """
    if peer_ip is None or peer_port is None:
        ctx_ip, ctx_port = _current_peer()
        peer_ip = peer_ip or ctx_ip
        peer_port = peer_port if peer_port is not None else ctx_port

    event = _build_event(layer, event_type, peer_ip, peer_port, details)
    rdb = _get_sync_redis()

    if rdb is None:
        _write_fallback(event)
        return

    try:
        pipe = rdb.pipeline(transaction=False)
        for method, args, kwargs in _build_pipeline_ops(event, details):
            getattr(pipe, method)(*args, **kwargs)
        pipe.execute()
    except Exception as e:
        log.debug(f"redis sync write failed: {e}, fallback su file")
        _write_fallback(event)


# ─── Smart dispatcher ────────────────────────────────────────────────────────
def log_event(**kwargs) -> None:
    """
    Convenience: rileva il contesto di esecuzione e dispatcha sul giusto
    backend. Se siamo in asyncio, schedula la coroutine; se in thread, sync.
    """
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(log_event_async(**kwargs))
    except RuntimeError:
        log_event_sync(**kwargs)