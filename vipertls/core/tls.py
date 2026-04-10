import ssl
import socket
import select
import time
import threading
from typing import Optional, Any

from ..fingerprints.ja3 import JA3Spec, parse_ja3
from ..fingerprints.presets import BrowserPreset

try:
    from OpenSSL.SSL import (
        Context as _PyOSSLContext,
        Connection as _PyOSSLConnection,
        TLS_METHOD as _TLS_METHOD,
        OP_NO_SSLv2 as _OP_NO_SSLv2,
        OP_NO_SSLv3 as _OP_NO_SSLv3,
        OP_NO_TLSv1 as _OP_NO_TLSv1,
        OP_NO_TLSv1_1 as _OP_NO_TLSv1_1,
        VERIFY_PEER as _VERIFY_PEER,
        VERIFY_FAIL_IF_NO_PEER_CERT as _VERIFY_FAIL_IF_NO_PEER_CERT,
        ZeroReturnError as _ZeroReturnError,
        SysCallError as _SysCallError,
    )
    from OpenSSL._util import ffi as _ossl_ffi, lib as _ossl_lib
    _PYOSSL_AVAILABLE = True
except Exception:
    _PYOSSL_AVAILABLE = False
    _PyOSSLContext = None
    _PyOSSLConnection = None
    _ossl_lib = None

_SESSION_CACHE: dict = {}
_SESSION_LOCK = threading.Lock()
_CONTEXT_CACHE: dict = {}
_CONTEXT_LOCK = threading.Lock()


class _ViperSSLSocket:
    def __init__(
        self,
        conn: Any,
        raw_sock: socket.socket,
        session_reused: bool = False,
        connect_ms: float = 0.0,
        handshake_ms: float = 0.0,
    ) -> None:
        self._conn = conn
        self._raw = raw_sock
        self._session_reused_flag = session_reused
        self.connect_ms = connect_ms
        self.handshake_ms = handshake_ms

    def sendall(self, data: bytes) -> None:
        self._conn.sendall(data)

    def recv(self, size: int) -> bytes:
        while True:
            try:
                data = self._conn.recv(size)
                return data if data is not None else b""
            except Exception as exc:
                exc_name = type(exc).__name__
                if exc_name == "WantReadError":
                    select.select([self._raw], [], [], 5.0)
                    continue
                if exc_name in ("ZeroReturnError", "SysCallError"):
                    return b""
                return b""

    def close(self) -> None:
        try:
            self._conn.shutdown()
        except Exception:
            pass
        try:
            self._raw.close()
        except Exception:
            pass

    def selected_alpn_protocol(self) -> Optional[str]:
        try:
            proto = self._conn.get_alpn_proto_negotiated()
            if proto:
                return proto.decode("utf-8")
        except Exception:
            pass
        return None

    @property
    def session_reused(self) -> bool:
        return self._session_reused_flag

    def cipher(self) -> Optional[tuple]:
        try:
            name = self._conn.get_cipher_name()
            version = self._conn.get_cipher_version()
            bits = self._conn.get_cipher_bits()
            if name:
                return (name, version or "", bits or 0)
        except Exception:
            pass
        return None

    def version(self) -> Optional[str]:
        try:
            return self._conn.get_protocol_version_name()
        except Exception:
            return None

    def getpeercert(self, binary_form: bool = False) -> Any:
        return None

    def fileno(self) -> int:
        try:
            return self._raw.fileno()
        except Exception:
            return -1

    def settimeout(self, timeout: Optional[float]) -> None:
        try:
            self._raw.settimeout(timeout)
        except Exception:
            pass


def _get_cached_session(key: Optional[tuple]) -> Any:
    if key is None:
        return None
    with _SESSION_LOCK:
        return _SESSION_CACHE.get(key)


def _store_session(key: Optional[tuple], session: Any) -> None:
    if key is None or session is None:
        return
    with _SESSION_LOCK:
        _SESSION_CACHE[key] = session


def _ja3_cache_key(ja3: Optional[JA3Spec]) -> tuple:
    if ja3 is None:
        return ("preset",)
    return (
        "ja3",
        ja3.tls_version,
        tuple(ja3.cipher_ids),
        tuple(ja3.extension_ids),
        tuple(ja3.curve_ids),
        tuple(ja3.point_formats),
    )


def _apply_tls13_ciphers(ctx_ptr: Any, ciphers: list) -> None:
    if not _ossl_lib or not ciphers:
        return
    cipher_str = ":".join(ciphers).encode()
    try:
        if hasattr(_ossl_lib, "SSL_CTX_set_ciphersuites"):
            _ossl_lib.SSL_CTX_set_ciphersuites(ctx_ptr, cipher_str)
    except Exception:
        pass


def _apply_curve_groups(ctx_ptr: Any, curves: list) -> None:
    if not _ossl_lib or not curves:
        return
    groups_str = ":".join(curves).encode()
    try:
        if hasattr(_ossl_lib, "SSL_CTX_set1_groups_list"):
            _ossl_lib.SSL_CTX_set1_groups_list(ctx_ptr, groups_str)
        elif hasattr(_ossl_lib, "SSL_CTX_set1_curves_list"):
            _ossl_lib.SSL_CTX_set1_curves_list(ctx_ptr, groups_str)
    except Exception:
        pass


def _build_pyossl_context(
    preset: BrowserPreset,
    ja3: Optional[JA3Spec],
    verify: bool,
) -> Any:
    opts = _OP_NO_SSLv2 | _OP_NO_SSLv3 | _OP_NO_TLSv1 | _OP_NO_TLSv1_1
    ctx = _PyOSSLContext(_TLS_METHOD)
    ctx.set_options(opts)

    if verify:
        ctx.set_default_verify_paths()
        ctx.set_verify(
            _VERIFY_PEER | _VERIFY_FAIL_IF_NO_PEER_CERT,
            lambda conn, cert, errnum, depth, ok: ok,
        )
    else:
        ctx.set_verify(0, lambda conn, cert, errnum, depth, ok: True)

    ja3_spec = ja3 if ja3 is not None else _safe_parse_ja3(preset.ja3)

    if ja3_spec:
        if ja3_spec.tls12_ciphers:
            try:
                ctx.set_cipher_list(":".join(ja3_spec.tls12_ciphers).encode())
            except Exception:
                pass

        if ja3_spec.tls13_ciphers:
            _apply_tls13_ciphers(ctx._context, ja3_spec.tls13_ciphers)

        if ja3_spec.curve_names:
            _apply_curve_groups(ctx._context, ja3_spec.curve_names)

    try:
        ctx.set_alpn_protos([p.encode() for p in preset.alpn])
    except Exception:
        pass

    return ctx


def _build_stdlib_context(
    preset: BrowserPreset,
    ja3: Optional[JA3Spec],
    verify: bool,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_default_certs()

    for flag in ("OP_NO_SSLv2", "OP_NO_SSLv3"):
        if hasattr(ssl, flag):
            ctx.options |= getattr(ssl, flag)

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    ja3_spec = ja3 if ja3 is not None else _safe_parse_ja3(preset.ja3)
    if ja3_spec and ja3_spec.tls12_ciphers:
        try:
            ctx.set_ciphers(":".join(ja3_spec.tls12_ciphers))
        except ssl.SSLError:
            pass

    ctx.set_alpn_protocols(preset.alpn)
    return ctx


def _safe_parse_ja3(ja3_str: str) -> Optional[JA3Spec]:
    try:
        return parse_ja3(ja3_str)
    except Exception:
        return None


def _get_or_build_context(
    preset: BrowserPreset,
    ja3: Optional[JA3Spec],
    verify: bool,
    pyossl: bool,
) -> Any:
    key = (preset.name, verify, pyossl, *_ja3_cache_key(ja3))
    with _CONTEXT_LOCK:
        ctx = _CONTEXT_CACHE.get(key)
        if ctx is None:
            if pyossl and _PYOSSL_AVAILABLE:
                ctx = _build_pyossl_context(preset, ja3, verify)
            else:
                ctx = _build_stdlib_context(preset, ja3, verify)
            _CONTEXT_CACHE[key] = ctx
    return ctx


def open_tls_connection(
    host: str,
    port: int,
    preset: BrowserPreset,
    ja3: Optional[JA3Spec] = None,
    proxy_sock: Optional[socket.socket] = None,
    timeout: int = 30,
    verify: bool = True,
) -> Any:
    if _PYOSSL_AVAILABLE:
        try:
            return _open_pyossl(host, port, preset, ja3, proxy_sock, timeout, verify)
        except Exception:
            pass
    return _open_stdlib(host, port, preset, ja3, proxy_sock, timeout, verify)


def _do_handshake_with_timeout(conn: Any, raw_sock: socket.socket, timeout: int) -> None:
    deadline = time.perf_counter() + timeout
    while True:
        try:
            conn.do_handshake()
            return
        except Exception as exc:
            exc_name = type(exc).__name__
            if exc_name in ("WantReadError", "WantWriteError"):
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    raise TimeoutError("TLS handshake timed out") from exc
                if exc_name == "WantReadError":
                    select.select([raw_sock], [], [], min(remaining, 1.0))
                else:
                    select.select([], [raw_sock], [], min(remaining, 1.0))
            else:
                raise


def _open_pyossl(
    host: str,
    port: int,
    preset: BrowserPreset,
    ja3: Optional[JA3Spec],
    proxy_sock: Optional[socket.socket],
    timeout: int,
    verify: bool,
) -> _ViperSSLSocket:
    ctx = _get_or_build_context(preset, ja3, verify, pyossl=True)
    session_key = (host, port, preset.name)
    cached_session = _get_cached_session(session_key)

    t_connect_start = time.perf_counter()
    if proxy_sock is not None:
        raw = proxy_sock
        raw.settimeout(timeout)
    else:
        raw = socket.create_connection((host, port), timeout=timeout)
    connect_ms = (time.perf_counter() - t_connect_start) * 1000

    raw.setblocking(True)

    conn = _PyOSSLConnection(ctx, raw)
    conn.set_tlsext_host_name(host.encode())
    conn.set_connect_state()

    pre_session_set = False
    if cached_session is not None:
        try:
            conn.set_session(cached_session)
            pre_session_set = True
        except Exception:
            pass

    t_hs_start = time.perf_counter()
    conn.do_handshake()
    handshake_ms = (time.perf_counter() - t_hs_start) * 1000

    raw.settimeout(timeout)

    session_reused = False
    if pre_session_set:
        try:
            new_sess = conn.get_session()
            if new_sess and cached_session:
                session_reused = new_sess.get_id() == cached_session.get_id()
        except Exception:
            pass

    try:
        new_session = conn.get_session()
        _store_session(session_key, new_session)
    except Exception:
        pass

    return _ViperSSLSocket(
        conn, raw,
        session_reused=session_reused,
        connect_ms=connect_ms,
        handshake_ms=handshake_ms,
    )


def _open_stdlib(
    host: str,
    port: int,
    preset: BrowserPreset,
    ja3: Optional[JA3Spec],
    proxy_sock: Optional[socket.socket],
    timeout: int,
    verify: bool,
) -> ssl.SSLSocket:
    ctx = _get_or_build_context(preset, ja3, verify, pyossl=False)
    session_key = (host, port, preset.name)
    cached_session = _get_cached_session(session_key)

    if proxy_sock is not None:
        raw = proxy_sock
        raw.settimeout(timeout)
    else:
        raw = socket.create_connection((host, port), timeout=timeout)

    kwargs: dict = {
        "server_hostname": host,
        "server_side": False,
        "do_handshake_on_connect": True,
    }

    if cached_session is not None:
        try:
            sock = ctx.wrap_socket(raw, session=cached_session, **kwargs)
            session = getattr(sock, "session", None)
            _store_session(session_key, session)
            return sock
        except Exception:
            pass

    sock = ctx.wrap_socket(raw, **kwargs)
    session = getattr(sock, "session", None)
    _store_session(session_key, session)
    return sock


def build_ssl_context(
    preset: BrowserPreset,
    ja3: Optional[JA3Spec] = None,
    verify: bool = True,
) -> Any:
    if _PYOSSL_AVAILABLE:
        try:
            return _build_pyossl_context(preset, ja3, verify)
        except Exception:
            pass
    return _build_stdlib_context(preset, ja3, verify)


def wrap_socket(
    raw_sock: socket.socket,
    host: str,
    ctx: Any,
    server_side: bool = False,
    session_key: Optional[tuple] = None,
) -> Any:
    if _PYOSSL_AVAILABLE and isinstance(ctx, _PyOSSLContext):
        conn = _PyOSSLConnection(ctx, raw_sock)
        if not server_side:
            conn.set_tlsext_host_name(host.encode())
            conn.set_connect_state()
        else:
            conn.set_accept_state()
        conn.do_handshake()
        return _ViperSSLSocket(conn, raw_sock)

    kwargs: dict = {
        "server_hostname": host if not server_side else None,
        "server_side": server_side,
        "do_handshake_on_connect": True,
    }
    cached = _get_cached_session(session_key)
    if cached is not None:
        try:
            sock = ctx.wrap_socket(raw_sock, session=cached, **kwargs)
            _store_session(session_key, getattr(sock, "session", None))
            return sock
        except Exception:
            pass
    sock = ctx.wrap_socket(raw_sock, **kwargs)
    _store_session(session_key, getattr(sock, "session", None))
    return sock
