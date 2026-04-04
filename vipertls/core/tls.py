import os
import ssl
import socket
import struct
import ctypes
import ctypes.util
import sys
from pathlib import Path
from typing import Optional

from ..fingerprints.ja3 import JA3Spec
from ..fingerprints.presets import BrowserPreset


class _OpenSSLLib:
    _instance: Optional["_OpenSSLLib"] = None
    _lib: Optional[ctypes.CDLL] = None

    def __new__(cls) -> "_OpenSSLLib":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load()
        return cls._instance

    def _load(self) -> None:
        candidates = self._candidate_paths()

        # On Windows, libssl-3.dll depends on libcrypto-3.dll in the same dir.
        # Without pre-registering that directory, ctypes raises OSError even when
        # the path is correct.  os.add_dll_directory() (Python 3.8+) fixes this.
        # We intentionally do NOT close the cookies so the dirs stay registered
        # for the lifetime of the process — subsequent ctypes calls still  need them.
#i fucking wonder why do i waste my time on that shit


 

        
        if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
            _seen_dirs: set[str] = set()
            for c in candidates:
                dll_dir = str(Path(c).parent.resolve())
                if dll_dir not in _seen_dirs:
                    _seen_dirs.add(dll_dir)
                    try:
                        # Store on class so the GC doesn't close these cookies.
                        if not hasattr(self, "_dll_dir_cookies"):
                            self._dll_dir_cookies = []
                        self._dll_dir_cookies.append(os.add_dll_directory(dll_dir))
                    except (OSError, ValueError):
                        pass

        for candidate in candidates:
            try:
                self._lib = ctypes.CDLL(str(candidate))
                return
            except OSError:
                continue

    def _candidate_paths(self) -> list[str]:
        candidates: list[str] = []
        seen: set[str] = set()

        def add(value: Optional[object]) -> None:
            if not value:
                return
            path = str(value)
            if path in seen:
                return
            seen.add(path)
            candidates.append(path)

        # Ask the platform loader first.
        for name in self._find_library_names():
            found = ctypes.util.find_library(name)
            if found:
                add(found)

        # CPython on Windows bundles libssl in the install's DLL directories.
        for path in self._bundled_library_paths():
            add(path)

        # Common direct soname/dll fallbacks.
        for path in self._fallback_library_names():
            add(path)

        return candidates

    def _find_library_names(self) -> list[str]:
        if sys.platform == "win32":
            return ["libssl", "ssl"]
        if sys.platform == "darwin":
            return ["ssl", "libssl"]
        return ["ssl", "libssl"]

    def _bundled_library_paths(self) -> list[Path]:
        # Collect root directories to search, deduped.
        root_seen: set[Path] = set()
        roots: list[Path] = []

        def _add_root(p: Path) -> None:
            try:
                p = p.resolve()
            except OSError:
                return
            if p not in root_seen:
                root_seen.add(p)
                roots.append(p)

        # The directory that contains the Python executable.
        exe_dir = Path(sys.executable).resolve().parent
        _add_root(exe_dir)
        _add_root(exe_dir / "DLLs")

        # The directory that contains the compiled _ssl extension.
        try:
            _add_root(Path(ssl._ssl.__file__).resolve().parent)
        except AttributeError:
            pass

        # ViperTLS bundled bin directory (relative to this file: ../bin/)
        pkg_bin = Path(__file__).resolve().parent.parent / "bin"
        if pkg_bin.exists():
            _add_root(pkg_bin)

        # When running inside a virtual environment, sys.executable is the venv's
        # Scripts/python.exe — but the actual OpenSSL DLLs live in the *base*
        # Python installation (sys.base_prefix / DLLs).  This is the most common
        # reason ctypes can't find libssl-3.dll on Windows.
        base = getattr(sys, "base_prefix", None) or sys.prefix
        if base and Path(base).resolve() != Path(sys.prefix).resolve():
            base_path = Path(base).resolve()
            _add_root(base_path)
            _add_root(base_path / "DLLs")
            _add_root(base_path / "Library" / "bin")  # conda / Windows Store builds

        # Respect PYTHONHOME if set (e.g. custom embedded distributions).
        python_home = os.environ.get("PYTHONHOME")
        if python_home:
            _add_root(Path(python_home))
            _add_root(Path(python_home) / "DLLs")

        if sys.platform == "win32":
            names = ["libssl-3.dll", "libssl-1_1.dll", "libssl.dll"]
        elif sys.platform == "darwin":
            names = ["libssl.3.dylib", "libssl.1.1.dylib", "libssl.dylib"]
        else:
            names = ["libssl.so.3", "libssl.so.1.1", "libssl.so"]

        seen: set[Path] = set()
        candidates: list[Path] = []
        for root in roots:
            for name in names:
                path = root / name
                if path.exists() and path not in seen:
                    seen.add(path)
                    candidates.append(path)
        return candidates

    def _fallback_library_names(self) -> list[str]:
        if sys.platform == "win32":
            return ["libssl-3.dll", "libssl-1_1.dll", "libssl.dll"]
        if sys.platform == "darwin":
            return ["libssl.3.dylib", "libssl.1.1.dylib", "libssl.dylib"]
        return ["libssl.so.3", "libssl.so.1.1", "libssl.so"]

    @property
    def available(self) -> bool:
        return self._lib is not None

    def set_groups_list(self, ssl_ctx_ptr: int, groups: str) -> bool:
        if not self._lib:
            return False
        
        # 1. Try SSL_CTX_set1_groups_list (modern name)
        try:
            fn = self._lib.SSL_CTX_set1_groups_list
            fn.restype = ctypes.c_int
            fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            if fn(ssl_ctx_ptr, groups.encode()) == 1:
                return True
        except AttributeError:
            pass

        # 2. Try SSL_CTX_set1_curves_list (older name/alias)
        try:
            fn = self._lib.SSL_CTX_set1_curves_list
            fn.restype = ctypes.c_int
            fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            if fn(ssl_ctx_ptr, groups.encode()) == 1:
                return True
        except AttributeError:
            pass

        # 3. Fallback to SSL_CTX_ctrl (most reliable on Windows/Macros)
        # #define SSL_CTRL_SET_GROUPS_LIST 92
        try:
            fn = self._lib.SSL_CTX_ctrl
            fn.restype = ctypes.c_long
            fn.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_char_p]
            # args: ctx, cmd, larg, parg
            return fn(ssl_ctx_ptr, 92, 0, groups.encode()) == 1
        except AttributeError:
            return False

    def set_tls13_ciphersuites(self, ssl_ctx_ptr: int, ciphers: str) -> bool:
        if not self._lib:
            return False
        try:
            fn = self._lib.SSL_CTX_set_ciphersuites
            fn.restype = ctypes.c_int
            fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            return fn(ssl_ctx_ptr, ciphers.encode()) == 1
        except AttributeError:
            return False


_openssl = _OpenSSLLib()


def _extract_ssl_ctx_ptr(ctx: ssl.SSLContext) -> int:
    raw = (ctypes.c_char * 24).from_address(id(ctx))
    return struct.unpack_from("Q", raw, 16)[0]


def build_ssl_context(preset: BrowserPreset, ja3: Optional[JA3Spec] = None, verify: bool = True) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_default_certs()

    ctx.options |= ssl.OP_NO_SSLv2 if hasattr(ssl, "OP_NO_SSLv2") else 0
    ctx.options |= ssl.OP_NO_SSLv3 if hasattr(ssl, "OP_NO_SSLv3") else 0
    ctx.options &= ~ssl.OP_NO_TLSv1_3 if hasattr(ssl, "OP_NO_TLSv1_3") else 0

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    if ja3 is not None:
        _apply_ja3(ctx, ja3)
    else:
        _apply_preset_ciphers(ctx, preset)

    ctx.set_alpn_protocols(preset.alpn)

    return ctx


def _apply_ja3(ctx: ssl.SSLContext, ja3: JA3Spec) -> None:
    tls12_ciphers = [c for c in ja3.tls12_ciphers if c]
    if tls12_ciphers:
        try:
            ctx.set_ciphers(":".join(tls12_ciphers))
        except ssl.SSLError:
            pass

    if ja3.tls13_ciphers and _openssl.available:
        try:
            ctx_ptr = _extract_ssl_ctx_ptr(ctx)
            _openssl.set_tls13_ciphersuites(ctx_ptr, ":".join(ja3.tls13_ciphers))
        except Exception:
            pass

    if ja3.curve_names and _openssl.available:
        try:
            ctx_ptr = _extract_ssl_ctx_ptr(ctx)
            _openssl.set_groups_list(ctx_ptr, ":".join(ja3.curve_names))
        except Exception:
            pass


def _apply_preset_ciphers(ctx: ssl.SSLContext, preset: BrowserPreset) -> None:
    from ..fingerprints.ja3 import parse_ja3
    try:
        ja3_spec = parse_ja3(preset.ja3)
        _apply_ja3(ctx, ja3_spec)
    except Exception:
        pass


def wrap_socket(
    raw_sock: socket.socket,
    host: str,
    ctx: ssl.SSLContext,
    server_side: bool = False,
) -> ssl.SSLSocket:
    return ctx.wrap_socket(
        raw_sock,
        server_hostname=host if not server_side else None,
        server_side=server_side,
        do_handshake_on_connect=True,
    )


def open_tls_connection(
    host: str,
    port: int,
    preset: BrowserPreset,
    ja3: Optional[JA3Spec] = None,
    proxy_sock: Optional[socket.socket] = None,
    timeout: int = 30,
    verify: bool = True,
) -> ssl.SSLSocket:
    ctx = build_ssl_context(preset, ja3=ja3, verify=verify)

    if proxy_sock is not None:
        raw = proxy_sock
        raw.settimeout(timeout)
    else:
        raw = socket.create_connection((host, port), timeout=timeout)

    return wrap_socket(raw, host, ctx)
