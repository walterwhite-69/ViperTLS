import ssl
import socket
import gzip
import zlib
from typing import Optional
from urllib.parse import urlparse, urlencode

from ..fingerprints.presets import BrowserPreset
from ..fingerprints.ja4 import compute_ja4h
from .response import ViperResponse


_HOP_BY_HOP = frozenset([
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
])


def _build_request_line(method: str, path: str, query: str) -> bytes:
    full_path = path if path else "/"
    if query:
        full_path = f"{full_path}?{query}"
    return f"{method.upper()} {full_path} HTTP/1.1\r\n".encode()


def _serialize_headers(
    host: str,
    headers: dict,
    preset: BrowserPreset,
    body: Optional[bytes],
) -> tuple:
    ordered: list = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    if "host" not in headers_lower:
        ordered.append(("Host", host))

    for key in preset.header_order:
        key_lower = key.lower()
        if key_lower in headers_lower:
            ordered.append((key, headers_lower[key_lower]))
        elif key_lower in {k.lower(): k for k in preset.default_headers}:
            for dk, dv in preset.default_headers.items():
                if dk.lower() == key_lower:
                    ordered.append((dk, dv))
                    break

    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower not in {h.lower() for h, _ in ordered} and k_lower not in _HOP_BY_HOP:
            ordered.append((k, v))

    if body:
        has_content_length = any(h.lower() == "content-length" for h, _ in ordered)
        if not has_content_length:
            ordered.append(("Content-Length", str(len(body))))

    ordered.append(("Connection", "close"))

    raw = "".join(f"{k}: {v}\r\n" for k, v in ordered).encode()
    return raw, [(k, v) for k, v in ordered]


def _recv_until_headers(sock: object) -> tuple:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    sep = buf.find(b"\r\n\r\n")
    if sep == -1:
        return buf, b""
    return buf[:sep], buf[sep + 4:]


def _parse_status_line(line: bytes) -> tuple:
    parts = line.split(b" ", 2)
    status = int(parts[1])
    reason = parts[2].decode("latin-1").strip() if len(parts) > 2 else ""
    return status, reason


def _parse_headers(raw: bytes) -> tuple:
    headers: dict = {}
    set_cookies: list = []
    lines = raw.split(b"\r\n")
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, _, value = line.partition(b":")
        k = key.strip().decode("latin-1").lower()
        v = value.strip().decode("latin-1")
        if k == "set-cookie":
            set_cookies.append(v)
        else:
            headers[k] = v
    return headers, set_cookies


def _read_chunked(sock: object, initial: bytes) -> bytes:
    buf = initial
    body = b""
    while True:
        while b"\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return body
            buf += chunk
        line_end = buf.find(b"\r\n")
        size_str = buf[:line_end].split(b";")[0].strip()
        try:
            chunk_size = int(size_str, 16)
        except ValueError:
            break
        buf = buf[line_end + 2:]
        if chunk_size == 0:
            break
        while len(buf) < chunk_size + 2:
            more = sock.recv(4096)
            if not more:
                body += buf[:chunk_size]
                return body
            buf += more
        body += buf[:chunk_size]
        buf = buf[chunk_size + 2:]
    return body


def _read_body(sock: object, headers: dict, initial: bytes) -> bytes:
    encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in encoding:
        return _read_chunked(sock, initial)

    content_length = headers.get("content-length")
    if content_length is not None:
        total = int(content_length)
        body = initial
        while len(body) < total:
            remaining = total - len(body)
            chunk = sock.recv(min(remaining, 65536))
            if not chunk:
                break
            body += chunk
        return body

    body = initial
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
    except (ssl.SSLError, socket.timeout, OSError):
        pass
    return body


def http1_request(
    ssl_sock: object,
    method: str,
    host: str,
    path: str,
    query: str,
    headers: dict,
    preset: BrowserPreset,
    body: Optional[bytes],
    target_url: str,
) -> ViperResponse:
    request = _build_request_line(method, path, query)
    header_bytes, ordered_headers = _serialize_headers(host, headers, preset, body)
    request += header_bytes
    request += b"\r\n"
    if body:
        request += body

    try:
        ja4h = compute_ja4h(method, "HTTP/1.1", ordered_headers)
    except Exception:
        ja4h = ""

    ssl_sock.sendall(request)

    raw_headers, leftover = _recv_until_headers(ssl_sock)
    lines = raw_headers.split(b"\r\n")
    status_code, _ = _parse_status_line(lines[0])
    resp_headers, set_cookies = _parse_headers(raw_headers)

    raw_body = _read_body(ssl_sock, resp_headers, leftover)

    resp_headers["x-vipertls-ja4h"] = ja4h

    return ViperResponse(
        status_code=status_code,
        headers=resp_headers,
        content=raw_body,
        url=target_url,
        http_version="HTTP/1.1",
        set_cookies=set_cookies,
    )
