import socket
import struct
from urllib.parse import urlparse


def _normalize_proxy_url(proxy_url: str) -> str:
    raw = (proxy_url or "").strip()
    if "://" in raw:
        return raw

    parts = raw.split(":")
    if len(parts) == 2:
        host, port = parts
        if host and port.isdigit():
            return f"http://{host}:{port}"
    if len(parts) == 4:
        host, port, username, password = parts
        if host and port.isdigit():
            return f"http://{username}:{password}@{host}:{port}"

    raise ValueError(
        "Unsupported proxy format. Use http://host:port, socks5://host:port, ip:port, or ip:port:user:pass"
    )


def open_tunnel(host: str, port: int, proxy_url: str) -> socket.socket:
    parsed = urlparse(_normalize_proxy_url(proxy_url))
    scheme = parsed.scheme.lower()
    proxy_host = parsed.hostname
    proxy_port = parsed.port
    username = parsed.username
    password = parsed.password

    if scheme in ("http", "https"):
        return _http_connect(host, port, proxy_host, proxy_port, username, password)
    elif scheme in ("socks5", "socks5h"):
        remote_resolve = scheme == "socks5h"
        return _socks5_connect(host, port, proxy_host, proxy_port, username, password, remote_resolve)
    elif scheme == "socks4":
        return _socks4_connect(host, port, proxy_host, proxy_port, username)
    else:
        raise ValueError(f"Unsupported proxy scheme: {scheme}")


def _http_connect(host, port, proxy_host, proxy_port, username, password):
    sock = socket.create_connection((proxy_host, proxy_port), timeout=30)
    connect_line = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    if username and password:
        import base64
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        connect_line += f"Proxy-Authorization: Basic {credentials}\r\n"
    connect_line += "Proxy-Connection: Keep-Alive\r\n\r\n"
    sock.sendall(connect_line.encode())

    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Proxy closed connection during CONNECT")
        response += chunk

    status_line = response.split(b"\r\n")[0].decode()
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or parts[1] != "200":
        raise ConnectionError(f"Proxy CONNECT failed: {status_line}")

    return sock


def _socks5_connect(host, port, proxy_host, proxy_port, username, password, remote_resolve):
    sock = socket.create_connection((proxy_host, proxy_port), timeout=30)

    use_auth = username is not None and password is not None
    auth_method = b"\x02" if use_auth else b"\x00"
    sock.sendall(b"\x05\x01" + auth_method)

    greeting = _recv_exact(sock, 2)
    if greeting[0] != 0x05:
        raise ConnectionError("SOCKS5: invalid server greeting")
    chosen = greeting[1]

    if chosen == 0x02:
        if not use_auth:
            raise ConnectionError("SOCKS5: server requires authentication but none provided")
        user_bytes = username.encode()
        pass_bytes = password.encode()
        auth_msg = bytes([0x01, len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes
        sock.sendall(auth_msg)
        auth_response = _recv_exact(sock, 2)
        if auth_response[1] != 0x00:
            raise ConnectionError("SOCKS5: authentication failed")
    elif chosen == 0xFF:
        raise ConnectionError("SOCKS5: no acceptable authentication method")

    if remote_resolve:
        host_bytes = host.encode()
        addr_type = b"\x03"
        addr_data = bytes([len(host_bytes)]) + host_bytes
    else:
        try:
            ip = socket.gethostbyname(host)
            packed = socket.inet_aton(ip)
            addr_type = b"\x01"
            addr_data = packed
        except socket.gaierror:
            host_bytes = host.encode()
            addr_type = b"\x03"
            addr_data = bytes([len(host_bytes)]) + host_bytes

    port_bytes = struct.pack(">H", port)
    sock.sendall(b"\x05\x01\x00" + addr_type + addr_data + port_bytes)

    reply_header = _recv_exact(sock, 4)
    if reply_header[1] != 0x00:
        _SOCKS5_ERRORS = {
            0x01: "general failure",
            0x02: "connection forbidden",
            0x03: "network unreachable",
            0x04: "host unreachable",
            0x05: "connection refused",
            0x06: "TTL expired",
            0x07: "command not supported",
            0x08: "address type not supported",
        }
        reason = _SOCKS5_ERRORS.get(reply_header[1], f"code {reply_header[1]}")
        raise ConnectionError(f"SOCKS5: connection failed: {reason}")

    addr_type = reply_header[3]
    if addr_type == 0x01:
        _recv_exact(sock, 4)
    elif addr_type == 0x03:
        length = _recv_exact(sock, 1)[0]
        _recv_exact(sock, length)
    elif addr_type == 0x04:
        _recv_exact(sock, 16)

    _recv_exact(sock, 2)
    return sock


def _socks4_connect(host, port, proxy_host, proxy_port, username):
    sock = socket.create_connection((proxy_host, proxy_port), timeout=30)
    try:
        ip = socket.gethostbyname(host)
        packed_ip = socket.inet_aton(ip)
    except socket.gaierror:
        raise ConnectionError(f"SOCKS4: cannot resolve {host}")

    user_bytes = (username or "").encode() + b"\x00"
    request = struct.pack(">BBH", 0x04, 0x01, port) + packed_ip + user_bytes
    sock.sendall(request)

    reply = _recv_exact(sock, 8)
    if reply[1] != 0x5A:
        raise ConnectionError(f"SOCKS4: connection rejected, code {reply[1]}")

    return sock


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Connection closed while reading {n} bytes")
        buf += chunk
    return buf
