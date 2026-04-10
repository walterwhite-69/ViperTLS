import asyncio
import ssl
import time
from collections import deque
from typing import Optional
from urllib.parse import urlparse

from ..fingerprints.presets import BrowserPreset
from .response import ViperResponse


class _H3Protocol:
    def __init__(self, quic_conn, h3_conn, loop):
        self._quic = quic_conn
        self._h3 = h3_conn
        self._loop = loop
        self._stream_events: dict = {}
        self._stream_waiters: dict = {}

    def _transmit(self, transport):
        data = self._quic.datagrams_to_send(now=self._loop.time())
        for datagram, addr in data:
            try:
                transport.sendto(datagram, addr)
            except Exception:
                pass

    def _process_quic_events(self):
        from aioquic.h3.events import HeadersReceived, DataReceived
        events = []
        event = self._quic.next_event()
        while event is not None:
            h3_events = self._h3.handle_event(event)
            for h3_event in h3_events:
                sid = getattr(h3_event, "stream_id", None)
                if sid is not None and sid in self._stream_events:
                    self._stream_events[sid].append(h3_event)
                    if isinstance(h3_event, DataReceived) and h3_event.stream_ended:
                        waiter = self._stream_waiters.get(sid)
                        if waiter and not waiter.done():
                            waiter.set_result(None)
                events.append(h3_event)
            event = self._quic.next_event()
        return events


def _build_quic_config(preset: BrowserPreset, host: str, verify: bool) -> object:
    from aioquic.quic.configuration import QuicConfiguration

    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
        server_name=host,
    )

    if not verify:
        config.verify_mode = ssl.CERT_NONE
    else:
        config.verify_mode = ssl.CERT_REQUIRED

    qp = preset.quic_params
    if hasattr(config, "max_data"):
        config.max_data = qp.get("max_data", 15728640)
    if hasattr(config, "max_stream_data"):
        config.max_stream_data = qp.get("max_stream_data", 6291456)
    if hasattr(config, "max_streams_bidi"):
        config.max_streams_bidi = qp.get("max_streams_bidi", 100)
    if hasattr(config, "max_streams_uni"):
        config.max_streams_uni = qp.get("max_streams_uni", 100)
    if hasattr(config, "idle_timeout"):
        config.idle_timeout = qp.get("idle_timeout", 30.0)

    return config


def _build_h3_headers(
    method: str,
    host: str,
    path: str,
    query: str,
    scheme: str,
    headers: dict,
    preset: BrowserPreset,
) -> list:
    full_path = path or "/"
    if query:
        full_path = f"{full_path}?{query}"

    result = [
        (b":method", method.upper().encode()),
        (b":scheme", scheme.encode()),
        (b":authority", host.encode()),
        (b":path", full_path.encode()),
    ]

    headers_lower = {k.lower(): v for k, v in headers.items()}
    headers_lower.setdefault("user-agent", preset.user_agent)

    _hop_by_hop = frozenset({
        "connection", "keep-alive", "transfer-encoding", "upgrade",
        "proxy-connection", "te", "trailers",
    })

    for key in preset.header_order:
        kl = key.lower()
        if kl in _hop_by_hop:
            continue
        if kl in headers_lower:
            result.append((kl.encode(), headers_lower[kl].encode()))
        elif kl in {k.lower(): k for k in preset.default_headers}:
            for dk, dv in preset.default_headers.items():
                if dk.lower() == kl:
                    result.append((dk.lower().encode(), dv.encode()))
                    break

    seen = {k.decode() for k, _ in result}
    for k, v in headers_lower.items():
        if k not in seen and k not in _hop_by_hop:
            result.append((k.encode(), v.encode()))

    return result


async def http3_request_async(
    host: str,
    port: int,
    method: str,
    path: str,
    query: str,
    headers: dict,
    preset: BrowserPreset,
    body: Optional[bytes],
    target_url: str,
    scheme: str = "https",
    verify: bool = True,
    timeout: int = 30,
) -> ViperResponse:
    from aioquic.asyncio import connect
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived, H3Event

    config = _build_quic_config(preset, host, verify)
    h3_headers = _build_h3_headers(method, host, path, query, scheme, headers, preset)

    class _SimpleH3Client:
        def __init__(self, quic, h3):
            self._quic = quic
            self._h3 = h3
            self._response_headers: dict = {}
            self._response_body: list = []
            self._set_cookies: list = []
            self._status_code: int = 0
            self._done = asyncio.Event()

        def http_event_received(self, event):
            if isinstance(event, HeadersReceived):
                for k, v in event.headers:
                    ks = k.decode("latin-1") if isinstance(k, bytes) else k
                    vs = v.decode("latin-1") if isinstance(v, bytes) else v
                    if ks == ":status":
                        self._status_code = int(vs)
                    elif ks.lower() == "set-cookie":
                        self._set_cookies.append(vs)
                    else:
                        self._response_headers[ks.lower()] = vs
            elif isinstance(event, DataReceived):
                if event.data:
                    self._response_body.append(event.data)
                if event.stream_ended:
                    self._done.set()

    status_code = 0
    resp_headers: dict = {}
    set_cookies: list = []
    body_chunks: list = []

    async with connect(
        host, port,
        configuration=config,
        create_protocol=None,
    ) as quic_proto:
        h3 = H3Connection(quic_proto._quic)
        stream_id = quic_proto._quic.get_next_available_stream_id()

        h3.send_headers(
            stream_id=stream_id,
            headers=h3_headers,
            end_stream=(body is None),
        )
        if body:
            h3.send_data(stream_id=stream_id, data=body, end_stream=True)

        quic_proto.transmit()

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                await asyncio.wait_for(
                    asyncio.shield(quic_proto.wait_connected()),
                    timeout=min(remaining, 1.0),
                )
            except (asyncio.TimeoutError, Exception):
                pass

            done = False
            event = quic_proto._quic.next_event()
            while event is not None:
                for h3_event in h3.handle_event(event):
                    if isinstance(h3_event, HeadersReceived) and h3_event.stream_id == stream_id:
                        for k, v in h3_event.headers:
                            ks = k.decode("latin-1") if isinstance(k, bytes) else k
                            vs = v.decode("latin-1") if isinstance(v, bytes) else v
                            if ks == ":status":
                                status_code = int(vs)
                            elif ks.lower() == "set-cookie":
                                set_cookies.append(vs)
                            else:
                                resp_headers[ks.lower()] = vs
                    elif isinstance(h3_event, DataReceived) and h3_event.stream_id == stream_id:
                        if h3_event.data:
                            body_chunks.append(h3_event.data)
                        if h3_event.stream_ended:
                            done = True
                event = quic_proto._quic.next_event()

            if done:
                break

            await asyncio.sleep(0.01)

    return ViperResponse(
        status_code=status_code,
        headers={
            **resp_headers,
            "x-vipertls-h2-priority": "false",
        },
        content=b"".join(body_chunks),
        url=target_url,
        http_version="HTTP/3",
        set_cookies=set_cookies,
    )


def http3_request_blocking(
    host: str,
    port: int,
    method: str,
    path: str,
    query: str,
    headers: dict,
    preset: BrowserPreset,
    body: Optional[bytes],
    target_url: str,
    scheme: str = "https",
    verify: bool = True,
    timeout: int = 30,
) -> ViperResponse:
    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                http3_request_async(
                    host=host,
                    port=port,
                    method=method,
                    path=path,
                    query=query,
                    headers=headers,
                    preset=preset,
                    body=body,
                    target_url=target_url,
                    scheme=scheme,
                    verify=verify,
                    timeout=timeout,
                )
            )
        finally:
            loop.close()
    except Exception as exc:
        raise RuntimeError(f"HTTP/3 request failed: {exc}") from exc
