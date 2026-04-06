import ssl
import socket
from typing import Optional

import h2.config
import h2.connection
import h2.events
import h2.settings

from ..fingerprints.presets import BrowserPreset
from .response import ViperResponse


_PSEUDO_LETTER_MAP = {
    "m": ":method",
    "a": ":authority",
    "s": ":scheme",
    "p": ":path",
}

_HOP_BY_HOP = frozenset([
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
])

_CHROMIUM_PRIORITY_PREFACE = (
    (3, 201, 0, True),
    (5, 101, 0, True),
    (7, 1, 0, True),
    (9, 1, 7, True),
    (11, 1, 3, True),
)

_CHROMIUM_PRIORITY_FAMILIES = ("chrome", "edge", "brave", "opera")


def _parse_h2_fingerprint(fingerprint: str) -> tuple[dict, int, list[str]]:
    parts = fingerprint.split("|")
    if len(parts) != 4:
        raise ValueError(f"Invalid HTTP/2 fingerprint: {fingerprint!r}")

    settings_part, window_part, _, priority_part = parts

    settings: dict[h2.settings.SettingCodes, int] = {}
    for item in settings_part.split(";"):
        if ":" not in item:
            continue
        id_str, val_str = item.split(":", 1)
        try:
            code = h2.settings.SettingCodes(int(id_str))
            settings[code] = int(val_str)
        except (ValueError, KeyError):
            continue

    window_increment = int(window_part)
    pseudo_order = [_PSEUDO_LETTER_MAP[c] for c in priority_part.split(",") if c in _PSEUDO_LETTER_MAP]

    return settings, window_increment, pseudo_order


def _build_header_list(
    method: str,
    host: str,
    scheme: str,
    path: str,
    query: str,
    extra_headers: dict[str, str],
    preset: BrowserPreset,
    pseudo_order: list[str],
) -> list[tuple[str, str]]:
    full_path = path if path else "/"
    if query:
        full_path = f"{full_path}?{query}"

    pseudo_values = {
        ":method": method.upper(),
        ":authority": host,
        ":scheme": scheme,
        ":path": full_path,
    }

    result: list[tuple[str, str]] = []
    for pseudo in pseudo_order:
        if pseudo in pseudo_values:
            result.append((pseudo, pseudo_values[pseudo]))

    extra_lower = {k.lower(): v for k, v in extra_headers.items()}

    for key in preset.header_order:
        key_lower = key.lower()
        if key_lower in _HOP_BY_HOP:
            continue
        if key_lower in extra_lower:
            result.append((key_lower, extra_lower[key_lower]))
        elif key_lower in {k.lower(): k for k in preset.default_headers}:
            for dk, dv in preset.default_headers.items():
                if dk.lower() == key_lower:
                    result.append((dk.lower(), dv))
                    break

    seen = {h for h, _ in result}
    for k, v in extra_headers.items():
        k_lower = k.lower()
        if k_lower not in seen and k_lower not in _HOP_BY_HOP:
            result.append((k_lower, v))

    return result


class HTTP2Connection:
    def __init__(self, ssl_sock: ssl.SSLSocket, preset: BrowserPreset) -> None:
        self._sock = ssl_sock
        self._preset = preset
        self._priority_enabled = any(name in preset.name.lower() for name in _CHROMIUM_PRIORITY_FAMILIES)
        self._settings, self._window_increment, self._pseudo_order = _parse_h2_fingerprint(
            preset.http2_fingerprint
        )
        self._conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        )
                                                                            
                                                                          
                           
        self._conn.local_settings = h2.settings.Settings(
            client=True,
            initial_values=self._settings,
        )
        self._conn.max_inbound_frame_size = self._conn.local_settings.max_frame_size
        self._conn._inbound_flow_control_window_manager = h2.connection.WindowManager(
            max_window_size=self._conn.local_settings.initial_window_size,
        )

    def _flush(self) -> None:
        data = self._conn.data_to_send(65535)
        if data:
            self._sock.sendall(data)

    def _read_raw(self) -> Optional[bytes]:
        data = self._sock.recv(65535)
        return data if data else None

    def _send_priority_preface(self) -> None:
        if not self._priority_enabled:
            return
        for stream_id, weight, depends_on, exclusive in _CHROMIUM_PRIORITY_PREFACE:
            self._conn.prioritize(
                stream_id=stream_id,
                weight=weight,
                depends_on=depends_on,
                exclusive=exclusive,
            )

    def request(
        self,
        method: str,
        host: str,
        scheme: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body: Optional[bytes],
        target_url: str,
    ) -> ViperResponse:
        self._conn.initiate_connection()

        if self._window_increment > 0:
            self._conn.increment_flow_control_window(self._window_increment)

        self._send_priority_preface()
        self._flush()

        stream_id = self._conn.get_next_available_stream_id()

        header_list = _build_header_list(
            method, host, scheme, path, query, headers, self._preset, self._pseudo_order
        )

        if body:
            self._conn.send_headers(
                stream_id,
                header_list,
                end_stream=False,
                priority_weight=42 if self._priority_enabled else None,
                priority_depends_on=11 if self._priority_enabled else None,
                priority_exclusive=self._priority_enabled or None,
            )
            self._flush()
            self._conn.send_data(stream_id, body, end_stream=True)
        else:
            self._conn.send_headers(
                stream_id,
                header_list,
                end_stream=True,
                priority_weight=42 if self._priority_enabled else None,
                priority_depends_on=11 if self._priority_enabled else None,
                priority_exclusive=self._priority_enabled or None,
            )

        self._flush()

        status_code = 0
        resp_headers: dict[str, str] = {}
        set_cookies: list[str] = []
        body_chunks: list[bytes] = []

        while True:
            try:
                raw = self._read_raw()
            except (ssl.SSLError, OSError):
                break

            if raw is None:
                break

            try:
                events = self._conn.receive_data(raw)
            except Exception:
                break

            self._flush()

            stream_done = False
            for event in events:
                if isinstance(event, h2.events.ResponseReceived):
                    for k, v in event.headers:
                        k_str = k if isinstance(k, str) else k.decode("latin-1")
                        v_str = v if isinstance(v, str) else v.decode("latin-1")
                        if k_str == ":status":
                            status_code = int(v_str)
                        elif k_str.lower() == "set-cookie":
                            set_cookies.append(v_str)
                        else:
                            resp_headers[k_str.lower()] = v_str

                elif isinstance(event, h2.events.DataReceived):
                    if event.data:
                        body_chunks.append(event.data)
                    self._conn.acknowledge_received_data(
                        event.flow_controlled_length, stream_id
                    )
                    self._flush()

                elif isinstance(event, h2.events.StreamEnded):
                    stream_done = True

                elif isinstance(event, h2.events.WindowUpdated):
                    pass

                elif isinstance(event, h2.events.SettingsAcknowledged):
                    pass

            if stream_done:
                break

        return ViperResponse(
            status_code=status_code,
            headers={
                **resp_headers,
                "x-vipertls-h2-priority": "true" if self._priority_enabled else "false",
            },
            content=b"".join(body_chunks),
            url=target_url,
            http_version="HTTP/2",
            set_cookies=set_cookies,
        )

    def close(self) -> None:
        try:
            self._conn.close_connection()
            self._flush()
        except Exception:
            pass
        try:
            self._sock.close()
        except Exception:
            pass
