import json
import zlib
import gzip
from typing import Any


class ViperResponse:
    def __init__(
        self,
        status_code: int,
        headers: dict,
        content: bytes,
        url: str,
        http_version: str = "HTTP/2",
        set_cookies: list | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.content = self._decompress(content)
        self.url = url
        self.http_version = http_version
        self.set_cookies: list = set_cookies or []

    def _parse_cookie_pairs(self, values: list) -> dict:
        parsed: dict = {}
        for item in values:
            first = item.split(";", 1)[0].strip()
            if "=" not in first:
                continue
            name, value = first.split("=", 1)
            if name:
                parsed[name] = value
        return parsed

    def _parse_json_header(self, name: str) -> dict:
        raw = self.headers.get(name, "").strip()
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except Exception:
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items()}

    def _decompress(self, data: bytes) -> bytes:
        encoding = self.headers.get("content-encoding", "").lower().strip()
        if not encoding or not data:
            return data
        try:
            if encoding == "gzip":
                return gzip.decompress(data)
            if encoding == "br":
                import brotli
                return brotli.decompress(data)
            if encoding == "deflate":
                try:
                    return zlib.decompress(data)
                except zlib.error:
                    return zlib.decompress(data, -zlib.MAX_WBITS)
            if encoding == "zstd":
                try:
                    import zstandard as zstd
                    import io
                    dctx = zstd.ZstdDecompressor()
                    with dctx.stream_reader(io.BytesIO(data)) as reader:
                        return reader.read()
                except ImportError:
                    return data
        except Exception:
            return data
        return data

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    @property
    def text(self) -> str:
        encoding = self._detect_encoding()
        return self.content.decode(encoding, errors="replace")

    def _detect_encoding(self) -> str:
        ct = self.headers.get("content-type", "")
        for part in ct.split(";"):
            part = part.strip()
            if part.lower().startswith("charset="):
                return part[8:].strip().strip('"')
        try:
            from charset_normalizer import from_bytes
            result = from_bytes(self.content).best()
            if result:
                return str(result.encoding)
        except ImportError:
            pass
        return "utf-8"

    def json(self) -> Any:
        return json.loads(self.content)

    @property
    def solved_by(self) -> str:
        return self.headers.get("x-vipertls-solved-by", "tls")

    @property
    def from_cache(self) -> bool:
        return self.solved_by == "cache"

    @property
    def cookies_received(self) -> dict:
        header_cookies = self._parse_json_header("x-viper-received-cookies")
        if header_cookies:
            return header_cookies
        return self._parse_cookie_pairs(self.set_cookies)

    @property
    def cookies_used(self) -> dict:
        return self._parse_json_header("x-vipertls-used-cookies") or self._parse_json_header("x-viper-used-cookies")

    @property
    def tls_resumed(self) -> bool:
        return self.headers.get("x-vipertls-tls-resumed", "").lower() == "true"

    @property
    def h2_priority(self) -> bool:
        return self.headers.get("x-vipertls-h2-priority", "").lower() == "true"

    @property
    def ja4_profile(self) -> str:
        return self.headers.get("x-vipertls-ja4-profile", "")

    @property
    def ja4(self) -> str:
        return self.headers.get("x-vipertls-ja4", "")

    @property
    def ja4_r(self) -> str:
        return self.headers.get("x-vipertls-ja4-r", "")

    @property
    def ja4h(self) -> str:
        return self.headers.get("x-vipertls-ja4h", "")

    @property
    def ja4s(self) -> str:
        return self.headers.get("x-vipertls-ja4s", "")

    @property
    def ja4l(self) -> str:
        return self.headers.get("x-vipertls-ja4l", "")

    @property
    def solve_info(self) -> dict:
        return {
            "solved_by": self.solved_by,
            "from_cache": self.from_cache,
            "http_version": self.http_version,
            "tls_resumed": self.tls_resumed,
            "h2_priority": self.h2_priority,
            "ja4": self.ja4,
            "ja4_r": self.ja4_r,
            "ja4h": self.ja4h,
            "ja4s": self.ja4s,
            "ja4l": self.ja4l,
            "ja4_profile": self.ja4_profile,
            "cookies_received": self.cookies_received,
            "cookies_used": self.cookies_used,
        }

    @property
    def meta(self) -> dict:
        return self.solve_info

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise ViperHTTPError(self.status_code, self.url)

    def __repr__(self) -> str:
        return f"<ViperResponse [{self.status_code}]>"


class ViperHTTPError(Exception):
    def __init__(self, status_code: int, url: str) -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(f"HTTP {status_code} for {url}")


class ViperConnectionError(Exception):
    pass


class ViperTimeoutError(Exception):
    pass


class ViperProxyError(Exception):
    pass
