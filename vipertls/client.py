import ssl
import socket
import asyncio
import json
import os
import re
from typing import Optional
from urllib.parse import urlparse, urlencode, urljoin

from .fingerprints.ja3 import parse_ja3, JA3Spec
from .fingerprints.presets import BrowserPreset, resolve_preset
from .core.tls import open_tls_connection
from .core.http1 import http1_request
from .core.http2 import HTTP2Connection
from .core.response import ViperResponse, ViperConnectionError, ViperTimeoutError
from .proxy.tunnel import open_tunnel


_DEFAULT_TIMEOUT = 30
_MAX_REDIRECTS = 10

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

_CHROMIUM_NAMES = {"chrome", "edge", "brave", "opera"}
_DEBUG_MESSAGES_DEFAULT = os.getenv("VIPERTLS_DEBUG_MESSAGES", "").lower() in {"1", "true", "yes", "on"}


def _parse_cookie_header(cookie_header: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for part in (cookie_header or "").split(";"):
        item = part.strip()
        if not item or "=" not in item:
            continue
        name, value = item.split("=", 1)
        if name:
            parsed[name] = value
    return parsed


def _attach_used_cookie_headers(response: ViperResponse, headers: dict[str, str]) -> None:
    cookie_header = headers.get("cookie", "").strip()
    if not cookie_header:
        return
    used = _parse_cookie_header(cookie_header)
    if not used:
        return
    response.headers["x-vipertls-used-cookie-names"] = ",".join(used.keys())
    response.headers["x-vipertls-used-cookies"] = json.dumps(used, separators=(",", ":"))


def _build_ch_hints(preset: BrowserPreset, critical_ch_header: str) -> dict[str, str]:
    """
    Build Client Hint headers for a Cloudflare critical-ch retry.
    When CF returns critical-ch, a real browser retries with the listed headers.
    """
    requested = {h.strip().lower() for h in critical_ch_header.split(",")}
    hints: dict[str, str] = {}

    name = preset.name.lower()
    if not any(b in name for b in _CHROMIUM_NAMES):
        return hints

    ua = preset.user_agent
    m = re.search(r"Chrome/([\d.]+)", ua)
    full_version = m.group(1) if m else "124.0.6367.60"
    major = full_version.split(".")[0]

    sec_ch_ua = preset.default_headers.get("sec-ch-ua", "")
    full_version_list = re.sub(
        r';v="(\d+)"',
        lambda x: f';v="{full_version}"' if x.group(1) == major else f';v="{x.group(1)}.0.0.0"',
        sec_ch_ua,
    )

    ch_map: dict[str, str] = {
        "sec-ch-ua":                  sec_ch_ua,
        "sec-ch-ua-mobile":           preset.default_headers.get("sec-ch-ua-mobile", "?0"),
        "sec-ch-ua-platform":         preset.default_headers.get("sec-ch-ua-platform", '"Windows"'),
        "sec-ch-ua-full-version":     f'"{full_version}"',
        "sec-ch-ua-full-version-list": full_version_list,
        "sec-ch-ua-arch":             '"x86"',
        "sec-ch-ua-bitness":          '"64"',
        "sec-ch-ua-model":            '""',
        "sec-ch-ua-platform-version": '"10.0.0"',
    }

    for hint in requested:
        if hint in ch_map:
            hints[hint] = ch_map[hint]

    return hints


def _inject_extended_ch(preset: BrowserPreset, headers: dict[str, str]) -> None:
    """
    Proactively inject extended Client Hint headers for Chromium-based presets.
    Chrome sends these automatically on sites where Accept-CH has been cached
    (which includes all Cloudflare-protected sites after the first visit).
    Sending them upfront avoids the critical-ch challenge entirely.
    """
    ua = preset.user_agent
    m = re.search(r"Chrome/([\d.]+)", ua)
    full_version = m.group(1) if m else "124.0.6367.60"
    major = full_version.split(".")[0]

    sec_ch_ua = preset.default_headers.get("sec-ch-ua", headers.get("sec-ch-ua", ""))
    full_version_list = re.sub(
        r';v="(\d+)"',
        lambda x: f';v="{full_version}"' if x.group(1) == major else f';v="{x.group(1)}.0.0.0"',
        sec_ch_ua,
    )

    extended = {
        "sec-ch-ua-full-version":      f'"{full_version}"',
        "sec-ch-ua-full-version-list": full_version_list,
        "sec-ch-ua-arch":              '"x86"',
        "sec-ch-ua-model":             '""',
        "sec-ch-ua-platform-version":  '"10.0.0"',
        "sec-ch-ua-bitness":           '"64"',
    }
    for k, v in extended.items():
        if k not in headers:
            headers[k] = v


def _merge_headers(preset: BrowserPreset, overrides: dict[str, str]) -> dict[str, str]:
    merged = dict(preset.default_headers)
    merged["user-agent"] = preset.user_agent
    for k, v in overrides.items():
        merged[k.lower()] = v
    if any(b in preset.name.lower() for b in _CHROMIUM_NAMES):
        _inject_extended_ch(preset, merged)
    return merged


def _resolve_redirect(base_url: str, location: str) -> str:
    if location.startswith("http://") or location.startswith("https://"):
        return location
    return urljoin(base_url, location)


async def _solve_cloudflare_challenge(
    response: ViperResponse,
    method: str,
    url: str,
    preset: BrowserPreset,
    debug=None,
) -> Optional[ViperResponse]:
    if method.upper() not in {"GET", "HEAD"}:
        return None

    try:
        from .solver.browser import get_solver, is_challenge
    except Exception:
        return None

    text = response.text
    if not is_challenge(response.status_code, text, response.headers):
        return None

    if debug:
        debug("Detected JS challenge")
        debug("Solving challenge")
    response.headers["x-vipertls-solved-by"] = "solving"
    
    solver = await get_solver()
    try:
        solved = await solver.solve(url=url, user_agent=preset.user_agent, preset=preset.name)
    except Exception:
        if debug:
            debug("Challenge solve failed")
        return None

    if debug:
        if solved.method in {"browser", "cache"} and (solved.status or 0) < 400:
            debug(f"Challenge solved via {solved.method}")
        else:
            debug("Challenge solve failed")

    headers = {
        "content-type": "text/html; charset=utf-8",
        "x-vipertls-solved-by": solved.method,
    }
    set_cookies = [f"{k}={v}" for k, v in solved.cookies.items()]

    return ViperResponse(
        status_code=solved.status or 200,
        headers=headers,
        content=solved.html.encode("utf-8", errors="replace"),
        url=solved.url,
        http_version="HTTP/2",
        set_cookies=set_cookies,
    )


class AsyncClient:
    """Async ViperTLS client.

    Use this client when you want browser-like TLS fingerprints with optional
    browser challenge fallback. Typical usage:

        async with vipertls.AsyncClient(impersonate="edge_133") as client:
            response = await client.get("https://example.com")
    """

    def __init__(
        self,
        impersonate: str = "chrome_124",
        ja3: Optional[str] = None,
        proxy: Optional[str] = None,
        timeout: int = _DEFAULT_TIMEOUT,
        verify: bool = True,
        follow_redirects: bool = True,
        use_solver: bool = True,
        debug_messages: bool = _DEBUG_MESSAGES_DEFAULT,
    ) -> None:
        self._preset: BrowserPreset = resolve_preset(impersonate)
        self._ja3: Optional[JA3Spec] = parse_ja3(ja3) if ja3 else None
        self._proxy = proxy
        self._timeout = timeout
        self._verify = verify
        self._follow_redirects = follow_redirects
        self._use_solver = use_solver
        self._debug_messages = debug_messages

    def _debug(self, message: str) -> None:
        if self._debug_messages:
            print(f"[ViperTLS] {message}", flush=True)

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        body: Optional[bytes] = None,
        **kwargs,
    ) -> ViperResponse:
        merged_headers = _merge_headers(self._preset, headers or {})
        current_url = url
        redirects = 0
        ch_retried = False

        from .solver.browser import get_cache
        cache = get_cache()
        domain = urlparse(url).netloc
        cached_data = cache.get(domain, self._preset.name)
        
        cache_hit = False
        if cached_data:
            cookies_list, ua, hints = cached_data
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies_list)
            if "cookie" in merged_headers:
                merged_headers["cookie"] += f"; {cookie_str}"
            else:
                merged_headers["cookie"] = cookie_str
            
            if ua:
                merged_headers["user-agent"] = ua
            if hints:
                merged_headers.update(hints)
                
            cache_hit = True
            self._debug("Loaded cached cookies")

        while True:
            response = await self._send_single(method, current_url, merged_headers, body)
            
            if cache_hit and response.status_code == 403:
                from .solver.browser import is_challenge
                if is_challenge(response.status_code, response.text):
                    self._debug("Cached cookies expired, retrying fresh")
                    cache.clear(domain, self._preset.name)
                    cache_hit = False
                    merged_headers.pop("cookie", None)
                    continue

            if cache_hit:
                response.headers["x-vipertls-solved-by"] = "cache"
                self._debug("Served using cached clearance")

            if (
                not ch_retried
                and "critical-ch" in response.headers
                and response.status_code in (403, 200)
            ):
                extra = _build_ch_hints(self._preset, response.headers["critical-ch"])
                if extra:
                    merged_headers.update(extra)
                    if response.set_cookies:
                        cookie_pairs = []
                        for sc in response.set_cookies:
                            name_val = sc.split(";")[0].strip()
                            if "=" in name_val:
                                cookie_pairs.append(name_val)
                        if cookie_pairs:
                            existing = merged_headers.get("cookie", "")
                            new_cookies = "; ".join(cookie_pairs)
                            merged_headers["cookie"] = (
                                existing + "; " + new_cookies if existing else new_cookies
                            )
                    ch_retried = True
                    continue

            if (
                self._follow_redirects
                and response.status_code in _REDIRECT_STATUSES
                and "location" in response.headers
                and redirects < _MAX_REDIRECTS
            ):
                location = response.headers["location"]
                current_url = _resolve_redirect(current_url, location)

                if response.status_code == 303:
                    method = "GET"
                    body = None

                redirects += 1
                continue

            if self._use_solver:
                solved = await _solve_cloudflare_challenge(
                    response=response,
                    method=method,
                    url=current_url,
                    preset=self._preset,
                    debug=self._debug,
                )
                if solved is not None:
                    _attach_used_cookie_headers(solved, merged_headers)
                    return solved

            if response.status_code < 400:
                self._debug("TLS request passed")
            else:
                self._debug(f"TLS request returned {response.status_code}")

            _attach_used_cookie_headers(response, merged_headers)
            return response

    async def _send_single(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Optional[bytes],
    ) -> ViperResponse:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        query = parsed.query
        scheme = parsed.scheme

        loop = asyncio.get_event_loop()

        try:
            response = await loop.run_in_executor(
                None,
                lambda: self._send_blocking(method, host, port, scheme, path, query, headers, body, url),
            )
        except TimeoutError as exc:
            raise ViperTimeoutError(f"Request timed out: {url}") from exc
        except (ssl.SSLError, socket.error, OSError) as exc:
            raise ViperConnectionError(f"Connection failed: {exc}") from exc

        return response

    def _send_blocking(
        self,
        method: str,
        host: str,
        port: int,
        scheme: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body: Optional[bytes],
        target_url: str,
    ) -> ViperResponse:
        socket.setdefaulttimeout(self._timeout)

        if self._proxy:
            raw_sock = open_tunnel(host, port, self._proxy)
        else:
            raw_sock = None

        if scheme == "https":
            ssl_sock = open_tls_connection(
                host=host,
                port=port,
                preset=self._preset,
                ja3=self._ja3,
                proxy_sock=raw_sock,
                timeout=self._timeout,
                verify=self._verify,
            )
            negotiated = ssl_sock.selected_alpn_protocol()

            if negotiated == "h2":
                conn = HTTP2Connection(ssl_sock, self._preset)
                try:
                    return conn.request(
                        method=method,
                        host=host,
                        scheme=scheme,
                        path=path,
                        query=query,
                        headers=headers,
                        body=body,
                        target_url=target_url,
                    )
                finally:
                    conn.close()
            else:
                try:
                    return http1_request(
                        ssl_sock=ssl_sock,
                        method=method,
                        host=host,
                        path=path,
                        query=query,
                        headers=headers,
                        preset=self._preset,
                        body=body,
                        target_url=target_url,
                    )
                finally:
                    try:
                        ssl_sock.close()
                    except Exception:
                        pass
        else:
            plain_sock = raw_sock or socket.create_connection((host, port), timeout=self._timeout)
            try:
                return http1_request(
                    ssl_sock=plain_sock,
                    method=method,
                    host=host,
                    path=path,
                    query=query,
                    headers=headers,
                    preset=self._preset,
                    body=body,
                    target_url=target_url,
                )
            finally:
                try:
                    plain_sock.close()
                except Exception:
                    pass

    async def get(self, url: str, headers: Optional[dict[str, str]] = None, **kw) -> ViperResponse:
        return await self.request("GET", url, headers=headers, **kw)

    async def post(self, url: str, headers: Optional[dict[str, str]] = None, body: Optional[bytes] = None, **kw) -> ViperResponse:
        return await self.request("POST", url, headers=headers, body=body, **kw)

    async def put(self, url: str, headers: Optional[dict[str, str]] = None, body: Optional[bytes] = None, **kw) -> ViperResponse:
        return await self.request("PUT", url, headers=headers, body=body, **kw)

    async def patch(self, url: str, headers: Optional[dict[str, str]] = None, body: Optional[bytes] = None, **kw) -> ViperResponse:
        return await self.request("PATCH", url, headers=headers, body=body, **kw)

    async def delete(self, url: str, headers: Optional[dict[str, str]] = None, **kw) -> ViperResponse:
        return await self.request("DELETE", url, headers=headers, **kw)

    async def head(self, url: str, headers: Optional[dict[str, str]] = None, **kw) -> ViperResponse:
        return await self.request("HEAD", url, headers=headers, **kw)

    async def __aenter__(self) -> "AsyncClient":
        return self

    async def __aexit__(self, *_) -> None:
        pass


class Client:
    """Synchronous wrapper around ``AsyncClient``.

    This is useful when you do not want to manage an asyncio event loop
    yourself.
    """

    def __init__(self, **kwargs) -> None:
        self._async_client = AsyncClient(**kwargs)

    def _run(self, coro):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(asyncio.run, coro)
                    return future.result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    def request(self, method: str, url: str, **kwargs) -> ViperResponse:
        return self._run(self._async_client.request(method, url, **kwargs))

    def get(self, url: str, **kwargs) -> ViperResponse:
        return self._run(self._async_client.get(url, **kwargs))

    def post(self, url: str, **kwargs) -> ViperResponse:
        return self._run(self._async_client.post(url, **kwargs))

    def put(self, url: str, **kwargs) -> ViperResponse:
        return self._run(self._async_client.put(url, **kwargs))

    def patch(self, url: str, **kwargs) -> ViperResponse:
        return self._run(self._async_client.patch(url, **kwargs))

    def delete(self, url: str, **kwargs) -> ViperResponse:
        return self._run(self._async_client.delete(url, **kwargs))

    def head(self, url: str, **kwargs) -> ViperResponse:
        return self._run(self._async_client.head(url, **kwargs))
