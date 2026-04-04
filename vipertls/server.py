import json
from typing import Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import Response as FastAPIResponse

from .client import AsyncClient

app = FastAPI(title="ViperTLS", docs_url=None, redoc_url=None)

_VIPER_PREFIX = "x-viper-"

_ALWAYS_STRIP = frozenset([
    "host", "content-length", "transfer-encoding", "connection",
    "proxy-connection", "keep-alive", "upgrade", "content-type",
    "expect", "te", "via", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "x-real-ip", "forwarded", "pragma",
])

_PRESET_OWNED = frozenset([
    "user-agent", "accept", "accept-language", "accept-encoding",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-ch-ua-full-version", "sec-ch-ua-full-version-list",
    "sec-ch-ua-arch", "sec-ch-ua-model", "sec-ch-ua-platform-version",
    "sec-ch-ua-bitness",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
    "cache-control", "upgrade-insecure-requests", "priority",
])

_PASSTHROUGH_ALLOWLIST = frozenset([
    "cookie", "authorization", "referer", "origin",
    "if-none-match", "if-modified-since", "range",
])


def _parse_received_cookies(set_cookies: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in set_cookies:
        first = item.split(";", 1)[0].strip()
        if "=" not in first:
            continue
        name, value = first.split("=", 1)
        if name:
            parsed[name] = value
    return parsed


def _extract_viper_config(request: Request) -> dict:
    config = {}
    for key, value in request.headers.items():
        if key.lower().startswith(_VIPER_PREFIX):
            field = key[len(_VIPER_PREFIX):].lower().replace("-", "_")
            config[field] = value
    return config


def _extract_forward_headers(request: Request, impersonate: bool) -> dict[str, str]:
    headers = {}
    for key, value in request.headers.items():
        k_lower = key.lower()
        if k_lower.startswith(_VIPER_PREFIX):
            continue
        if k_lower in _ALWAYS_STRIP:
            continue
        if impersonate:
            if k_lower in _PRESET_OWNED:
                continue
            if k_lower not in _PASSTHROUGH_ALLOWLIST and not k_lower.startswith("x-"):
                continue
        headers[k_lower] = value
    return headers


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def proxy_handler(request: Request, path: str = "") -> FastAPIResponse:
    config = _extract_viper_config(request)

    target_url = config.get("url")
    if not target_url:
        return FastAPIResponse(
            content=b'{"error": "X-Viper-URL header is required"}',
            status_code=400,
            media_type="application/json",
        )
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    method = config.get("method", request.method).upper()
    impersonate = config.get("impersonate", "chrome_124").strip().strip('"').strip("'")
    proxy = config.get("proxy")
    timeout = int(config.get("timeout", 30))
    ja3_override = config.get("ja3")
    no_redirect = config.get("no_redirect", "false").lower() in ("true", "1", "yes")
    skip_verify = config.get("skip_verify", "false").lower() in ("true", "1", "yes")
    force_http1 = config.get("force_http1", "false").lower() in ("true", "1", "yes")

    forward_headers = _extract_forward_headers(request, impersonate=bool(impersonate))

    extra_headers_raw = config.get("headers")
    if extra_headers_raw:
        try:
            extra = json.loads(extra_headers_raw)
            forward_headers.update({k.lower(): v for k, v in extra.items()})
        except (json.JSONDecodeError, AttributeError):
            pass

    body_override = config.get("body")
    if body_override is not None:
        body = body_override.encode() if isinstance(body_override, str) else body_override
    else:
        raw_body = await request.body()
        body = raw_body if raw_body else None

    if force_http1 and "x-viper-force-http1" not in impersonate:
        preset_name = impersonate
    else:
        preset_name = impersonate

    try:
        async with AsyncClient(
            impersonate=preset_name,
            ja3=ja3_override,
            proxy=proxy,
            timeout=timeout,
            verify=not skip_verify,
            follow_redirects=not no_redirect,
        ) as client:
            response = await client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                body=body,
            )
    except Exception as exc:
        return FastAPIResponse(
            content=json.dumps({"error": str(exc)}).encode(),
            status_code=502,
            media_type="application/json",
        )

    excluded_response_headers = frozenset([
        "content-encoding", "transfer-encoding", "content-length", "connection",
    ])

    response_headers = {
        k: v for k, v in response.headers.items()
        if k.lower() not in excluded_response_headers
    }

    response_headers["x-viper-http-version"] = response.http_version
    if response.set_cookies:
        received = _parse_received_cookies(response.set_cookies)
        response_headers["x-viper-received-cookie-names"] = ",".join(received.keys())
        response_headers["x-viper-received-cookies"] = json.dumps(
            received,
            separators=(",", ":"),
        )

    outbound = FastAPIResponse(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers,
        media_type=response.headers.get("content-type"),
    )
    for cookie in response.set_cookies:
        outbound.raw_headers.append((b"set-cookie", cookie.encode("latin-1", errors="ignore")))
    return outbound
