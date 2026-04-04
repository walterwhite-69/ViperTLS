<div align="center">

```
 ██╗   ██╗██╗██████╗ ███████╗██████╗ ████████╗██╗     ███████╗
 ██║   ██║██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║     ██╔════╝
 ██║   ██║██║██████╔╝█████╗  ██████╔╝   ██║   ██║     ███████╗
 ╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗   ██║   ██║     ╚════██║
  ╚████╔╝ ██║██║     ███████╗██║  ██║   ██║   ███████╗███████║
   ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝
```

**Pure Python TLS fingerprint spoofing with browser challenge fallback. No curl_cffi. No Go binary. No excuses.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![HTTP/2](https://img.shields.io/badge/HTTP%2F2-✓-brightgreen?style=flat-square)](https://http2.github.io)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-bypassed-orange?style=flat-square&logo=cloudflare&logoColor=white)](https://cloudflare.com)
[![Bugs](https://img.shields.io/badge/bugs-probably%20some-red?style=flat-square)](https://github.com)
[![Vibes](https://img.shields.io/badge/vibes-immaculate-purple?style=flat-square)](https://github.com)

</div>

---

## What is this?

ViperTLS is a **pure Python HTTP client** that makes your requests look like they're coming from a real browser at the TLS level. It spoofs:

- **JA3 / JA4** — The TLS ClientHello fingerprint (cipher suites, curves, extensions — all in the exact order a real browser sends them)
- **HTTP/2 SETTINGS frames** — The window sizes, header table sizes, and frame ordering that real browsers negotiate
- **HTTP/2 pseudo-header order** — Chrome sends `:method :authority :scheme :path`. Firefox does `:method :path :authority :scheme`. Yes, this actually matters.
- **HTTP header ordering** — Because Cloudflare reads your headers like a suspicious bouncer reading a fake ID

The result: your Python script walks up to Cloudflare's velvet rope looking like Chrome 124 in a suit, and gets waved straight through.

When TLS fingerprinting is not enough and a site still throws a browser challenge, ViperTLS can escalate into a real browser solve, capture the useful cookies, and reuse them on later requests. So the practical request flow is:

- **TLS** when the site is easy
- **Browser** when the site needs a challenge solve
- **Cache** when the site was already solved and the clearance cookies are still valid

Think of it as [CycleTLS](https://github.com/Danny-Dasilva/CycleTLS) — but in pure Python, without spawning a Go subprocess, without curl_cffi, and without any of that compiled-binary nonsense.

> ⚠️ **Fair warning:** There are probably bugs. TLS fingerprinting is a moving target, Cloudflare updates its detection constantly, and we wrote this in Python instead of something sensible. Use in production at your own risk. You've been warned. We take no responsibility. Good luck. ❤️

---

## How It Works

Cloudflare and other bot-detection systems don't just look at your User-Agent. They analyze the **actual bytes** of your TLS handshake and HTTP/2 connection setup. Every library has a fingerprint:

```
python-requests  →  JA3: 3b5074b1b5d032e5620f69f9159c1ab7  →  BLOCKED
urllib3          →  JA3: b32309a26951912be7dba376398abc3b  →  BLOCKED
Chrome 124       →  JA3: 03a48f04706e1bd47024208459fbfe91  →  ✓ ALLOWED
ViperTLS         →  JA3: looks like Chrome 124             →  ✓ ALLOWED
```

ViperTLS gets there by:

1. Using `ssl.SSLContext.set_ciphers()` to set TLS 1.2 cipher order (OpenSSL preserves it exactly)
2. Using `ctypes` to call `SSL_CTX_set_ciphersuites()` directly on the `SSL_CTX*` pointer extracted from CPython internals — for TLS 1.3 cipher ordering
3. Using `ctypes` → `SSL_CTX_set1_groups_list()` for elliptic curve ordering
4. Using the [`h2`](https://python-hyper.org/projects/h2/) library with custom SETTINGS injected before the connection preface
5. Sending HTTP headers in the exact order browsers actually send them

No binary dependencies. No subprocess bridge. Just Python, ctypes, and a deep understanding of how OpenSSL works internally. Spooky? A little. Does it work? Yes.

---

## Installation

```bash
pip install vipertls
vipertls install-browsers
```

For a source checkout:

```bash
git clone https://github.com/walterwhite-69/ViperTLS
cd vipertls
pip install -e .
python install_browsers.py
```

**Quick commands:**
```
vipertls --help
vipertls
vipertls paths
vipertls serve --host 127.0.0.1 --port 5000
```

ViperTLS keeps Playwright browsers, solver cookies, and other writable runtime files in one ViperTLS-managed home directory. In a source checkout that is the repo root. In a pip install it falls back to a per-user writable `vipertls` directory automatically.

If the solver cannot find a local Chrome or Edge install, it can bootstrap Playwright Chromium into that same ViperTLS home automatically on first browser solve. You can also do it explicitly with `vipertls --install-browsers`.

When you use ViperTLS from your own Python script as a module, it prefers a script-local `.vipertls` folder next to that script, so solver cookies and browser assets stay bundled with the scraper project instead of getting mixed into one global cache.

Python 3.10+ required. Works on Windows and Linux. macOS may work, but the browser-solver path is less tested.

---

## Quick Start

```python
import asyncio
import vipertls

async def main():
    async with vipertls.AsyncClient(impersonate="edge_133", debug_messages=True) as client:
        response = await client.get("https://www.crunchyroll.com/")
        print(response.status_code)  # 200, not 403
        print(response.solved_by)    # tls / browser / cache
        print(response.solve_info)

asyncio.run(main())
```

That's it. If you were using `requests` before, you were getting 403'd and quietly crying about it. Now you're not.

---

## Ways to Use ViperTLS

ViperTLS can be used in three main ways, depending on what kind of integration you need:

### 1. As a Python module

Best when you control the Python code directly and want the cleanest API.

Use this when:

- you're writing your own Python scraper/client
- you want direct access to `ViperResponse`
- you want to inspect `solved_by`, `cookies_received`, `cookies_used`, and `solve_info`

Typical shape:

```python
import asyncio
import vipertls

async def main():
    async with vipertls.AsyncClient(impersonate="edge_133") as client:
        response = await client.get("https://example.com")
        print(response.status_code)
        print(response.solved_by)
        print(response.solve_info)

asyncio.run(main())
```

### 2. As a local proxy server

Best when the thing making requests cannot import Python code directly, but can send HTTP requests to `localhost`.

Use this when:

- you're integrating with OpenBullet-style tools
- you're routing requests from another app/language
- you want to control target URL and preset through headers

Typical shape:

```bash
vipertls serve --host 127.0.0.1 --port 8080
```

Then:

```bash
curl http://127.0.0.1:8080 \
  -H "X-Viper-URL: https://example.com" \
  -H "X-Viper-Impersonate: edge_133"
```

### 3. As a standalone browser solver API

Best when you only want the browser-solver side exposed as an API service.

Use this when:

- you want HTML + cookies from a solved challenge page
- you want to call the solver separately from the full client/proxy
- you want a browser-solve worker for another service

Typical shape:

```bash
python -m vipertls.solver --port 8081
```

Then:

```bash
curl -X POST http://127.0.0.1:8081/solve \
  -H "content-type: application/json" \
  -d "{\"url\":\"https://example.com\",\"preset\":\"edge_133\",\"timeout\":30}"
```

### Which one should you use?

- use the **Python module** if you're already in Python
- use the **local proxy server** if another tool can only talk HTTP
- use the **standalone solver API** if you only need challenge solving as a service

---

## Usage

### Async Client

The primary interface. Fully async, built on `asyncio`.

```python
import asyncio
import vipertls

async def main():
    async with vipertls.AsyncClient(
        impersonate="edge_133",     # best default when browser solving matters
        proxy="socks5://user:pass@host:1080",  # optional proxy
        timeout=30,                 # seconds
        verify=True,                # TLS cert verification
        follow_redirects=True,
        debug_messages=True,
    ) as client:

        # GET
        r = await client.get("https://example.com/")
        print(r.status_code, r.http_version, len(r.content))
        print(r.solved_by, r.from_cache)
        print(r.cookies_received)
        print(r.cookies_used)

        # POST with JSON body
        import json
        r = await client.post(
            "https://api.example.com/login",
            headers={"content-type": "application/json", "accept": "application/json"},
            body=json.dumps({"username": "me", "password": "hunter2"}).encode(),
        )
        data = r.json()

        # Custom JA3 override (if you want to be specific)
        custom = vipertls.AsyncClient(
            impersonate="chrome_124",
            ja3="771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-27-65281-0-23-35-13-16-11-5-10-51-45-43-17513-21,29-23-24,0",
        )

asyncio.run(main())
```

### Solver States

When you inspect a response, `r.solved_by` tells you how ViperTLS got through:

- `tls` — direct request worked immediately
- `browser` — direct request hit a challenge and the browser solver resolved it
- `cache` — an earlier browser solve already produced valid cookies, so ViperTLS reused them

The extra response metadata is available directly on the Python object:

```python
print(r.solved_by)
print(r.from_cache)
print(r.cookies_received)
print(r.cookies_used)
print(r.solve_info)
```

### Sync Client

For when asyncio gives you anxiety.

```python
import vipertls

client = vipertls.Client(impersonate="firefox_127", timeout=30)

r = client.get("https://www.tempmail.la/")
print(r.status_code)   # 200
print(r.text[:500])

r2 = client.post(
    "https://api.example.com/data",
    headers={"content-type": "application/json"},
    body=b'{"hello": "world"}',
)
print(r2.json())
```

### Response Object

```python
r = await client.get("https://example.com/api/data")

r.status_code    # int  — 200, 403, 429, etc.
r.ok             # bool — True if status < 400
r.solved_by      # str  — "tls", "browser", or "cache"
r.from_cache     # bool — True when cached cookies were reused
r.headers        # dict — all lowercase keys
r.content        # bytes — decompressed (gzip / br / deflate handled automatically)
r.text           # str  — auto-detected encoding
r.json()         # any  — parsed JSON, raises on invalid
r.http_version   # str  — "HTTP/2" or "HTTP/1.1"
r.url            # str  — final URL after redirects
r.cookies_received  # dict — cookies returned by the site on that response
r.cookies_used      # dict — cookies ViperTLS sent internally
r.solve_info        # dict — grouped ViperTLS metadata
r.raise_for_status()  # raises ViperHTTPError if status >= 400
```

### Runtime Helpers

The top-level module also exposes a few convenience helpers:

```python
import vipertls

print(vipertls.get_runtime_paths())
vipertls.clear_solver_cache()
vipertls.clear_solver_cache(domain="1337x.to")
vipertls.clear_solver_cache(domain="1337x.to", preset="edge_133")
```

---

## Live Dashboard (TUI)

A beautiful real-time request monitor built with [`rich`](https://github.com/Textualize/rich). Swap `AsyncClient` for `ViperDashboard` and watch the requests roll in.

```python
import asyncio
from vipertls import ViperDashboard

async def main():
    async with ViperDashboard(impersonate="chrome_124", timeout=30) as dash:
        # Fire requests — the dashboard updates live as each one completes
        results = await asyncio.gather(
            dash.get("https://www.miruro.to/"),
            dash.get("https://www.crunchyroll.com/"),
            dash.get("https://tls.peet.ws/api/all", headers={"accept": "application/json"}),
            dash.post("https://api.example.com/auth", body=b'{"user":"me"}'),
        )

asyncio.run(main())
```

Run the included demo to see it in action:

```bash
python demo.py
```

The dashboard shows live spinners for in-flight requests, color-coded status codes, HTTP version, response size, timing, and preset used — all updating in real time.

```
╭─────────────────────────────────────────────────────────────────╮
│  ⚡ V I P E R TLS  v0.1.1   ·   Live Request Monitor           │
╰─────────────────────────────────────────────────────────────────╯
  ◉ 9 requests   ✓ 7 ok   ✗ 2 failed   ⏱ 312ms avg   ↓ 187.4 KB

  Time      Method   URL                                 Status  Proto    Size      Time     Preset
 ─────────────────────────────────────────────────────────────────────────────────────────────────
  14:22:09  GET      miruro.to/                            200   HTTP/2   20.3 KB   287ms   chrome_124
  14:22:09  GET      crunchyroll.com/                      200   HTTP/2   15.0 KB   401ms   chrome_124
  14:22:08  GET      tls.peet.ws/api/all                   200   HTTP/2   8.2 KB    198ms   chrome_124
  14:22:08  POST     api.example.com/auth                  401   HTTP/2   185 B     134ms   chrome_124
```

---

## Server Mode

Run ViperTLS as a local HTTP proxy server. Make requests to `localhost` with `X-Viper-*` control headers — useful for integrating with tools that can't use the Python library directly.

```bash
# Start the server
vipertls serve --host 127.0.0.1 --port 8080

# Or with more workers for concurrent load
vipertls serve --host 0.0.0.0 --port 8080 --workers 4
```

Then make requests to it from anywhere:

```bash
curl -s http://localhost:8080 \
  -H "X-Viper-URL: https://www.crunchyroll.com/" \
  -H "X-Viper-Impersonate: chrome_124" \
  | head -c 500
```

```python
import requests  # ironic

r = requests.get("http://localhost:8080", headers={
    "X-Viper-URL": "https://www.miruro.to/",
    "X-Viper-Impersonate": "chrome_124",
    "X-Viper-Proxy": "socks5://user:pass@proxy:1080",
})
print(r.status_code)
```

### Control Headers

| Header | Description | Example |
|--------|-------------|---------|
| `X-Viper-URL` | **Required.** Target URL to request | `https://www.crunchyroll.com/api/...` |
| `X-Viper-Method` | HTTP method (default: GET) | `POST` |
| `X-Viper-Impersonate` | Browser preset name | `chrome_124`, `firefox_127`, `safari_17` |
| `X-Viper-Proxy` | Proxy URL | `socks5://user:pass@host:1080` |
| `X-Viper-Timeout` | Request timeout in seconds | `30` |
| `X-Viper-JA3` | Override JA3 fingerprint string | `771,4865-4866-4867,...` |
| `X-Viper-No-Redirect` | Disable redirect following | `true` |
| `X-Viper-Skip-Verify` | Skip TLS certificate verification | `true` |
| `X-Viper-Force-HTTP1` | Force HTTP/1.1 even if server supports H2 | `true` |
| `X-Viper-Body` | Request body as string | `{"key":"value"}` |
| `X-Viper-Headers` | Extra headers as JSON string | `{"authorization":"Bearer ..."}` |

All other non-`X-Viper-*` headers you send are forwarded to the target. The response comes back with the target's real status code, headers, and body.

The proxy response also includes ViperTLS-specific helper headers such as:

- `X-ViperTLS-Solved-By`
- `X-Viper-HTTP-Version`
- `X-Viper-Received-Cookies`
- `X-ViperTLS-Used-Cookies`

---

## Standalone Solver API

If you want only the browser-solver exposed as a small API service, run the solver directly:

```bash
python -m vipertls.solver --host 127.0.0.1 --port 8081
```

Available endpoints:

- `POST /solve` — solve one URL and return HTML, cookies, user-agent, method, and elapsed time
- `DELETE /cookies/{domain}` — clear solver cookies for one domain
- `DELETE /cookies` — clear all solver cookies
- `GET /health` — health check

Example request:

```bash
curl -X POST http://127.0.0.1:8081/solve \
  -H "content-type: application/json" \
  -d "{\"url\":\"https://nopecha.com/demo/cloudflare\",\"preset\":\"edge_133\",\"timeout\":30}"
```

Example response shape:

```json
{
  "url": "https://example.com",
  "status": 200,
  "html": "<!doctype html>...",
  "cookies": {
    "cf_clearance": "..."
  },
  "user_agent": "Mozilla/5.0 ...",
  "method": "browser",
  "elapsed_ms": 8421.7
}
```

---

## Browser Presets

| Preset | Alias | TLS Version | Ciphers | Curves | HTTP/2 Window | Pseudo-header order |
|--------|-------|-------------|---------|--------|---------------|---------------------|
| `chrome_120` | — | TLS 1.3 | 16 | X25519, P-256, P-384 | 15,663,105 | `:method :authority :scheme :path` |
| `chrome_124` | — | TLS 1.3 | 16 | X25519, P-256, P-384 | 15,663,105 | `:method :authority :scheme :path` |
| `chrome_131` | `chrome` | TLS 1.3 | 16 | X25519, P-256, P-384 | 15,663,105 | `:method :authority :scheme :path` |
| `firefox_120` | — | TLS 1.3 | 18 | X25519, P-256, P-384, P-521, ffdhe2048, ffdhe3072 | 12,517,377 | `:method :path :authority :scheme` |
| `firefox_127` | `firefox` | TLS 1.3 | 18 | X25519, P-256, P-384, P-521, ffdhe2048, ffdhe3072 | 12,517,377 | `:method :path :authority :scheme` |
| `safari_17` | `safari` | TLS 1.3 | 20 | X25519, P-256, P-384, P-521 | 15,663,105 | `:method :authority :scheme :path` |

Aliases: `chrome` → `chrome_131`, `firefox` → `firefox_127`, `safari` → `safari_17`

```python
# All valid
AsyncClient(impersonate="chrome")
AsyncClient(impersonate="chrome_124")
AsyncClient(impersonate="firefox_127")
AsyncClient(impersonate="safari_17")
```

### Recommended Presets

- `edge_133` — best default when you care about the browser-solver path
- `chrome_*` — good default for TLS-first traffic
- `firefox_*` — useful when you specifically want Firefox-like TLS and HTTP/2 behavior

---

## Proxy Support

ViperTLS supports all common proxy types. The tunnel is established first, then TLS is wrapped over it — so the fingerprint is still fully intact through the proxy.

```python
# SOCKS5 (with auth)
AsyncClient(proxy="socks5://username:password@proxy.host:1080")

# SOCKS5 with remote DNS (anonymizes DNS leaks)
AsyncClient(proxy="socks5h://username:password@proxy.host:1080")

# SOCKS4
AsyncClient(proxy="socks4://proxy.host:1080")

# HTTP CONNECT proxy
AsyncClient(proxy="http://username:password@proxy.host:8080")

# Short HTTP proxy formats
AsyncClient(proxy="127.0.0.1:8080")
AsyncClient(proxy="127.0.0.1:8080:user:pass")
```

If you pass `ip:port` or `ip:port:user:pass`, ViperTLS treats it as an HTTP CONNECT proxy automatically. For SOCKS proxies, keep using the explicit `socks4://`, `socks5://`, or `socks5h://` form.

---

## Error Handling

```python
from vipertls import AsyncClient, ViperHTTPError, ViperConnectionError, ViperTimeoutError

async with AsyncClient(impersonate="chrome_124") as client:
    try:
        r = await client.get("https://example.com/")
        r.raise_for_status()
        print(r.json())
    except ViperHTTPError as e:
        print(f"Server returned {e.status_code}")
    except ViperTimeoutError:
        print("Timed out — the server is either slow or dead")
    except ViperConnectionError as e:
        print(f"Could not connect: {e}")
```

---

## Hosting

Yes, it's hostable. It's a FastAPI server — if it runs Python, it runs ViperTLS.

### Railway / Render

A `Procfile` is included:

```
web: python -m vipertls serve --host 0.0.0.0 --port $PORT
```

Push to GitHub, connect to Railway or Render, done. Both platforms pick up `$PORT` automatically.

### Docker

A `Dockerfile` is included:

```bash
docker build -t vipertls .
docker run -p 8080:8080 vipertls

# With env variable port
docker run -e PORT=9000 -p 9000:9000 vipertls
```

### Docker Compose

```yaml
version: "3.9"
services:
  vipertls:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
    restart: unless-stopped
```

### VPS / Bare Metal

```bash
# Install
git clone https://github.com/walterwhite-69/ViperTLS && cd ViperTLS
pip install -r requirements.txt

# Run
python -m vipertls serve --host 0.0.0.0 --port 8080 --workers 4

# Or with systemd / screen / tmux / whatever keeps you sane
screen -S vipertls python -m vipertls serve --host 0.0.0.0 --port 8080
```

### Pterodactyl

Use the generic Python egg (or any egg that gives you a shell). Startup command:

```
python -m vipertls serve --host 0.0.0.0 --port {{SERVER_PORT}}
```

Set `SERVER_PORT` as an egg variable. That's it.

### ⚠️ Important for Hosted Deployments

- TLS fingerprinting requires direct TCP connections. **Do not put ViperTLS behind another HTTP reverse proxy** (nginx, Caddy, etc.) — proxy termination will strip the TLS layer and your fingerprint data becomes irrelevant. Put it behind a TCP passthrough (stream proxy) instead, or expose it directly.
- Some cloud providers do outbound connection filtering. If you're getting timeouts hitting specific sites from hosted environments, that's likely the issue — not ViperTLS.

---

## Architecture

```
AsyncClient.get("https://target.com/")
         │
         ▼
  resolve_preset("chrome_124")
         │
         ▼
  parse_ja3(preset.ja3) → JA3Spec
  (cipher IDs → OpenSSL names, curve IDs → group names)
         │
         ├─── [proxy?] open_tunnel(host, 443, proxy_url)
         │              └─ HTTP CONNECT / SOCKS4 / SOCKS5
         │
         ▼
  build_ssl_context(preset, ja3)
         ├─ ctx.set_ciphers(tls12_ciphers)         ← order preserved by OpenSSL
         ├─ ctypes → SSL_CTX_set_ciphersuites()    ← TLS 1.3 cipher order
         ├─ ctypes → SSL_CTX_set1_groups_list()    ← elliptic curve order
         └─ ctx.set_alpn_protocols(["h2","http/1.1"])
         │
         ▼
  ctx.wrap_socket(raw_sock, server_hostname=host)
  (TLS handshake — ClientHello looks like real Chrome)
         │
         ▼
  check ssl_sock.selected_alpn_protocol()
         │
         ├── "h2"       → HTTP2Connection
         │                ├─ h2.local_settings.update(settings)
         │                ├─ initiate_connection()  (sends SETTINGS frame)
         │                ├─ increment_flow_control_window(15663105)
         │                └─ send_headers(pseudo_headers in Chrome order)
         │
         └── "http/1.1" → http1_request()
                          └─ serialize headers in preset.header_order
         │
         ▼
  ViperResponse(status, headers, decompressed_body, url, http_version)
```

The ctypes trick for extracting `SSL_CTX*` from Python's `ssl.SSLContext`:

```python
# CPython PySSLContext struct (64-bit):
#   offset 0:  ob_refcnt  (8 bytes)
#   offset 8:  ob_type    (8 bytes)
#   offset 16: SSL_CTX*   (8 bytes)  ← this is what we want

raw = (ctypes.c_char * 24).from_address(id(ctx))
ssl_ctx_ptr = struct.unpack_from("Q", raw, 16)[0]

libssl.SSL_CTX_set1_groups_list(ssl_ctx_ptr, b"X25519:P-256:P-384")
```

Is this cursed? Yes. Does it work? Also yes.

---

## Known Limitations & Bugs

Because honesty is important (and we're going to find out eventually anyway):

- **HTTP/2 SETTINGS values** — The `h2` library applies its own defaults before our custom values in some configurations. The window increment and pseudo-header order (the most important parts for fingerprinting) work correctly. The raw SETTINGS frame values may differ slightly from a real Chrome capture.
- **No HTTP/3 / QUIC** — Not implemented yet. Sites that exclusively use QUIC will fall back to HTTP/2, which is fine for now.
- **No connection pooling** — Each request opens a fresh TLS connection. Fast enough for scraping, not ideal for high-frequency trading or something equally unhinged.
- **No WebSocket / SSE support** — Coming. Maybe.
- **ctypes approach is CPython 64-bit only** — Works on Linux and macOS (x86_64, arm64). If you're on 32-bit Python for some reason, please update. If you're running PyPy, this will explode. Gracefully, we hope.
- **No full browser profile emulation** — The solver is practical and effective, but it is not pretending to be a naturally used desktop profile with years of trust history.
- **Cloudflare behavior changes constantly** — Some sites solve cleanly, some need browser fallback, and some can still become unstable as Cloudflare updates detection logic.
- **No general-purpose cookie jar API yet** — Solver cache exists and is reusable, but broader cookie/session ergonomics are still evolving.

---

## Roadmap

- [ ] JA4 fingerprint support
- [ ] HTTP/3 / QUIC (aioquic)
- [ ] Connection pooling and keep-alive
- [ ] First-class cookie jar / session management
- [ ] WebSocket support
- [ ] SSE (Server-Sent Events)
- [ ] More browser presets (Opera, Chrome Android, Safari iOS)
- [ ] Automated fingerprint testing against tls.peet.ws / ja3er.com
- [ ] Richer response metadata and cache/session tooling

---

## License

MIT. Do whatever you want with it. Don't blame us when it breaks.

---

<div align="center">

**As always, Made By Walter.**

**Built with Python, ctypes, questionable life choices, and a deep hatred of getting 403'd.**

*If this saved you from writing a Go wrapper, consider starring the repo.*

</div>
