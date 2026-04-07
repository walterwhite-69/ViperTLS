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

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![HTTP/2](https://img.shields.io/badge/HTTP%2F2-%E2%9C%93-brightgreen?style=flat-square)](https://http2.github.io)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-bypassed-orange?style=flat-square&logo=cloudflare&logoColor=white)](https://cloudflare.com)
[![Bugs](https://img.shields.io/badge/bugs-probably%20some-red?style=flat-square)](https://github.com)
[![Vibes](https://img.shields.io/badge/vibes-immaculate-purple?style=flat-square)](https://github.com)

</div>

---

## What is this?

ViperTLS is a **pure Python HTTP client** that makes your requests look like they're coming from a real browser at the TLS level. It spoofs:

- **JA3 / JA4** — The TLS ClientHello fingerprint
- **HTTP/2 SETTINGS frames** — The window sizes, header table sizes, and frame ordering that real browsers negotiate
- **HTTP/2 pseudo-header order** — Chrome sends `:method :authority :scheme :path`. Firefox does `:method :path :authority :scheme`.
- **HTTP header ordering** — Because Cloudflare reads your headers like a suspicious bouncer reading a fake ID

The result: your Python script walks up to Cloudflare's velvet rope looking like Chrome in a suit, and gets waved straight through.

When TLS fingerprinting is not enough and a site still throws a browser challenge, ViperTLS can escalate into a real browser solve, capture the useful cookies, and reuse them on later requests. So the practical request flow is:

- **TLS** when the site is easy
- **Browser** when the site needs a challenge solve
- **Cache** when the site was already solved and the clearance cookies are still valid

Think of it as [CycleTLS](https://github.com/Danny-Dasilva/CycleTLS) — but in pure Python, without spawning a Go subprocess, without curl_cffi, and without any of that compiled-binary nonsense.

> ⚠️ **Fair warning:** There are probably bugs. TLS fingerprinting is a moving target, Cloudflare updates its detection constantly, and we wrote this in Python instead of something sensible. Use in production at your own risk.

---

## How It Works

Cloudflare and other bot-detection systems don't just look at your User-Agent. They analyze the **actual bytes** of your TLS handshake and HTTP/2 connection setup. Every library has a fingerprint:

```
python-requests  →  JA3: 3b5074b1b5d032e5620f69f9159c1ab7  →  BLOCKED
urllib3          →  JA3: b32309a26951912be7dba376398abc3b  →  BLOCKED
Chrome           →  JA3: browser-like                       →  ALLOWED
ViperTLS         →  JA3: looks like a real browser          →  ALLOWED
```

ViperTLS gets there by:

1. Using `ssl.SSLContext.set_ciphers()` to set TLS 1.2 cipher order
2. Using `ctypes` to call `SSL_CTX_set_ciphersuites()` directly on the `SSL_CTX*` pointer extracted from CPython internals for TLS 1.3 cipher ordering
3. Using `ctypes` → `SSL_CTX_set1_groups_list()` for elliptic curve ordering
4. Using the [`h2`](https://python-hyper.org/projects/h2/) library with custom SETTINGS and Chromium-style behavior injected before the request
5. Sending HTTP headers in the exact order browsers actually send them

No binary bridge. No subprocess wrapper. Just Python, ctypes, and questionable life choices.

---

## Installation

```bash
pip install vipertls
vipertls install-browsers
```

On Linux:

```bash
vipertls install-browsers --with-deps
```

For a source checkout:

```bash
git clone https://github.com/walterwhite-69/ViperTLS
cd ViperTLS
pip install -e .
python install_browsers.py
```

**Quick commands:**

```bash
vipertls --help
vipertls
vipertls paths
vipertls serve --host 127.0.0.1 --port 5000
```

ViperTLS keeps Playwright browsers, solver cookies, and other writable runtime files in one ViperTLS-managed home directory. In a source checkout that is the repo root. In a pip install it falls back to a per-user writable `vipertls` directory automatically.

If the solver cannot find a local Chrome or Edge install, it can bootstrap Playwright Chromium into that same ViperTLS home automatically on first browser solve. You can also do it explicitly with `vipertls install-browsers`.

When you use ViperTLS from your own Python script as a module, it prefers a script-local `vipertls` folder next to that script, so solver cookies and browser assets stay bundled with the scraper project instead of getting mixed into one global cache.

Python `3.12` is the recommended runtime. Hosted deployments should prefer Python `3.12`. Python `3.13` disables the fragile low-level OpenSSL pointer path to avoid crashes, so browser solving can still work but TLS fingerprint control may be less exact on that runtime.

---

## Quick Start

```python
import asyncio
import vipertls

async def main():
    async with vipertls.AsyncClient(impersonate="edge_133", debug_messages=True) as client:
        response = await client.get("https://www.crunchyroll.com/")
        print(response.status_code)
        print(response.solved_by)
        print(response.solve_info)

asyncio.run(main())
```

---

## Ways to Use ViperTLS

ViperTLS can be used in three main ways, depending on what kind of integration you need:

### 1. As a Python module

Best when you control the Python code directly and want the cleanest API.

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

```python
import asyncio
import vipertls

async def main():
    async with vipertls.AsyncClient(
        impersonate="edge_133",
        proxy="socks5://user:pass@host:1080",
        timeout=30,
        verify=True,
        follow_redirects=True,
        debug_messages=True,
    ) as client:
        r = await client.get("https://example.com/")
        print(r.status_code, r.http_version, len(r.content))
        print(r.solved_by, r.from_cache)
        print(r.cookies_received)
        print(r.cookies_used)

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

```python
import vipertls

client = vipertls.Client(impersonate="firefox_127", timeout=30)
r = client.get("https://www.tempmail.la/")
print(r.status_code)
print(r.text[:500])
```

### Response Object

```python
r.status_code
r.ok
r.solved_by
r.from_cache
r.headers
r.content
r.text
r.json()
r.http_version
r.url
r.cookies_received
r.cookies_used
r.solve_info
r.raise_for_status()
```

### Runtime Helpers

```python
import vipertls

print(vipertls.get_runtime_paths())
vipertls.clear_solver_cache()
vipertls.clear_solver_cache(domain="1337x.to")
vipertls.clear_solver_cache(domain="1337x.to", preset="edge_133")
```

---

## Live Dashboard (TUI)

A real-time request monitor built with [`rich`](https://github.com/Textualize/rich).

```python
import asyncio
from vipertls import ViperDashboard

async def main():
    async with ViperDashboard(impersonate="chrome_124", timeout=30) as dash:
        await asyncio.gather(
            dash.get("https://www.crunchyroll.com/"),
            dash.get("https://tls.peet.ws/api/all", headers={"accept": "application/json"}),
        )

asyncio.run(main())
```

The dashboard shows live spinners for in-flight requests, color-coded status codes, HTTP version, response size, timing, and preset used.

---

## Server Mode

Run ViperTLS as a local HTTP proxy server. Make requests to `localhost` with `X-Viper-*` control headers.

```bash
vipertls serve --host 127.0.0.1 --port 8080
vipertls serve --host 0.0.0.0 --port 8080 --workers 4
```

Then:

```bash
curl -s http://localhost:8080 \
  -H "X-Viper-URL: https://www.crunchyroll.com/" \
  -H "X-Viper-Impersonate: chrome_124"
```

### Control Headers

| Header | Description | Example |
|--------|-------------|---------|
| `X-Viper-URL` | Target URL to request | `https://www.crunchyroll.com/api/...` |
| `X-Viper-Method` | HTTP method | `POST` |
| `X-Viper-Impersonate` | Browser preset name | `chrome_124`, `firefox_127`, `safari_17` |
| `X-Viper-Proxy` | Proxy URL | `socks5://user:pass@host:1080` |
| `X-Viper-Timeout` | Request timeout in seconds | `30` |
| `X-Viper-JA3` | Override JA3 fingerprint string | `771,4865-4866-4867,...` |
| `X-Viper-No-Redirect` | Disable redirect following | `true` |
| `X-Viper-Skip-Verify` | Skip TLS certificate verification | `true` |
| `X-Viper-Force-HTTP1` | Force HTTP/1.1 | `true` |
| `X-Viper-Body` | Request body as string | `{"key":"value"}` |
| `X-Viper-Headers` | Extra headers as JSON string | `{"authorization":"Bearer ..."}` |

The proxy response also includes ViperTLS-specific helper headers such as:

- `X-ViperTLS-Solved-By`
- `X-Viper-HTTP-Version`
- `X-Viper-Received-Cookies`
- `X-ViperTLS-Used-Cookies`

---

## Standalone Solver API

```bash
python -m vipertls.solver --host 127.0.0.1 --port 8081
```

Available endpoints:

- `POST /solve`
- `DELETE /cookies/{domain}`
- `DELETE /cookies`
- `GET /health`

Example:

```bash
curl -X POST http://127.0.0.1:8081/solve \
  -H "content-type: application/json" \
  -d "{\"url\":\"https://nopecha.com/demo/cloudflare\",\"preset\":\"edge_133\",\"timeout\":30}"
```

---

## Browser Presets

| Preset | Alias | TLS Version | Pseudo-header order |
|--------|-------|-------------|---------------------|
| `chrome_124` | — | TLS 1.3 | `:method :authority :scheme :path` |
| `chrome_131` | `chrome` | TLS 1.3 | `:method :authority :scheme :path` |
| `firefox_127` | `firefox` | TLS 1.3 | `:method :path :authority :scheme` |
| `safari_17` | `safari` | TLS 1.3 | `:method :authority :scheme :path` |

Aliases: `chrome` → `chrome_131`, `firefox` → `firefox_127`, `safari` → `safari_17`

### Recommended Presets

- `edge_133` — best default when you care about the browser-solver path
- `chrome_*` — good default for TLS-first traffic
- `firefox_*` — useful when you specifically want Firefox-like TLS and HTTP/2 behavior

---

## Proxy Support

```python
AsyncClient(proxy="socks5://username:password@proxy.host:1080")
AsyncClient(proxy="socks5h://username:password@proxy.host:1080")
AsyncClient(proxy="socks4://proxy.host:1080")
AsyncClient(proxy="http://username:password@proxy.host:8080")
AsyncClient(proxy="127.0.0.1:8080")
AsyncClient(proxy="127.0.0.1:8080:user:pass")
```

If you pass `ip:port` or `ip:port:user:pass`, ViperTLS treats it as an HTTP CONNECT proxy automatically.

---

## Error Handling

```python
from vipertls import AsyncClient, ViperHTTPError, ViperConnectionError, ViperTimeoutError
```

---

## Hosting

Yes, it's hostable. It's a FastAPI server.

### Railway / Render

A `Procfile` is included:

```
web: python -m vipertls serve --host 0.0.0.0 --port $PORT
```

### Docker

```bash
docker build -t vipertls .
docker run -p 8080:8080 vipertls
```

### VPS / Bare Metal

```bash
git clone https://github.com/walterwhite-69/ViperTLS && cd ViperTLS
pip install -r requirements.txt
python -m vipertls serve --host 0.0.0.0 --port 8080 --workers 4
```

### Important for Hosted Deployments

- prefer Python `3.12`
- Linux browser solving needs Playwright system dependencies
- on Linux, use `vipertls install-browsers --with-deps` when the platform allows it
- if the platform blocks system package installation, browser solving may fail even if TLS mode still works

---

## Architecture

```text
AsyncClient.get("https://target.com/")
         │
         ▼
  resolve_preset("chrome_124")
         │
         ▼
  parse_ja3(preset.ja3) → JA3Spec
         │
         ├── [proxy?] open_tunnel(host, 443, proxy_url)
         │
         ▼
  build_ssl_context(preset, ja3)
         ├─ ctx.set_ciphers(tls12_ciphers)
         ├─ ctypes → SSL_CTX_set_ciphersuites()
         ├─ ctypes → SSL_CTX_set1_groups_list()
         └─ ctx.set_alpn_protocols(["h2","http/1.1"])
         │
         ▼
  ctx.wrap_socket(raw_sock, server_hostname=host)
         │
         ▼
  selected_alpn_protocol()
         ├── "h2"       → HTTP2Connection
         └── "http/1.1" → http1_request()
```

---

## Known Limitations & Bugs

- **No HTTP/3 / QUIC** — not implemented yet
- **No connection pooling** — each request opens a fresh TLS connection
- **ctypes approach is CPython-specific** — Python `3.13` disables the fragile direct pointer path
- **No full browser profile emulation** — solver is practical, not magic
- **Cloudflare behavior changes constantly**

---

## Roadmap

- [ ] fuller JA4 support
- [ ] HTTP/3 / QUIC
- [ ] connection pooling and keep-alive
- [ ] first-class cookie jar / session management
- [ ] WebSocket support
- [ ] SSE support
- [ ] more browser presets

---

## License

MIT. Do whatever you want with it.

---

<div align="center">

**As always, Made By Walter.**

**Built with Python, ctypes, questionable life choices, and a deep hatred of getting 403'd.**

</div>
