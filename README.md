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

[![Python](https://img.shields.io/badge/Python-3.10--3.14-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![HTTP/2](https://img.shields.io/badge/HTTP%2F2-%E2%9C%93-brightgreen?style=flat-square)](https://http2.github.io)
[![HTTP/3](https://img.shields.io/badge/HTTP%2F3-%E2%9C%93-brightgreen?style=flat-square)](https://http3.net)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-bypassed-orange?style=flat-square&logo=cloudflare&logoColor=white)](https://cloudflare.com)
[![Bugs](https://img.shields.io/badge/bugs-probably%20some-red?style=flat-square)](https://github.com)
[![Vibes](https://img.shields.io/badge/vibes-immaculate-purple?style=flat-square)](https://github.com)

</div>

---

## What is this?

ViperTLS is a **pure Python HTTP client** that makes your requests look like they're coming from a real browser at the TLS level. It spoofs:

- **JA3 / JA4 family** — The full TLS ClientHello fingerprint suite: JA4, JA4_r, JA4H, JA4S, JA4L
- **HTTP/2 SETTINGS frames** — The window sizes, header table sizes, and frame ordering that real browsers negotiate
- **HTTP/2 pseudo-header order** — Chrome sends `:method :authority :scheme :path`. Firefox does `:method :path :authority :scheme`.
- **HTTP header ordering** — Because Cloudflare reads your headers like a suspicious bouncer reading a fake ID
- **HTTP/3 / QUIC** — Browser-accurate QUIC transport parameters per browser family via aioquic

The result: your Python script walks up to Cloudflare's velvet rope looking like Chrome in a suit, and gets waved straight through.

When TLS fingerprinting is not enough and a site still throws a browser challenge, ViperTLS escalates into a real browser solve, captures the useful cookies, and reuses them on later requests. So the practical request flow is:

- **TLS** when the site uses invisible Cloudflare or fingerprint-only checks
- **Browser** when the site needs a full JS challenge solve
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

1. Using **pyOpenSSL** (`OpenSSL.SSL.Context`) with cffi to set TLS 1.2 cipher order, TLS 1.3 cipher suites, and elliptic curve groups — without touching CPython internals, works on Python 3.10 through 3.14
2. Using the [`h2`](https://python-hyper.org/projects/h2/) library with custom SETTINGS and Chromium-style behavior injected before the request
3. Sending HTTP headers in the exact order browsers actually send them
4. Computing and exposing the full **JA4 fingerprint family** on every response so you can verify what you're actually sending
5. Falling back to a real Chromium instance when a site requires a JS challenge that TLS alone cannot beat

No binary bridge. No subprocess wrapper. No ctypes. Just Python, pyOpenSSL, and questionable life choices.

---

## Installation

```bash
pip install vipertls
vipertls install-browsers
```

`vipertls install-browsers` downloads the Playwright Chromium binary that ViperTLS uses when a site requires a full browser challenge solve. The binary itself is handled entirely by Playwright — but Chromium also needs certain **system-level libraries** to run. These are not Python packages, they live at the OS level.

> **Windows users:** you don't need to do anything extra. Chromium ships its own DLLs on Windows.

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

**Python 3.10 through 3.14 are all supported.** The TLS layer uses pyOpenSSL with cffi — no ctypes, no CPython internal pointer extraction, no version-specific hacks. Every binary dependency ships compatible wheels for all supported Python versions.

---

## System Requirements for Browser Fallback

The browser challenge fallback runs a real Chromium instance. Chromium requires a set of shared libraries (`.so` files on Linux) to be present on your OS. If they're missing, you'll get `browser_failed` with `missing browser dependency`.

### Windows

No extra steps. Chromium ships its own DLLs.

### macOS

Playwright handles everything — no extra steps needed after `vipertls install-browsers`. If Chromium still crashes, install XQuartz:

```bash
brew install --cask xquartz
```

### Ubuntu / Debian / Kali / Pop!_OS

The easiest path — Playwright installs everything for you:

```bash
pip install playwright
playwright install --with-deps chromium
```

`--with-deps` calls `apt` under the hood and installs all required libs automatically. You only need to do this once.

If you'd rather install the libs manually:

```bash
sudo apt-get install -y \
  libglib2.0-0 libnss3 libnspr4 libatk1.0-0 \
  libatk-bridge2.0-0 libcups2 libdrm2 libdbus-1-3 \
  libxcb1 libxkbcommon0 libx11-6 libxcomposite1 \
  libxdamage1 libxext6 libxfixes3 libxrandr2 \
  libgbm1 libasound2 libpango-1.0-0 libcairo2 \
  libexpat1 libudev1
```

### Arch Linux / Manjaro

```bash
sudo pacman -S --needed \
  glib2 nss nspr atk at-spi2-atk at-spi2-core \
  cups libdrm dbus libxcb libxkbcommon \
  libx11 libxcomposite libxdamage libxext libxfixes libxrandr \
  mesa libgbm alsa-lib pango cairo expat systemd-libs
```

### Fedora / RHEL / CentOS

```bash
sudo dnf install -y \
  glib2 nss nspr atk at-spi2-atk at-spi2-core \
  cups-libs libdrm dbus-libs libxcb libxkbcommon \
  libX11 libXcomposite libXdamage libXext libXfixes libXrandr \
  mesa-libgbm alsa-lib pango cairo expat systemd-libs
```

### NixOS / Replit

NixOS doesn't use a standard FHS filesystem so you can't use `apt` or `pacman`. Add these to your `replit.nix` (or `shell.nix` / `flake.nix`):

```nix
{pkgs}: {
  deps = [
    pkgs.glib
    pkgs.nss
    pkgs.nspr
    pkgs.atk
    pkgs.at-spi2-atk
    pkgs.at-spi2-core
    pkgs.dbus
    pkgs.cups
    pkgs.libdrm
    pkgs.mesa
    pkgs.libgbm
    pkgs.libxkbcommon
    pkgs.alsa-lib
    pkgs.expat
    pkgs.udev
    pkgs.pango
    pkgs.cairo
    pkgs.gtk3
    pkgs.xorg.libX11
    pkgs.xorg.libXcomposite
    pkgs.xorg.libXdamage
    pkgs.xorg.libXext
    pkgs.xorg.libXfixes
    pkgs.xorg.libXrandr
    pkgs.xorg.libxcb
    pkgs.xorg.libXcursor
    pkgs.xorg.libXi
  ];
}
```

> **Note:** `libgbm` is a **separate Nix package** from `mesa` — you need both. `vipertls install-browsers` automatically detects NixOS and skips `--with-deps` (which would try to call `apt` and fail). Just run it directly — no flags needed.

---

## Verifying Your Setup

After installing libs and running `vipertls install-browsers`:

```bash
python3 -c "
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    page = b.new_page()
    page.goto('https://example.com')
    print('OK:', page.title())
    b.close()
"
```

If that prints `OK: Example Domain` your setup is good. If it throws a library error on Linux, check `ldd` on the Chromium binary to see what is still missing:

```bash
python3 -c "
from playwright._impl._driver import compute_driver_executable
import pathlib
print(pathlib.Path(compute_driver_executable()).parent.parent)
"
# then:
ldd ~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome | grep "not found"
```

Any `not found` entries are the missing libs — install the matching package for your distro.

---

## Quick Start

```python
import asyncio
import vipertls

async def main():
    async with vipertls.AsyncClient(impersonate="chrome_145", debug_messages=True) as client:
        response = await client.get("https://www.crunchyroll.com/")
        print(response.status_code)
        print(response.solved_by)
        print(response.solve_info)

asyncio.run(main())
```

---

## Ways to Use ViperTLS

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

### HTTP/3

```python
async with vipertls.AsyncClient(impersonate="chrome_145", http3=True) as client:
    r = await client.get("https://example.com/")
    print(r.http_version)
```

Passing `http3=True` forces QUIC from the first request. Without it, ViperTLS still detects `alt-svc: h3=` headers and upgrades automatically on subsequent requests to the same host.

### Sync Client

```python
import vipertls

client = vipertls.Client(impersonate="firefox_136", timeout=30)
r = client.get("https://www.tempmail.la/")
print(r.status_code)
print(r.text[:500])
```

### Solver States

When you inspect a response, `r.solved_by` tells you how ViperTLS got through:

- `tls` — direct request worked, TLS fingerprint was enough
- `browser` — direct request hit a challenge and the browser solver resolved it
- `cache` — an earlier browser solve already produced valid cookies, ViperTLS reused them

```python
print(r.solved_by)
print(r.from_cache)
print(r.cookies_received)
print(r.cookies_used)
print(r.solve_info)
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

### JA4 Fingerprint Family

Every response exposes the full JA4 fingerprint suite so you can verify exactly what your request looked like from the server's perspective:

```python
r.ja4      # TLS ClientHello fingerprint
r.ja4_r    # JA4 raw (unsorted, full values)
r.ja4h     # HTTP header fingerprint
r.ja4s     # Server hello fingerprint
r.ja4l     # Latency fingerprint (connect_ms_handshake_ms)
```

Example values from a live Chrome 145 request:

```
ja4   = t13d1516h2_dea800f94266_0cba2f92bfc0
ja4_r = t13d1516h2_47,53,156,157,4865,4866,4867,...
ja4h  = ge20nn19enUS_fe5b4433ad44_effb3a958668
ja4s  = t13d00_1301_000000000000
ja4l  = 36_59
```

These are also available via `r.solve_info` as a dict.

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
    async with ViperDashboard(impersonate="chrome_145", timeout=30) as dash:
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
  -H "X-Viper-Impersonate: chrome_145"
```

### Control Headers

| Header | Description | Example |
|--------|-------------|---------|
| `X-Viper-URL` | Target URL to request | `https://www.crunchyroll.com/api/...` |
| `X-Viper-Method` | HTTP method | `POST` |
| `X-Viper-Impersonate` | Browser preset name | `chrome_145`, `firefox_136`, `safari_18` |
| `X-Viper-Proxy` | Proxy URL | `socks5://user:pass@host:1080` |
| `X-Viper-Timeout` | Request timeout in seconds | `30` |
| `X-Viper-JA3` | Override JA3 fingerprint string | `771,4865-4866-4867,...` |
| `X-Viper-No-Redirect` | Disable redirect following | `true` |
| `X-Viper-Skip-Verify` | Skip TLS certificate verification | `true` |
| `X-Viper-Force-HTTP1` | Force HTTP/1.1 | `true` |
| `X-Viper-Body` | Request body as string | `{"key":"value"}` |
| `X-Viper-Headers` | Extra headers as JSON string | `{"authorization":"Bearer ..."}` |

The proxy response also includes ViperTLS-specific helper headers:

- `X-ViperTLS-Solved-By`
- `X-Viper-HTTP-Version`
- `X-Viper-Received-Cookies`
- `X-ViperTLS-Used-Cookies`
- `X-ViperTLS-JA4`
- `X-ViperTLS-JA4H`
- `X-ViperTLS-JA4S`
- `X-ViperTLS-JA4L`

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

| Preset | Alias | JA4 |
|--------|-------|-----|
| `chrome_145` | `chrome` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_140` | — | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_136` | — | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_133` | — | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_131` | — | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_124` | — | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_120` | — | `t13d1515h2_dea800f94266_daa8e4778a3e` |
| `firefox_136` | `firefox` | `t13d1814h2_f3ddd0d8df11_3bed559cf7b0` |
| `firefox_133` | — | `t13d1814h2_f3ddd0d8df11_3bed559cf7b0` |
| `firefox_127` | — | `t13d1814h2_f3ddd0d8df11_3bed559cf7b0` |
| `firefox_120` | — | `t13d1814h2_f3ddd0d8df11_3bed559cf7b0` |
| `safari_18` | `safari` | `t13d2214h2_bb4723730337_030652283baa` |
| `safari_17` | — | `t13d2214h2_bb4723730337_030652283baa` |
| `edge_136` | `edge` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `edge_133` | — | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `brave_136` | `brave` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `opera_117` | `opera` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |

Short aliases: `chrome` → `chrome_145`, `firefox` → `firefox_136`, `safari` → `safari_18`, `edge` → `edge_136`, `brave` → `brave_136`, `opera` → `opera_117`

### Recommended Presets

- `chrome_145` — best default for invisible Cloudflare and TLS-only targets; fast, no browser spin-up
- `edge_133` — best default when you expect browser challenge fallback; maps well to the solver browser path
- `firefox_136` — use when you specifically want Firefox TLS and HTTP/2 behavior
- `safari_18` — use for targets that check for Safari-specific fingerprints

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

## Architecture

```text
AsyncClient.get("https://target.com/")
         │
         ▼
  resolve_preset("chrome_145")   ←  ja4, ja4_r, quic_params auto-computed
         │
         ▼
  parse_ja3(preset.ja3) → JA3Spec
         │
         ├── [proxy?] open_tunnel(host, 443, proxy_url)
         │
         ▼
  open_tls_connection(preset, ja3)
         ├─ pyOpenSSL SSL.Context (cffi, not ctypes)
         ├─ SSL_CTX_set_ciphersuites()   ← TLS 1.3 cipher order
         ├─ SSL_CTX_set1_groups_list()   ← elliptic curve order
         ├─ socket.setblocking(True) before handshake → fast, no retry loop
         └─ ctx.set_alpn_protos(preset.alpn)
         │
         ▼
  selected_alpn_protocol()
         ├── "h2"       → HTTP2Connection (custom SETTINGS + pseudo-header order)
         ├── "http/1.1" → http1_request()
         └── [http3=True or alt-svc] → HTTP3Connection (aioquic, QUIC params per browser)
         │
         ▼
  ViperResponse
         ├── .ja4 / .ja4_r  ← from preset
         ├── .ja4h          ← computed from request headers
         ├── .ja4s          ← computed from server hello
         ├── .ja4l          ← connect_ms _ handshake_ms
         └── .solved_by     ← "tls" | "browser" | "cache"
         │
         ▼
  [403/503 + challenge markers?]
         └── CloudflareSolver → Playwright Chromium → cookies → retry
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

- Python 3.10+ is required; Python 3.12 or 3.13 are the most battle-tested hosted runtimes
- Linux browser solving needs Playwright system dependencies (see System Requirements above)
- On Replit / NixOS: add the Nix packages from the NixOS section, then run `vipertls install-browsers` — the NixOS auto-detection skips `--with-deps` automatically
- If the platform blocks system package installation, browser solving may fail even if TLS mode still works

---

## Known Limitations

- **No connection pooling** — each request opens a fresh TLS connection
- **No WebSocket support**
- **No SSE support**
- **Cloudflare behavior changes constantly** — presets may need updating as detection evolves
- **Browser solve is slow on first hit** (~20–30s) — subsequent hits use cache and are instant

---

## Roadmap

- [x] JA4 fingerprint family (JA4, JA4_r, JA4H, JA4S, JA4L)
- [x] HTTP/3 / QUIC via aioquic with per-browser QUIC transport params
- [x] Python 3.10–3.14 support via pyOpenSSL (no ctypes, no CPython version dependency)
- [x] NixOS / Replit auto-detection in browser installer
- [ ] Connection pooling and keep-alive
- [ ] First-class cookie jar / session management
- [ ] WebSocket support
- [ ] SSE support
- [ ] More browser presets (Opera GX, Samsung, mobile Chrome/Safari)

---

## License

MIT. Do whatever you want with it.

---

<div align="center">

**As always, Made By Walter.**

**Built with Python, pyOpenSSL, questionable life choices, and a deep hatred of getting 403'd.**

</div>
