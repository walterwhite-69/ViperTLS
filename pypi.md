# ViperTLS

Pure Python HTTP client that makes your requests look like a real browser at the TLS level. No curl_cffi. No Go binary. No compiled extensions.

Spoofs JA3/JA4 fingerprints, HTTP/2 SETTINGS frames, HTTP/2 pseudo-header order, and HTTP header ordering. When a site still throws a JS challenge, ViperTLS falls back to a real Chromium browser, captures the clearance cookies, and reuses them on later requests — automatically.

---

## Install

```bash
pip install vipertls
vipertls install-browsers
```

`vipertls install-browsers` downloads the Playwright Chromium binary used for browser challenge fallback. On Windows, nothing else is needed. On Linux, see [System Requirements](#system-requirements-linux--macos) below.

**Python 3.10 through 3.14 supported.**

---

## Quick Start

```python
import asyncio
import vipertls

async def main():
    async with vipertls.AsyncClient(impersonate="chrome_145") as client:
        r = await client.get("https://www.crunchyroll.com/")
        print(r.status_code)
        print(r.solved_by)

asyncio.run(main())
```

---

## Three Ways to Use It

### 1. Python module

```python
import asyncio
import vipertls

async def main():
    async with vipertls.AsyncClient(impersonate="edge_133") as client:
        r = await client.get("https://example.com")
        print(r.status_code, r.solved_by)

asyncio.run(main())
```

### 2. Local proxy server

Run a local HTTP server and hit any target through it using `X-Viper-*` headers.

```bash
vipertls serve --host 127.0.0.1 --port 8080
```

```bash
curl http://127.0.0.1:8080 \
  -H "X-Viper-URL: https://example.com" \
  -H "X-Viper-Impersonate: chrome_145"
```

The CLI launches a live TUI dashboard showing every request in real time — status, solve mode, timing, and preset.

### 3. Standalone browser solver API

Only need the challenge-solving side as a service:

```bash
python -m vipertls.solver --host 127.0.0.1 --port 8081
```

```bash
curl -X POST http://127.0.0.1:8081/solve \
  -H "content-type: application/json" \
  -d '{"url":"https://example.com","preset":"edge_133","timeout":30}'
```

Endpoints: `POST /solve`, `DELETE /cookies/{domain}`, `DELETE /cookies`, `GET /health`

---

## Async Client

```python
import asyncio
import vipertls

async def main():
    async with vipertls.AsyncClient(
        impersonate="chrome_145",
        proxy="socks5://user:pass@host:1080",
        timeout=30,
        verify=True,
        follow_redirects=True,
        debug_messages=False,
    ) as client:
        r = await client.get("https://example.com/")
        print(r.status_code, r.http_version, len(r.content))
        print(r.solved_by, r.from_cache)

asyncio.run(main())
```

### HTTP/3

```python
async with vipertls.AsyncClient(impersonate="chrome_145", http3=True) as client:
    r = await client.get("https://example.com/")
    print(r.http_version)
```

Pass `http3=True` to force QUIC. Without it, ViperTLS still upgrades automatically when it sees an `alt-svc: h3=` header from the server.

---

## Sync Client

```python
import vipertls

client = vipertls.Client(impersonate="firefox_136", timeout=30)
r = client.get("https://example.com/")
print(r.status_code)
print(r.text[:500])
```

---

## Response Object

```python
r.status_code
r.ok
r.headers
r.content
r.text
r.json()
r.url
r.http_version
r.solved_by
r.from_cache
r.cookies_received
r.cookies_used
r.solve_info
r.raise_for_status()
```

---

## Solver States

`r.solved_by` tells you how ViperTLS got through:

| Value | Meaning |
|---|---|
| `tls` | TLS fingerprint was enough — fast, no browser |
| `browser` | Site required a JS challenge — Playwright solved it |
| `cache` | Earlier browser solve still valid — cookies reused |

---

## JA4 Fingerprint Family

Every response exposes the full JA4 suite so you can verify what your request looked like from the server side:

```python
r.ja4      # TLS ClientHello fingerprint
r.ja4_r    # JA4 raw (unsorted, full values)
r.ja4h     # HTTP header fingerprint
r.ja4s     # Server hello fingerprint
r.ja4l     # Latency fingerprint (connect_ms_handshake_ms)
r.solve_info  # all of the above as a dict
```

---

## Proxy Support

```python
AsyncClient(proxy="socks5://user:pass@host:1080")
AsyncClient(proxy="socks5h://user:pass@host:1080")
AsyncClient(proxy="socks4://host:1080")
AsyncClient(proxy="http://user:pass@host:8080")
AsyncClient(proxy="host:port")
AsyncClient(proxy="host:port:user:pass")
```

Bare `host:port` and `host:port:user:pass` are treated as HTTP CONNECT proxies automatically.

---

## Error Handling

```python
from vipertls import AsyncClient, ViperHTTPError, ViperConnectionError, ViperTimeoutError

try:
    async with AsyncClient(impersonate="chrome_145") as client:
        r = await client.get("https://example.com/")
        r.raise_for_status()
except ViperTimeoutError:
    pass
except ViperConnectionError:
    pass
except ViperHTTPError as e:
    print(e.response.status_code)
```

---

## Runtime Helpers

```python
import vipertls

print(vipertls.get_runtime_paths())
vipertls.clear_solver_cache()
vipertls.clear_solver_cache(domain="1337x.to")
vipertls.clear_solver_cache(domain="1337x.to", preset="edge_133")
```

---

## Browser Presets

| Preset | JA4 |
|---|---|
| `chrome_145` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_140` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_136` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_133` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_131` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_124` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `chrome_120` | `t13d1515h2_dea800f94266_daa8e4778a3e` |
| `firefox_136` | `t13d1814h2_f3ddd0d8df11_3bed559cf7b0` |
| `firefox_133` | `t13d1814h2_f3ddd0d8df11_3bed559cf7b0` |
| `firefox_127` | `t13d1814h2_f3ddd0d8df11_3bed559cf7b0` |
| `firefox_120` | `t13d1814h2_f3ddd0d8df11_3bed559cf7b0` |
| `safari_18` | `t13d2214h2_bb4723730337_030652283baa` |
| `safari_17` | `t13d2214h2_bb4723730337_030652283baa` |
| `edge_136` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `edge_133` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `brave_136` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |
| `opera_117` | `t13d1516h2_dea800f94266_0cba2f92bfc0` |

Short aliases: `chrome` → `chrome_145`, `firefox` → `firefox_136`, `safari` → `safari_18`, `edge` → `edge_136`, `brave` → `brave_136`, `opera` → `opera_117`

**Which preset to use:**

- `chrome_145` — best default for TLS-only targets and invisible Cloudflare
- `edge_133` — best default when you expect a JS challenge fallback
- `firefox_136` — when you specifically need Firefox TLS/HTTP2 behavior
- `safari_18` — when the target checks for Safari-specific fingerprints

---

## Proxy Server Control Headers

| Header | Description | Example |
|---|---|---|
| `X-Viper-URL` | Target URL | `https://example.com/api` |
| `X-Viper-Method` | HTTP method | `POST` |
| `X-Viper-Impersonate` | Browser preset | `chrome_145` |
| `X-Viper-Proxy` | Proxy URL | `socks5://user:pass@host:1080` |
| `X-Viper-Timeout` | Timeout in seconds | `30` |
| `X-Viper-JA3` | Override JA3 string | `771,4865-4866-4867,...` |
| `X-Viper-No-Redirect` | Disable redirect following | `true` |
| `X-Viper-Skip-Verify` | Skip TLS cert verification | `true` |
| `X-Viper-Force-HTTP1` | Force HTTP/1.1 | `true` |
| `X-Viper-Body` | Request body as string | `{"key":"value"}` |
| `X-Viper-Headers` | Extra headers as JSON | `{"authorization":"Bearer ..."}` |

Response includes: `X-ViperTLS-Solved-By`, `X-Viper-HTTP-Version`, `X-ViperTLS-JA4`, `X-ViperTLS-JA4H`, `X-ViperTLS-JA4S`, `X-ViperTLS-JA4L`, `X-Viper-Received-Cookies`, `X-ViperTLS-Used-Cookies`

---

## Hosting

### Railway / Render

```
web: python -m vipertls serve --host 0.0.0.0 --port $PORT
```

### Docker

```bash
docker build -t vipertls .
docker run -p 8080:8080 vipertls
```

### VPS

```bash
pip install vipertls
vipertls install-browsers
python -m vipertls serve --host 0.0.0.0 --port 8080 --workers 4
```

**Hosted deployment notes:**

- Python 3.10+ required; 3.12 or 3.13 most battle-tested on cloud runtimes
- Linux needs Playwright system libraries for browser solving (see below)
- If the platform blocks system package installs, TLS mode still works — only browser challenge fallback is affected

---

## System Requirements (Linux / macOS)

The browser fallback runs real Chromium. It needs OS-level shared libraries.

### macOS

No extra steps after `vipertls install-browsers`. If Chromium crashes:

```bash
brew install --cask xquartz
```

### Ubuntu / Debian / Kali

Easiest — let Playwright install everything:

```bash
playwright install --with-deps chromium
```

Manual install if preferred:

```bash
sudo apt-get install -y \
  libglib2.0-0 libnss3 libnspr4 libatk1.0-0 \
  libatk-bridge2.0-0 libcups2 libdrm2 libdbus-1-3 \
  libxcb1 libxkbcommon0 libx11-6 libxcomposite1 \
  libxdamage1 libxext6 libxfixes3 libxrandr2 \
  libgbm1 libasound2 libpango-1.0-0 libcairo2 \
  libexpat1 libudev1
```

### Arch / Manjaro

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

Add to `replit.nix` (or `shell.nix` / `flake.nix`):

```nix
{pkgs}: {
  deps = [
    pkgs.glib pkgs.nss pkgs.nspr pkgs.atk
    pkgs.at-spi2-atk pkgs.at-spi2-core pkgs.dbus
    pkgs.cups pkgs.libdrm pkgs.mesa pkgs.libgbm
    pkgs.libxkbcommon pkgs.alsa-lib pkgs.expat
    pkgs.udev pkgs.pango pkgs.cairo pkgs.gtk3
    pkgs.xorg.libX11 pkgs.xorg.libXcomposite
    pkgs.xorg.libXdamage pkgs.xorg.libXext
    pkgs.xorg.libXfixes pkgs.xorg.libXrandr
    pkgs.xorg.libxcb pkgs.xorg.libXcursor
    pkgs.xorg.libXi
  ];
}
```

Then run `vipertls install-browsers` — NixOS is auto-detected and `--with-deps` is skipped automatically.

### Verifying your setup

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

If that prints `OK: Example Domain` you're good. If it throws a library error on Linux:

```bash
python3 -c "
from playwright._impl._driver import compute_driver_executable
import pathlib
print(pathlib.Path(compute_driver_executable()).parent.parent)
"
ldd ~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome | grep "not found"
```

Any `not found` entries are the missing libs — install the matching package for your distro.

---

## License

MIT
