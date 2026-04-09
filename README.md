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

`vipertls install-browsers` downloads the Playwright Chromium binary that ViperTLS uses when a site requires a full browser challenge solve. The binary itself is handled entirely by Playwright — but Chromium also needs certain **system-level libraries** to run. These are not Python packages, they live at the OS level.

> **Windows users:** you don't need to do anything extra. Chromium ships its own DLLs on Windows.

---

## System Requirements for Browser Fallback

The browser challenge fallback (used when a site serves a JS challenge that TLS spoofing alone can't beat) runs a real Chromium instance. Chromium requires a set of shared libraries (`.so` files on Linux) to be present on your OS. If they're missing, you'll get `browser_failed` with `missing browser dependency`.

### Ubuntu / Debian / Kali / Pop!_OS

The easiest path — Playwright can install everything for you:

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
    pkgs.xorg.libX11
    pkgs.xorg.libXcomposite
    pkgs.xorg.libXdamage
    pkgs.xorg.libXext
    pkgs.xorg.libXfixes
    pkgs.xorg.libXrandr
    pkgs.xorg.libxcb
  ];
}
```

> **Note:** `libgbm` is a **separate Nix package** from `mesa` — you need both. Also skip `--with-deps` when running `playwright install chromium` on NixOS, it will try to call `apt` and fail.

### macOS

Playwright handles everything on macOS — no extra steps needed after:

```bash
pip install vipertls
vipertls install-browsers
```

If Chromium still crashes, install XQuartz:

```bash
brew install --cask xquartz
```

---

## Verifying Your Setup

After installing libs and running `vipertls install-browsers`, you can confirm the browser works:

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

If that prints `OK: Example Domain` your setup is good. If it throws a library error, check `ldd` on the Chromium binary to see what's still missing:

```bash
# Find the chromium binary path
python3 -c "from playwright._impl._driver import compute_driver_executable; import pathlib; print(pathlib.Path(compute_driver_executable()).parent.parent)"

# Then run ldd on it (Linux only)
ldd ~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome | grep "not found"
```

Any `not found` entries are the missing libs — install the matching package for your distro.

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
