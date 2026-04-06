# ViperTLS

Pure Python TLS fingerprinting with browser challenge fallback.

ViperTLS starts with a direct TLS/HTTP request that looks like a real browser. If that is not enough and a site returns a JavaScript challenge, it can escalate to a Playwright browser solve, collect the useful cookies, and reuse them later.

Request flow:

- `tls` when the direct path works
- `browser` when a challenge must be solved
- `cache` when solved cookies are reused

## Install

```bash
pip install vipertls
vipertls install-browsers
```

On Linux:

```bash
vipertls install-browsers --with-deps
```

## Python Version

- Python `3.12` is the recommended runtime
- Hosted deployments should prefer Python `3.12`
- Python `3.13` disables the fragile low-level OpenSSL pointer path to avoid crashes, so browser solving can still work but TLS fingerprint control may be less exact on that runtime

## Quick Start

```python
import asyncio
import vipertls

async def main():
    async with vipertls.AsyncClient(
        impersonate="edge_133",
        debug_messages=True,
    ) as client:
        response = await client.get("https://www.crunchyroll.com/")
        print(response.status_code)
        print(response.solved_by)
        print(response.solve_info)

asyncio.run(main())
```

## Main Usage Modes

### 1. Python module

Best when you control the Python code directly.

```python
import asyncio
import vipertls

async def main():
    async with vipertls.AsyncClient(impersonate="edge_133") as client:
        response = await client.get("https://example.com")
        print(response.status_code)
        print(response.solved_by)
        print(response.cookies_received)
        print(response.cookies_used)

asyncio.run(main())
```

### 2. Local proxy server

Best when another tool can send HTTP requests to localhost but cannot import Python code.

```bash
vipertls serve --host 127.0.0.1 --port 8080
```

Then send requests with Viper headers:

```bash
curl http://127.0.0.1:8080 \
  -H "X-Viper-URL: https://example.com" \
  -H "X-Viper-Impersonate: edge_133"
```

### 3. Standalone solver API

Best when you only want the browser-solver exposed as a small service.

```bash
python -m vipertls.solver --host 127.0.0.1 --port 8081
```

```bash
curl -X POST http://127.0.0.1:8081/solve \
  -H "content-type: application/json" \
  -d "{\"url\":\"https://example.com\",\"preset\":\"edge_133\",\"timeout\":30}"
```

## CLI

```bash
vipertls
vipertls --help
vipertls paths
vipertls install-browsers
vipertls serve --host 127.0.0.1 --port 5000
```

## Recommended Presets

- `edge_133`
  - best default when browser challenge solving matters
- `chrome_*`
  - good default for TLS-first traffic
- `firefox_*`
  - useful when you specifically want Firefox-like TLS and HTTP/2 behavior

## Runtime Files

ViperTLS keeps writable runtime files in a single project-local folder when possible.

Typical layout:

- `vipertls/.playwright`
- `vipertls/solver/cookies.json`

You can inspect the active paths with:

```bash
vipertls paths
```

Or from Python:

```python
import vipertls

print(vipertls.get_runtime_paths())
```

## Response Metadata

When you use the Python client, responses expose ViperTLS-specific information directly:

```python
response.solved_by
response.from_cache
response.cookies_received
response.cookies_used
response.solve_info
response.tls_resumed
response.h2_priority
response.ja4_profile
```

## Proxy Formats

Supported:

- `http://host:port`
- `http://user:pass@host:port`
- `socks4://host:port`
- `socks5://host:port`
- `socks5h://host:port`
- `ip:port`
- `ip:port:user:pass`

Short proxy forms like `ip:port` and `ip:port:user:pass` are treated as HTTP CONNECT proxies.

## Hosted Deployments

ViperTLS works well as a hosted API, but browser solving depends on the host environment.

Important notes:

- prefer Python `3.12` on Railway/Render-style hosts
- Linux browser solving needs Playwright system dependencies
- on Linux, use `vipertls install-browsers --with-deps` when the platform allows it
- if the platform blocks system package installation, browser solving may fail even if TLS mode still works

## Railway Note

If you deploy the included `railway` demo, make sure Railway uses the `railway` folder as the service root.

That demo includes:

- `nixpacks.toml`
- `.python-version`
- `runtime.txt`

so the deployment can install browser dependencies and stay on Python `3.12`.

## Known Limits

- HTTP/3 / QUIC is not implemented yet
- some low-level TLS tuning depends on CPython internals
- browser solving quality still depends on host environment, browser runtime deps, and site behavior

## Project Links

- PyPI: https://pypi.org/project/vipertls/
- GitHub: https://github.com/walterwhite-69/ViperTLS

## License

MIT
