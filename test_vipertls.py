import sys
import traceback
import asyncio
import importlib.util
import os
import time

PASS = 0
FAIL = 0


def ok(label):
    global PASS
    PASS += 1
    print(f"  PASS  {label}")


def fail(label, exc=None):
    global FAIL
    FAIL += 1
    print(f"  FAIL  {label}")
    if exc:
        print(f"        {type(exc).__name__}: {exc}")


print(f"\nPython {sys.version}\n")

print("=== JA4 fingerprint family ===")
try:
    from vipertls.fingerprints.ja4 import (
        compute_ja4, compute_ja4_r, compute_ja4h, compute_ja4s, compute_ja4l, ja4_from_preset
    )
    ok("import ja4 module")
except Exception as e:
    fail("import ja4 module", e)
    sys.exit(1)

try:
    cipher_ids = [4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53]
    extension_ids = [18, 27, 65281, 0, 23, 35, 13, 16, 11, 5, 10, 51, 45, 43, 17513, 21]
    alpn = ["h2", "http/1.1"]
    ja4 = compute_ja4(771, cipher_ids, extension_ids, alpn)
    assert ja4.startswith("t13d"), f"Unexpected JA4 prefix: {ja4}"
    assert "_" in ja4
    parts = ja4.split("_")
    assert len(parts) == 3
    ok(f"compute_ja4: {ja4}")
except Exception as e:
    fail("compute_ja4", e)

try:
    ja4_r = compute_ja4_r(771, cipher_ids, extension_ids, alpn)
    assert ja4_r.startswith("t13d")
    ok(f"compute_ja4_r: {ja4_r[:50]}...")
except Exception as e:
    fail("compute_ja4_r", e)

try:
    headers = [
        (":method", "GET"), (":authority", "example.com"), (":scheme", "https"), (":path", "/"),
        ("user-agent", "Mozilla/5.0"), ("accept", "*/*"), ("accept-language", "en-US,en;q=0.9"),
        ("accept-encoding", "gzip, deflate, br"),
    ]
    ja4h = compute_ja4h("GET", "HTTP/2", headers)
    assert ja4h.startswith("ge20")
    parts = ja4h.split("_")
    assert len(parts) == 3
    ok(f"compute_ja4h: {ja4h}")
except Exception as e:
    fail("compute_ja4h", e)

try:
    ja4h_h1 = compute_ja4h("POST", "HTTP/1.1", [("Host", "x.com"), ("Content-Type", "application/json"), ("cookie", "a=b")])
    assert ja4h_h1.startswith("po11")
    assert "c" in ja4h_h1[:10]
    ok(f"compute_ja4h HTTP/1.1: {ja4h_h1}")
except Exception as e:
    fail("compute_ja4h HTTP/1.1", e)

try:
    ja4s = compute_ja4s("TLSv1.3", "TLS_AES_128_GCM_SHA256", 0x1301)
    assert ja4s.startswith("t13d")
    ok(f"compute_ja4s: {ja4s}")
except Exception as e:
    fail("compute_ja4s", e)

try:
    ja4l = compute_ja4l(12.7, 38.4)
    assert ja4l == "13_38", f"Got: {ja4l}"
    ok(f"compute_ja4l: {ja4l}")
except Exception as e:
    fail("compute_ja4l", e)

try:
    ja4_p, ja4_r_p = ja4_from_preset(
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
        "18-27-65281-0-23-35-13-16-11-5-10-51-45-43-17513-21,29-23-24,0",
        ["h2", "http/1.1"]
    )
    assert ja4_p.startswith("t13d")
    assert ja4_r_p.startswith("t13d")
    ok(f"ja4_from_preset: {ja4_p}")
except Exception as e:
    fail("ja4_from_preset", e)

print("\n=== Presets with JA4 ===")
try:
    from vipertls.fingerprints.presets import PRESETS, BrowserPreset
    ok("import presets")
except Exception as e:
    fail("import presets", e)
    sys.exit(1)

try:
    chrome = PRESETS["chrome_124"]
    assert chrome.ja4, "ja4 is empty"
    assert chrome.ja4_r, "ja4_r is empty"
    assert chrome.ja4.startswith("t13d"), f"Unexpected: {chrome.ja4}"
    assert chrome.quic_params.get("max_data") == 15728640
    ok(f"chrome_124 ja4={chrome.ja4}")
except Exception as e:
    fail("chrome_124 preset ja4", e)

try:
    ff = PRESETS["firefox_136"]
    assert ff.ja4, "ja4 is empty"
    assert ff.quic_params.get("max_data") == 12582912
    assert ff.quic_params.get("max_streams_bidi") == 16
    ok(f"firefox_136 ja4={ff.ja4}, quic_params OK")
except Exception as e:
    fail("firefox_136 preset ja4/quic_params", e)

try:
    for name, preset in PRESETS.items():
        if name in ("chrome", "firefox", "safari", "edge", "brave", "opera"):
            continue
        assert preset.ja4, f"{name} has empty ja4"
        assert preset.quic_params, f"{name} has empty quic_params"
    ok("all presets have ja4 and quic_params")
except Exception as e:
    fail("all presets check", e)

print("\n=== TLS layer (pyOpenSSL) ===")
try:
    from vipertls.core.tls import (
        _PYOSSL_AVAILABLE, _build_pyossl_context, _build_stdlib_context,
        open_tls_connection, _ViperSSLSocket
    )
    ok(f"import tls module (pyOpenSSL available: {_PYOSSL_AVAILABLE})")
except Exception as e:
    fail("import tls module", e)

try:
    if _PYOSSL_AVAILABLE:
        chrome_preset = PRESETS["chrome_124"]
        ctx = _build_pyossl_context(chrome_preset, None, verify=False)
        assert ctx is not None
        ok("build pyOpenSSL context")
    else:
        ok("pyOpenSSL not available, skipping context test")
except Exception as e:
    fail("build pyOpenSSL context", e)

try:
    chrome_preset = PRESETS["chrome_124"]
    ctx = _build_stdlib_context(chrome_preset, None, verify=False)
    import ssl
    assert isinstance(ctx, ssl.SSLContext)
    ok("build stdlib SSL context")
except Exception as e:
    fail("build stdlib SSL context", e)

print("\n=== Client interface ===")
try:
    from vipertls.client import AsyncClient, Client
    ok("import AsyncClient, Client")
except Exception as e:
    fail("import AsyncClient, Client", e)
    sys.exit(1)

try:
    client = AsyncClient(impersonate="chrome_124")
    assert client._preset.name == "chrome_124"
    ok("AsyncClient instantiation")
except Exception as e:
    fail("AsyncClient instantiation", e)

try:
    client_h3 = AsyncClient(impersonate="chrome_124", http3=True)
    assert client_h3._force_h3
    ok("AsyncClient with http3=True")
except Exception as e:
    fail("AsyncClient http3=True", e)

print("\n=== HTTP2 with JA4H ===")
try:
    from vipertls.core.http2 import HTTP2Connection, _build_header_list
    headers_list = _build_header_list(
        "GET", "example.com", "https", "/", "",
        {"accept": "text/html"}, PRESETS["chrome_124"], [":method", ":authority", ":scheme", ":path"]
    )
    assert any(h == ":method" for h, _ in headers_list)
    ok(f"http2 _build_header_list: {len(headers_list)} headers")
except Exception as e:
    fail("http2 _build_header_list", e)

print("\n=== HTTP1 with JA4H ===")
try:
    from vipertls.core.http1 import _serialize_headers
    raw_bytes, ordered = _serialize_headers("example.com", {"accept": "text/html"}, PRESETS["chrome_124"], None)
    assert raw_bytes
    assert isinstance(ordered, list)
    assert len(ordered) > 0
    ok(f"http1 _serialize_headers: {len(ordered)} headers")
except Exception as e:
    fail("http1 _serialize_headers", e)

print("\n=== Response object ===")
try:
    from vipertls.core.response import ViperResponse
    resp = ViperResponse(
        status_code=200,
        headers={
            "x-vipertls-ja4": "t13d15h2_abc123def456_xyz789abc123",
            "x-vipertls-ja4-r": "t13d15h2_47,52,49195_0,5,10,13",
            "x-vipertls-ja4h": "ge20nn05enUS_abc123def456_xyz789abc123",
            "x-vipertls-ja4s": "t13d02_1301_abc123def456",
            "x-vipertls-ja4l": "12_38",
            "content-type": "text/plain",
        },
        content=b"hello",
        url="https://example.com",
        http_version="HTTP/2",
    )
    assert resp.ja4 == "t13d15h2_abc123def456_xyz789abc123"
    assert resp.ja4_r == "t13d15h2_47,52,49195_0,5,10,13"
    assert resp.ja4h == "ge20nn05enUS_abc123def456_xyz789abc123"
    assert resp.ja4s == "t13d02_1301_abc123def456"
    assert resp.ja4l == "12_38"
    info = resp.solve_info
    assert "ja4" in info
    assert "ja4h" in info
    assert "ja4s" in info
    assert "ja4l" in info
    ok("ViperResponse JA4 properties + solve_info")
except Exception as e:
    fail("ViperResponse JA4 properties", e)

print("\n=== HTTP/3 module import ===")
try:
    from vipertls.core.http3 import http3_request_blocking, _build_quic_config, _build_h3_headers
    ok("import http3 module")
except Exception as e:
    fail("import http3 module", e)

try:
    chrome_preset = PRESETS["chrome_124"]
    config = _build_quic_config(chrome_preset, "example.com", verify=False)
    ok(f"build QUIC config: {type(config).__name__}")
except Exception as e:
    fail("build QUIC config", e)

try:
    chrome_preset = PRESETS["chrome_124"]
    h3_headers = _build_h3_headers("GET", "example.com", "/", "", "https", {}, chrome_preset)
    method_header = next((v for k, v in h3_headers if k == b":method"), None)
    assert method_header == b"GET"
    ok(f"build H3 headers: {len(h3_headers)} headers")
except Exception as e:
    fail("build H3 headers", e)

print("\n=== CLI cross-platform import ===")
try:
    cli_path = os.path.join(os.path.dirname(__file__), "vipertls.py")
    spec = importlib.util.spec_from_file_location("vipertls_cli", cli_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ok("CLI loads without error on this OS")
    assert hasattr(mod, "_IS_WIN"), "_IS_WIN not defined"
    ok(f"_IS_WIN={mod._IS_WIN} (platform={sys.platform})")
    assert hasattr(mod, "_poll_input")
    ok("_poll_input defined (cross-platform)")
    assert hasattr(mod, "_handle_key")
    ok("_handle_key defined")
    assert hasattr(mod, "main")
    ok("main() defined")
    if mod._IS_WIN:
        import msvcrt
        ok("Windows: msvcrt available")
    else:
        import termios, tty, select
        ok("Unix: termios/tty/select available")
except Exception as e:
    fail("CLI cross-platform check", e)
    traceback.print_exc()

print("\n=== Live request (httpbin.org) ===")
try:
    async def _live_httpbin():
        async with AsyncClient(impersonate="chrome_124", verify=False) as client:
            return await client.get("https://httpbin.org/get", headers={"accept": "application/json"})
    r = asyncio.run(_live_httpbin())
    assert r.status_code == 200, f"Status: {r.status_code}"
    assert r.ja4, f"ja4 empty, headers: {r.headers}"
    assert r.ja4h, "ja4h empty"
    ok(f"live GET httpbin.org: status={r.status_code} ja4={r.ja4}")
    ok(f"  ja4h={r.ja4h}")
    ok(f"  ja4s={r.ja4s}")
    ok(f"  ja4l={r.ja4l}")
    ok(f"  tls_resumed={r.tls_resumed} http_version={r.http_version}")
except Exception as e:
    fail("live request to httpbin.org", e)
    traceback.print_exc()

print("\n=== Live request (crunchyroll.com — TLS only) ===")
try:
    async def _live_crunchyroll():
        results = []
        for preset in ["chrome_136", "firefox_136", "edge_136"]:
            t0 = time.perf_counter()
            try:
                async with AsyncClient(impersonate=preset) as client:
                    r = await client.get("https://www.crunchyroll.com/")
                    elapsed = (time.perf_counter() - t0) * 1000
                    results.append((preset, r.status_code, r.solved_by, elapsed, len(r.content), None))
            except Exception as exc:
                elapsed = (time.perf_counter() - t0) * 1000
                results.append((preset, None, None, elapsed, 0, exc))
        return results
    results = asyncio.run(_live_crunchyroll())
    for preset, status, solved_by, elapsed, size, exc in results:
        if exc:
            fail(f"crunchyroll preset={preset}", exc)
        else:
            passed = status in (200, 301, 302, 403)
            label = f"crunchyroll preset={preset} status={status} solved_by={solved_by} time={elapsed:.0f}ms size={size}B"
            if passed:
                ok(label)
            else:
                fail(label)
except Exception as e:
    fail("crunchyroll live test", e)
    traceback.print_exc()

print("\n=== Live request (1337x.to — browser solver) ===")
try:
    async def _live_1337x():
        results = []
        for preset in ["edge_133", "chrome_133"]:
            t0 = time.perf_counter()
            try:
                async with AsyncClient(impersonate=preset) as client:
                    r = await client.get("https://www.1337x.to/")
                    elapsed = (time.perf_counter() - t0) * 1000
                    results.append((preset, r.status_code, r.solved_by, elapsed, len(r.content), None))
            except Exception as exc:
                elapsed = (time.perf_counter() - t0) * 1000
                results.append((preset, None, None, elapsed, 0, exc))
        return results
    results = asyncio.run(_live_1337x())
    for preset, status, solved_by, elapsed, size, exc in results:
        if exc:
            fail(f"1337x preset={preset}", exc)
        else:
            passed = status in (200, 301, 302)
            label = f"1337x preset={preset} status={status} solved_by={solved_by} time={elapsed:.0f}ms size={size}B"
            if passed:
                ok(label)
            else:
                fail(label)
except Exception as e:
    fail("1337x live test", e)
    traceback.print_exc()

print(f"\n{'='*40}")
print(f"Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)
