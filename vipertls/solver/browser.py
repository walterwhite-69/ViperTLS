
import asyncio
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict

from urllib.parse import urlparse
from playwright.async_api import async_playwright, Browser, BrowserContext
from playwright_stealth import Stealth

from ..runtime import browsers_path, configure_playwright_env, solver_cookie_file
from .stealth import build_stealth_script

def _playwright_default_browsers_path():
    try:
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if "Install location:" in line:
                raw = line.split("Install location:", 1)[1].strip()
                return str(Path(raw).parent)
    except Exception:
        pass
    return None


_PLAYWRIGHT_CACHE_PATH = _playwright_default_browsers_path()


_CHALLENGE_TITLES = {
    "just a moment",
    "attention required",
    "checking your browser",
    "verify you are human",
}
_CHALLENGE_STATUSES = {403, 503}
_CHALLENGE_MARKERS = [
    "_cf_chl_opt",
    "cdn-cgi/challenge-platform",
    "v-form-container",
    "cf-chl-prog",
    "turnstile",
    "challenge-form",
    "cf-challenge-running",
    "cf-please-wait",
    "cf-browser-verification",
    "cf-im-under-attack",
    "cf-spinner-please-wait",
    "why_captcha",
    "challenge-stage",
    "verify you are human",
    'id="challenge-running"',
    'id="cf-challenge-state"',
    'class="ray-id"',
    "cf-error-code",
    "lds-ring",
]
_HARD_CHALLENGE_MARKERS = [
    "_cf_chl_opt",
    "cf-challenge-running",
    "cf-please-wait",
    "cf-browser-verification",
    "cf-im-under-attack",
    "cf-spinner-please-wait",
    "why_captcha",
    "challenge-form",
    "challenge-stage",
    "verify you are human",
    'id="challenge-running"',
    'id="cf-challenge-state"',
    "cf-error-code",
]
_COOKIE_TTL = 7200
_CACHE_FILE = solver_cookie_file(create=True)
_LOCAL_BROWSERS = browsers_path()
_SOLVER_DEBUG = os.getenv("VIPERTLS_SOLVER_DEBUG", "").lower() in {"1", "true", "yes", "on"}
_STRONG_BROWSER_RETRY = os.getenv("VIPERTLS_STRONG_BROWSER_RETRY", "").lower() in {"1", "true", "yes", "on"}
_SOLVER_SESSION_TTL = int(os.getenv("VIPERTLS_SOLVER_SESSION_TTL", "300"))
_WAIT_AFTER_SOLVE = float(os.getenv("VIPERTLS_WAIT_AFTER_SOLVE", "1.5"))
_USE_STEALTH = os.getenv("VIPERTLS_SOLVER_USE_STEALTH", "").lower() in {"1", "true", "yes", "on"}
_REUSE_SESSIONS = os.getenv("VIPERTLS_SOLVER_REUSE_SESSIONS", "").lower() in {"1", "true", "yes", "on"}
_BLOCK_RESOURCES = os.getenv("VIPERTLS_SOLVER_BLOCK_RESOURCES", "").lower() in {"1", "true", "yes", "on"}
_SOLVE_BUDGET_SECONDS = float(os.getenv("VIPERTLS_SOLVER_BUDGET", "24"))
_AUTO_INSTALL_BROWSERS = os.getenv("VIPERTLS_AUTO_INSTALL_BROWSERS", "1").lower() in {"1", "true", "yes", "on"}
_AUTO_INSTALL_ATTEMPTED = False

_UA_VERSION_RE = re.compile(r"(?:Chrome|Edg|OPR|Brave)/([\d.]+)")


def _solver_debug(message: str) -> None:
    if _SOLVER_DEBUG:
        print(message)


def _short_failure_reason(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        return "unknown"
    lower = text.lower()
    if "cname cross-user banned" in lower:
        return "cloudflare banned page"
    if ".so" in lower or "shared library" in lower or "shared object" in lower or "libnss" in lower:
        return "missing browser dependency"
    if "target page, context or browser has been closed" in lower or "browser has been closed" in lower:
        return "browser crashed"
    if "just a moment" in lower or "verify you are human" in lower or "challenge" in lower:
        return "stuck on challenge page"
    if "timeout" in lower:
        return "timeout"
    return text[:120]


def _browser_family_from_path(executable_path: str | None) -> str:
    path = (executable_path or "").lower()
    if "msedge" in path or "edge" in path:
        return "edge"
    if "brave" in path:
        return "brave"
    if "opera" in path or "opr" in path:
        return "opera"
    return "chrome"


def _major_version(version: str) -> str:
    return (version.split(".", 1)[0] if version else "145") or "145"


def _full_version_from_ua(user_agent: str) -> str | None:
    match = _UA_VERSION_RE.search(user_agent or "")
    return match.group(1) if match else None


def _brand_triplet(family: str, major: str) -> list[dict[str, str]]:
    if family == "edge":
        primary = "Microsoft Edge"
    elif family == "brave":
        primary = "Brave"
    elif family == "opera":
        primary = "Opera"
    else:
        primary = "Google Chrome"
    return [
        {"brand": primary, "version": major},
        {"brand": "Chromium", "version": major},
        {"brand": "Not_A Brand", "version": "24"},
    ]


def _build_solver_user_agent(family: str, full_version: str) -> str:
    suffix = {
        "edge": f" Edg/{full_version}",
        "opera": f" OPR/{full_version}",
    }.get(family, "")
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{full_version} Safari/537.36{suffix}"
    )


def _build_solver_identity(family: str, browser_version: str, requested_user_agent: str) -> dict[str, object]:
    full_version = browser_version or _full_version_from_ua(requested_user_agent) or "145.0.0.0"
    major = _major_version(full_version)
    brands = _brand_triplet(family, major)
    full_version_list = [
        {
            "brand": item["brand"],
            "version": full_version if item["brand"] != "Not_A Brand" else "24.0.0.0",
        }
        for item in brands
    ]
    user_agent = _build_solver_user_agent(family, full_version)

    sec_ch_ua = ", ".join(f'"{item["brand"]}";v="{item["version"]}"' for item in brands)
    sec_ch_ua_full_version_list = ", ".join(
        f'"{item["brand"]}";v="{item["version"]}"' for item in full_version_list
    )
    return {
        "family": family,
        "user_agent": user_agent,
        "brands": brands,
        "fullVersionList": full_version_list,
        "uaFullVersion": full_version,
        "platformVersion": "10.0.0",
        "headers": {
            "accept-language": "en-US,en;q=0.9",
            "sec-ch-ua": sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-full-version": f'"{full_version}"',
            "sec-ch-ua-full-version-list": sec_ch_ua_full_version_list,
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-model": '""',
            "sec-ch-ua-platform-version": '"10.0.0"',
        },
    }


def _find_chrome_exec() -> Optional[str]:
    return _find_browser_exec("chrome")


def _find_browser_exec(family: str) -> Optional[str]:
    family = (family or "chrome").lower()
    search_roots = [
        str(_LOCAL_BROWSERS),
        os.path.expanduser("~/.cache/ms-playwright"),
        os.path.expandvars(r"%LOCALAPPDATA%\ms-playwright"),
    ]
    if _PLAYWRIGHT_CACHE_PATH and _PLAYWRIGHT_CACHE_PATH not in search_roots:
        search_roots.insert(0, _PLAYWRIGHT_CACHE_PATH)
    patterns_map = {
        "edge": ["edge-local/*/msedge.exe"],
        "brave": [],
        "opera": [],
        "chrome": [
            "chromium-*/chrome-win/chrome.exe",
            "chromium-*/chrome-linux64/chrome",
            "chromium-*/chrome-linux/chrome",
            "chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium",
        ],
    }
    for root in search_roots:
        for pat in patterns_map.get(family, []) + patterns_map["chrome"]:
            matches = sorted(glob.glob(os.path.join(root, pat)), reverse=True)
            if matches:
                return matches[0]

    system_candidates_map = {
        "edge": [
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe",
        ],
        "brave": [
            r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
            r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
            r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe",
        ],
        "opera": [
            r"%LOCALAPPDATA%\Programs\Opera\opera.exe",
            r"C:\Program Files\Opera\opera.exe",
        ],
        "chrome": [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe",
        ],
    }
    system_candidates = system_candidates_map.get(family, system_candidates_map["chrome"])
    for candidate in system_candidates:
        expanded = os.path.expandvars(candidate)
        if os.path.exists(expanded):
            return expanded

    _ensure_local_playwright_browser()
    for root in search_roots:
        for pat in patterns_map.get(family, []) + patterns_map["chrome"]:
            matches = sorted(glob.glob(os.path.join(root, pat)), reverse=True)
            if matches:
                return matches[0]
    return None


def _browsers_path() -> Optional[str]:
    if _LOCAL_BROWSERS.exists():
        return str(_LOCAL_BROWSERS)
    return None


def _ensure_local_playwright_browser() -> None:
    global _AUTO_INSTALL_ATTEMPTED
    if _AUTO_INSTALL_ATTEMPTED or not _AUTO_INSTALL_BROWSERS or _LOCAL_BROWSERS.exists():
        return
    _AUTO_INSTALL_ATTEMPTED = True
    try:
        from install_browsers import install_playwright_browsers

        if install_playwright_browsers(["chromium"], with_deps=(os.name != "nt")) == 0:
            configure_playwright_env()
    except Exception:
        pass


_CHROME_EXEC: Optional[str] = _find_chrome_exec()
_BROWSERS_PATH: Optional[str] = _browsers_path()

if _BROWSERS_PATH:
    configure_playwright_env()

_stealth = Stealth(
    navigator_webdriver=True,
    chrome_app=True,
    chrome_csi=True,
    chrome_load_times=True,
    chrome_runtime=False,
    hairline=True,
    iframe_content_window=True,
    media_codecs=True,
    navigator_hardware_concurrency=True,
    navigator_languages=True,
    navigator_permissions=True,
    navigator_platform=True,
    navigator_plugins=True,
    navigator_user_agent=True,
    navigator_vendor=True,
    error_prototype=True,
    sec_ch_ua=True,
    webgl_vendor=True,
    navigator_platform_override="Win32",
    navigator_vendor_override="Google Inc.",
)


@dataclass
class SolveResult:
    url: str
    status: int
    html: str
    cookies: dict[str, str]
    user_agent: str
    method: str
    elapsed_ms: float
    headers: dict[str, str] = field(default_factory=dict)
    reason: str = ""


@dataclass
class _SolverSession:
    context: BrowserContext
    created_at: float
    last_used_at: float


def _domain(url: str) -> str:
    h = urlparse(url).hostname or ""
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def is_challenge(status_code: int, html: str, headers: dict | None = None) -> bool:
    lower_headers = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    lower = (html or "").lower()

    if lower_headers.get("cf-chl-prog"):
        return True
    if "challenge-platform" in lower_headers.get("location", ""):
        return True
    if any(t in lower for t in _CHALLENGE_TITLES):
        return True
    if status_code in _CHALLENGE_STATUSES and any(marker in lower for marker in _CHALLENGE_MARKERS):
        return True

    if status_code in _CHALLENGE_STATUSES:
        if any(m in lower for m in _CHALLENGE_MARKERS):
            return True
        return bool(lower_headers.get("cf-ray") or lower_headers.get("server") == "cloudflare")

    return False


def _is_challenge_title(title: str) -> bool:
    t = title.lower()
    return any(k in t for k in _CHALLENGE_TITLES)


def _body_looks_resolved(html: str) -> bool:
    lower = (html or "").lower()
    if any(t in lower for t in _CHALLENGE_TITLES):
        return False
    if any(marker in lower for marker in _HARD_CHALLENGE_MARKERS):
        return False
    return True


def _page_looks_resolved(title: str, html: str) -> bool:
    if title and not _is_challenge_title(title) and _body_looks_resolved(html):
        return True
    if html and _body_looks_resolved(html) and not is_challenge(200, html, {}):
        return True
    return False


async def _safe_page_content(page) -> str:
    try:
        return await page.content()
    except Exception:
        return ""


async def _safe_page_title(page) -> str:
    try:
        return await page.title()
    except Exception:
        return ""


async def _capture_page_state(page, ctx: BrowserContext, attempts: int = 8, delay: float = 0.6) -> tuple[str, str, list]:
    last_title = ""
    last_html = ""
    last_cookies: list = []
    for _ in range(attempts):
        title = await _safe_page_title(page)
        html = await _safe_page_content(page)
        try:
            cookies = await ctx.cookies()
        except Exception:
            cookies = last_cookies

        if html:
            return title, html, cookies

        last_title = title
        last_html = html
        last_cookies = cookies
        await asyncio.sleep(delay)

    return last_title, last_html, last_cookies


async def _safe_debug_screenshot(page, domain: str) -> str | None:
    safe_domain = re.sub(r"[^a-zA-Z0-9._-]+", "_", domain or "challenge")
    out = Path(tempfile.gettempdir()) / f"vipertls_{safe_domain}_solver_debug.png"
    try:
        await page.screenshot(path=str(out))
        return str(out)
    except Exception:
        return None


async def _find_cloudflare_widget_frame(page):
    frame_selectors = [
        'iframe[title*="Cloudflare security challenge"]',
        'iframe[src*="challenge-platform"]',
        'iframe[id^="cf-chl-widget-"]',
    ]
    for selector in frame_selectors:
        try:
            handle = await page.query_selector(selector)
        except Exception:
            handle = None
        if not handle:
            continue
        try:
            frame = await handle.content_frame()
        except Exception:
            frame = None
        if frame:
            return frame, handle
    for frame in page.frames:
        if any(token in (frame.url or "") for token in ("challenge-platform", "turnstile")):
            try:
                return frame, await frame.frame_element()
            except Exception:
                continue
    return None, None


async def _click_cloudflare_widget(page) -> bool:
    frame, frame_element = await _find_cloudflare_widget_frame(page)
    if not frame or not frame_element:
        return False

    try:
        await frame_element.scroll_into_view_if_needed()
    except Exception:
        pass

    try:
        await frame_element.focus()
    except Exception:
        pass

    f_box = await frame_element.bounding_box()
    if not f_box:
        return False

    rel_candidates = [
        (min(24, max(18, f_box["width"] * 0.08)), f_box["height"] * 0.50),
        (min(30, max(22, f_box["width"] * 0.10)), f_box["height"] * 0.50),
        (min(36, max(26, f_box["width"] * 0.12)), f_box["height"] * 0.50),
        (min(24, max(18, f_box["width"] * 0.08)), f_box["height"] * 0.40),
        (min(24, max(18, f_box["width"] * 0.08)), f_box["height"] * 0.60),
    ]

    for rx, ry in rel_candidates:
        cx = f_box["x"] + rx
        cy = f_box["y"] + ry
        try:
            _solver_debug(f"    [Solver] CF WIDGET CLICK: abs=({int(cx)}, {int(cy)}) rel=({int(rx)}, {int(ry)})")
            await page.mouse.move(cx, cy)
            await frame_element.click(
                position={"x": float(rx), "y": float(ry)},
                force=True,
                timeout=1500,
            )
            await asyncio.sleep(1.0)
            try:
                await page.mouse.down()
                await page.mouse.up()
                await asyncio.sleep(0.4)
            except Exception:
                pass
        except Exception:
            try:
                await page.mouse.click(cx, cy)
                await asyncio.sleep(1.0)
            except Exception:
                continue

    for selector in (
        'iframe[title*="Cloudflare security challenge"]',
        'iframe[src*="challenge-platform"]',
        'iframe[id^="cf-chl-widget-"]',
    ):
        try:
            handle = await page.query_selector(selector)
            if handle:
                await handle.focus()
                await page.keyboard.press("Space")
                await asyncio.sleep(0.75)
                await page.keyboard.press("Enter")
                await asyncio.sleep(0.75)
                break
        except Exception:
            continue

    try:
        checkbox = await frame.query_selector(
            "input[type='checkbox'], label.ctp-checkbox-label, .ctp-checkbox-label, .cb-lb, .cb-i"
        )
        if checkbox and await checkbox.is_visible():
            try:
                await checkbox.click(force=True, timeout=1500)
                await asyncio.sleep(1.0)
            except Exception:
                pass
    except Exception:
        pass

    return True


class _CookieCache:
    def __init__(self) -> None:
        self._store: dict[str, tuple[list, float, str | None, dict, float | None]] = {}
        self._load()

    def _load(self) -> None:
        if not _CACHE_FILE.exists():
            return
        try:
            with open(_CACHE_FILE, "r") as f:
                data = json.load(f)
                now = time.time()
                for key, entry in data.items():
                    cookies = entry[0]
                    ts = entry[1]
                    ua = entry[2] if len(entry) > 2 else None
                    h = entry[3] if len(entry) > 3 else {}
                    expires_at = entry[4] if len(entry) > 4 else None

                    if expires_at is None:
                        cf_cookie = next((c for c in cookies if c.get("name") == "cf_clearance"), None)
                        expires_at = cf_cookie.get("expires") if cf_cookie else None

                    if expires_at and expires_at <= now:
                        continue
                    if expires_at is None and now - ts >= _COOKIE_TTL:
                        continue

                    offset = now - ts
                    self._store[key] = (cookies, time.monotonic() - offset, ua, h, expires_at)
        except Exception:
            pass

    def _save(self) -> None:
        try:
            now = time.time()
            out = {}
            for key, entry in self._store.items():
                cookies, mono_ts, ua, h, expires_at = entry
                offset = time.monotonic() - mono_ts
                out[key] = (cookies, now - offset, ua, h, expires_at)

            with open(_CACHE_FILE, "w") as f:
                json.dump(out, f)
        except Exception:
            pass

    def _get_key(self, domain: str, preset: str) -> str:
        return f"{domain}:{preset}"

    def set(self, domain: str, preset: str, cookies: list, user_agent: str, headers: dict) -> None:
        key = self._get_key(domain, preset)
        cf_cookie = next((c for c in cookies if c.get("name") == "cf_clearance"), None)
        expires_at = cf_cookie.get("expires") if cf_cookie else None
        self._store[key] = (cookies, time.monotonic(), user_agent, headers, expires_at)
        self._save()

    def get(self, domain: str, preset: str) -> Optional[tuple[list, str | None, dict]]:
        key = self._get_key(domain, preset)
        entry = self._store.get(key)
        if not entry:
            return None
        cookies, ts, user_agent, headers, expires_at = entry

        now = time.time()
        if expires_at and expires_at <= now:
            del self._store[key]
            self._save()
            return None
        if expires_at is None and time.monotonic() - ts > _COOKIE_TTL:
            del self._store[key]
            self._save()
            return None
        return cookies, user_agent, headers

    def clear(self, domain: str, preset: str) -> None:
        key = self._get_key(domain, preset)
        self._store.pop(key, None)
        self._save()

    def clear_domain(self, domain: str) -> None:
        suffix = f"{domain}:"
        keys = [key for key in self._store if key.startswith(suffix)]
        for key in keys:
            self._store.pop(key, None)
        self._save()

    def clear_all(self) -> None:
        self._store.clear()
        if _CACHE_FILE.exists():
            try:
                os.remove(_CACHE_FILE)
            except:
                pass


_cache = _CookieCache()


class CloudflareSolver:
    _pw = None
    _browsers: dict[tuple[str, bool], Browser] = {}
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CloudflareSolver, cls).__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not hasattr(self, "_sessions"):
            self._sessions: dict[str, _SolverSession] = {}

    async def _ensure_browser(self, family: str = "chrome", headless: bool = True) -> Browser:
        family = (family or "chrome").lower()
        key = (family, headless)
        browser = self._browsers.get(key)
        if browser and browser.is_connected():
            return browser

        if self._pw is None:
            self._pw = await async_playwright().start()

        args = [
            "--disable-blink-features=AutomationControlled",
        ]
        if os.name != "nt":
            args.append("--no-sandbox")
        if headless:
            args.insert(0, "--headless=new")

        launch_kwargs = {
            "headless": headless,
            "args": args,
        }
        executable_path = _find_browser_exec(family) or _CHROME_EXEC
        if executable_path:
            launch_kwargs["executable_path"] = executable_path

        browser = await self._browser_type().launch(**launch_kwargs)
        self._browsers[key] = browser
        return browser

    def _browser_type(self):
        return self._pw.chromium

    def _session_key(self, *, domain: str, preset: str, headless: bool, full_resources: bool) -> str:
        return f"{domain}|{preset}|{int(headless)}|{int(full_resources)}"

    async def _expire_sessions(self) -> None:
        now = time.monotonic()
        expired = [
            key for key, session in self._sessions.items()
            if now - session.last_used_at > _SOLVER_SESSION_TTL
        ]
        for key in expired:
            session = self._sessions.pop(key)
            try:
                await session.context.close()
            except Exception:
                pass

    async def _get_or_create_context(
        self,
        *,
        browser: Browser,
        identity: dict[str, object],
        domain: str,
        preset: str,
        headless: bool,
        full_resources: bool,
    ) -> BrowserContext:
        if not _REUSE_SESSIONS:
            return await self._make_context(browser, identity, full_resources=full_resources)

        await self._expire_sessions()
        key = self._session_key(
            domain=domain,
            preset=preset,
            headless=headless,
            full_resources=full_resources,
        )
        session = self._sessions.get(key)
        if session:
            session.last_used_at = time.monotonic()
            return session.context

        context = await self._make_context(browser, identity, full_resources=full_resources)
        self._sessions[key] = _SolverSession(
            context=context,
            created_at=time.monotonic(),
            last_used_at=time.monotonic(),
        )
        return context

    async def _make_context(
        self,
        browser: Browser,
        identity: dict[str, object],
        full_resources: bool = False,
    ) -> BrowserContext:
        ctx = await browser.new_context(
            user_agent=str(identity["user_agent"]),
            viewport={"width": 1366, "height": 768},
            screen={"width": 1366, "height": 768},
            locale="en-US",
            timezone_id="America/New_York",
            color_scheme="light",
            java_script_enabled=True,
            accept_downloads=False,
            extra_http_headers={
                "accept-language": "en-US,en;q=0.9",
            },
        )

        async def handle_route(route):
            req = route.request
            url = req.url
            if full_resources or not _BLOCK_RESOURCES:
                await route.continue_()
                return
            if "challenges.cloudflare.com" in url or "turnstile" in url:
                await route.continue_()
                return

            if req.resource_type in ["image", "media", "font"]:
                await route.abort()
            elif req.resource_type == "stylesheet" and "tempmail.la" in url:
                await route.abort()
            else:
                await route.continue_()

        await ctx.route("**/*", handle_route)

        if _USE_STEALTH:
            await _stealth.apply_stealth_async(ctx)
            await ctx.add_init_script(build_stealth_script(identity))
        return ctx

    async def _wait_for_clearance(self, page, ctx: BrowserContext, deadline: float) -> bool:
        last_click = 0.0
        last_reload = 0.0
        started = time.monotonic()

        while time.monotonic() < deadline:
            try:
                cookies = await ctx.cookies()
            except Exception:
                await asyncio.sleep(0.25)
                continue

            if any(c["name"] == "cf_clearance" for c in cookies):
                return True

            title = await _safe_page_title(page)
            html = await _safe_page_content(page)

            if _page_looks_resolved(title, html):
                return True

            if time.monotonic() - last_click > 2.5:
                try:
                    if await _click_cloudflare_widget(page):
                        last_click = time.monotonic()
                        await asyncio.sleep(2.0)
                        continue

                    def get_all_frames(frame):
                        frames = [frame]
                        for child in frame.child_frames:
                            frames.extend(get_all_frames(child))
                        return frames

                    all_frames = get_all_frames(page.main_frame)
                    for frame in all_frames:
                        success = await frame.query_selector("#success-text, .success, .cb-success, .success-string")
                        if success and await success.is_visible():
                            return True

                        target = await frame.query_selector(".cb-lb, .cb-i, .ctp-checkbox-label, input[type='checkbox']")
                        if target and await target.is_visible():
                            box = await target.bounding_box()
                            frame_element = await frame.frame_element()
                            f_box = await frame_element.bounding_box() if frame_element else None

                            if box:
                                cx, cy = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
                                if f_box:
                                    cx += f_box["x"]
                                    cy += f_box["y"]

                                _solver_debug(f"    [Solver] TARGET LOCKED: Click at ({int(cx)}, {int(cy)})")
                                await page.mouse.move(cx, cy)
                                await page.mouse.click(cx, cy)
                                try:
                                    await target.click(force=True, timeout=1000)
                                except Exception:
                                    pass

                                last_click = time.monotonic()
                                await asyncio.sleep(1.5)
                                break
                except Exception:
                    pass

            if (
                time.monotonic() - started > 10
                and not any(c["name"] == "cf_clearance" for c in cookies)
                and _is_challenge_title(title or "")
                and "turnstile" not in (html or "").lower()
            ):
                return False

            if time.monotonic() - last_reload > 10 and is_challenge(403, html or title, {"server": "cloudflare"}):
                try:
                    await page.reload(wait_until="domcontentloaded", timeout=8000)
                    last_reload = time.monotonic()
                except Exception:
                    last_reload = time.monotonic()

            await asyncio.sleep(0.4)
        return False

    async def _try_direct(
        self,
        url: str,
        user_agent: str,
        cached_cookies: list,
        timeout: int,
        extra_headers: dict | None = None,
    ) -> Optional["SolveResult"]:
        from vipertls.client import AsyncClient

        cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cached_cookies)
        try:
            headers = {
                "user-agent": user_agent,
                "cookie": cookie_header,
            }
            if extra_headers:
                headers.update(extra_headers)

            async with AsyncClient(impersonate="chrome_124", use_solver=False) as client:
                resp = await asyncio.wait_for(
                    client.get(
                        url,
                        headers=headers,
                    ),
                    timeout=timeout,
                )
                if not is_challenge(resp.status_code, resp.text, resp.headers):
                    cookies_dict = {c["name"]: c["value"] for c in cached_cookies}
                    return SolveResult(
                        url=url,
                        status=resp.status_code,
                        html=resp.text,
                        cookies=cookies_dict,
                        user_agent=user_agent,
                        method="cache",
                        elapsed_ms=0.0,
                    )
        except Exception:
            pass
        return None

    async def _run_browser_attempt(
        self,
        url: str,
        user_agent: str,
        preset: str,
        domain: str,
        t0: float,
        *,
        timeout: int,
        headless: bool,
        full_resources: bool,
        cached: Optional[tuple[list, str | None, dict]],
    ) -> "SolveResult":
        requested_family = _browser_family_from_path(_find_browser_exec(preset) or preset)
        if requested_family == "chrome" and preset.lower() in {"edge", "edge_133", "edge_136"}:
            requested_family = "edge"
        browser = await self._ensure_browser(family=requested_family, headless=headless)
        executable_path = _find_browser_exec(requested_family) or _CHROME_EXEC
        identity = _build_solver_identity(
            _browser_family_from_path(executable_path),
            browser.version,
            user_agent,
        )
        ctx = await self._get_or_create_context(
            browser=browser,
            identity=identity,
            domain=domain,
            preset=preset,
            headless=headless,
            full_resources=full_resources,
        )
        if cached:
            existing = {(c["name"], c.get("domain"), c.get("path")) for c in await ctx.cookies()}
            to_add = [
                cookie for cookie in cached[0]
                if (cookie["name"], cookie.get("domain"), cookie.get("path")) not in existing
            ]
            if to_add:
                await ctx.add_cookies(to_add)

        page = await ctx.new_page()
        try:
            budget = min(float(timeout), _SOLVE_BUDGET_SECONDS)
            nav_timeout_ms = 45000
            initial_wait_seconds = min(5.0, max(3.0, budget * 0.22))
            click_wait_seconds = min(8.0, max(4.0, budget * 0.33))

            await page.goto(url, wait_until="domcontentloaded", timeout=nav_timeout_ms)
            await asyncio.sleep(initial_wait_seconds)

            async def _build_success(html: str, cookies: list) -> "SolveResult":
                ua = await page.evaluate("navigator.userAgent")
                hints = await page.evaluate("""() => {
                    if (navigator.userAgentData) {
                        return {
                            'sec-ch-ua': navigator.userAgentData.brands.map(b => `"${b.brand}";v="${b.version}"`).join(', '),
                            'sec-ch-ua-full-version': `"${navigator.userAgentData.uaFullVersion || ''}"`,
                            'sec-ch-ua-full-version-list': (navigator.userAgentData.fullVersionList || []).map(b => `"${b.brand}";v="${b.version}"`).join(', '),
                            'sec-ch-ua-mobile': '?0',
                            'sec-ch-ua-platform': `"${navigator.userAgentData.platform || 'Windows'}"`,
                            'sec-ch-ua-arch': '"x86"',
                            'sec-ch-ua-bitness': '"64"',
                            'sec-ch-ua-model': '""',
                            'sec-ch-ua-platform-version': `"${navigator.userAgentData.platformVersion || '10.0.0'}"`,
                        };
                    }
                    return {};
                }""")
                _cache.set(domain, preset, cookies, ua, hints)
                return SolveResult(
                    status=200,
                    method="browser",
                    html=html,
                    url=page.url,
                    cookies={c["name"]: c["value"] for c in cookies},
                    user_agent=ua,
                    headers=hints,
                    elapsed_ms=(time.perf_counter() - t0) * 1000,
                    reason="",
                )

            initial_title, initial_html, initial_cookies = await _capture_page_state(page, ctx)
            if any(c["name"] == "cf_clearance" for c in initial_cookies) and _page_looks_resolved(initial_title, initial_html):
                return await _build_success(initial_html, initial_cookies)

            clicked = await _click_cloudflare_widget(page)
            if clicked:
                await asyncio.sleep(click_wait_seconds)
                clicked_title, clicked_html, clicked_cookies = await _capture_page_state(page, ctx)
                if any(c["name"] == "cf_clearance" for c in clicked_cookies) and _page_looks_resolved(clicked_title, clicked_html):
                    return await _build_success(clicked_html, clicked_cookies)

            deadline = time.monotonic() + max(2.0, budget - (time.perf_counter() - t0))
            solved = await self._wait_for_clearance(page, ctx, deadline)

            if solved:
                _solver_debug(f"    [Solver] SUCCESS: Stabilizing for {_WAIT_AFTER_SOLVE:.1f}s...")
                await asyncio.sleep(_WAIT_AFTER_SOLVE)
                final_title, final_html, cookies = await _capture_page_state(page, ctx)
                if any(c["name"] == "cf_clearance" for c in cookies) and _page_looks_resolved(final_title, final_html):
                    return await _build_success(final_html, cookies)

            final_title, final_html, cookies = await _capture_page_state(page, ctx)
            if any(c["name"] == "cf_clearance" for c in cookies) and _page_looks_resolved(final_title, final_html):
                return await _build_success(final_html, cookies)

            debug_path = await _safe_debug_screenshot(page, domain)
            failed_html = final_html
            headers = {"x-vipertls-debug-screenshot": debug_path} if debug_path else {}
            return SolveResult(
                status=403,
                method="browser_failed",
                html=failed_html,
                url=page.url,
                cookies={},
                user_agent=user_agent,
                headers={
                    **headers,
                    "x-vipertls-failure-reason": _short_failure_reason(final_title or failed_html),
                },
                elapsed_ms=(time.perf_counter() - t0) * 1000,
                reason=_short_failure_reason(final_title or failed_html),
            )
        finally:
            await page.close()
            if _REUSE_SESSIONS:
                session_key = self._session_key(
                    domain=domain,
                    preset=preset,
                    headless=headless,
                    full_resources=full_resources,
                )
                session = self._sessions.get(session_key)
                if session:
                    session.last_used_at = time.monotonic()
            else:
                try:
                    await ctx.close()
                except Exception:
                    pass

    async def solve(
        self,
        url: str,
        user_agent: str,
        preset: str,
        timeout: int = 30,
    ) -> "SolveResult":
        t0 = time.perf_counter()
        domain = urlparse(url).netloc

        cached = _cache.get(domain, preset)
        if cached:
            cached_cookies, cached_ua, cached_headers = cached
            direct = await self._try_direct(
                url,
                cached_ua or user_agent,
                cached_cookies,
                timeout,
                cached_headers,
            )
            if direct and direct.status == 200:
                direct.elapsed_ms = (time.perf_counter() - t0) * 1000
                return direct
            _cache.clear(domain, preset)

        attempts = [
            {"headless": True, "full_resources": True},
        ]
        if _STRONG_BROWSER_RETRY:
            attempts.append({"headless": False, "full_resources": True})
        last_result = None
        for attempt in attempts:
            try:
                result = await self._run_browser_attempt(
                    url,
                    user_agent,
                    preset,
                    domain,
                    t0,
                    timeout=timeout,
                    headless=attempt["headless"],
                    full_resources=attempt["full_resources"],
                    cached=cached,
                )
            except Exception as exc:
                reason = _short_failure_reason(str(exc))
                result = SolveResult(
                    status=403,
                    method="browser_failed",
                    html="",
                    url=url,
                    cookies={},
                    user_agent=user_agent,
                    elapsed_ms=(time.perf_counter() - t0) * 1000,
                    headers={"x-vipertls-failure-reason": reason},
                    reason=reason,
                )
            if result.status == 200:
                return result
            last_result = result

        return last_result or SolveResult(
            status=403,
            method="browser_failed",
            html="",
            url=url,
            cookies={},
            user_agent=user_agent,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
            headers={"x-vipertls-failure-reason": "unknown"},
            reason="unknown",
        )

    async def close(self) -> None:
        for session in list(self._sessions.values()):
            try:
                await session.context.close()
            except Exception:
                pass
        self._sessions.clear()
        for browser in list(self._browsers.values()):
            try:
                await browser.close()
            except Exception:
                pass
        self._browsers.clear()
        if self._pw:
            try:
                await self._pw.stop()
            except Exception:
                pass


_global_solver: Optional[CloudflareSolver] = None

async def get_solver() -> CloudflareSolver:
    global _global_solver
    if _global_solver is None:
        _global_solver = CloudflareSolver()
    return _global_solver

def get_cache() -> _CookieCache:
    return _cache


def clear_cache(domain: str | None = None, preset: str | None = None) -> None:
    if domain and preset:
        _cache.clear(domain, preset)
        return
    if domain:
        _cache.clear_domain(domain)
        return
    _cache.clear_all()
