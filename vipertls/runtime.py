from __future__ import annotations

import os
import sys
from pathlib import Path


_PACKAGE_ROOT = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_ROOT.parent


def _is_source_checkout() -> bool:
    return (_PROJECT_ROOT / "install_browsers.py").exists() and (_PROJECT_ROOT / "vipertls.py").exists()


def _script_runtime_home() -> Path | None:
    raw = (sys.argv[0] or "").strip()
    if not raw or raw in {"-c", "-m"}:
        return None
    path = Path(raw).expanduser()
    try:
        resolved = path.resolve()
    except Exception:
        return None
    if not resolved.exists() or not resolved.is_file():
        return None
    if resolved.name.lower() in {"vipertls", "vipertls.exe", "python", "python.exe", "pythonw.exe"}:
        return None
    return resolved.parent / ".vipertls"


def _default_runtime_home() -> Path:
    override = os.getenv("VIPERTLS_HOME")
    if override:
        return Path(override).expanduser().resolve()

    if _is_source_checkout():
        return _PROJECT_ROOT

    script_home = _script_runtime_home()
    if script_home is not None:
        return script_home

    if os.name == "nt":
        base = Path(os.getenv("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        return base / "vipertls"

    xdg = os.getenv("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).expanduser().resolve() / "vipertls"

    return Path.home() / ".local" / "share" / "vipertls"


def runtime_home(create: bool = False) -> Path:
    home = _default_runtime_home()
    if create:
        home.mkdir(parents=True, exist_ok=True)
    return home


def browsers_path(create: bool = False) -> Path:
    path = runtime_home(create=create) / ".playwright"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def solver_dir(create: bool = False) -> Path:
    path = runtime_home(create=create) / "solver"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def solver_cookie_file(create: bool = False) -> Path:
    path = solver_dir(create=create) / "cookies.json"
    if create:
        path.parent.mkdir(parents=True, exist_ok=True)
    return path


def configure_playwright_env() -> Path:
    path = browsers_path(create=True)
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(path))
    return path


def describe_runtime_paths() -> dict[str, str]:
    return {
        "home": str(runtime_home()),
        "browsers": str(browsers_path()),
        "cookies": str(solver_cookie_file()),
    }
