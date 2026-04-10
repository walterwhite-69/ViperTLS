
                      
import argparse
import os
import platform
import subprocess
import sys

from vipertls.runtime import browsers_path, configure_playwright_env, runtime_home


def _is_nixos() -> bool:
    if os.path.exists("/etc/NIXOS"):
        return True
    if os.environ.get("NIX_STORE") or os.environ.get("NIX_PATH"):
        return True
    nix_build = os.environ.get("NIX_BUILD_TOP")
    if nix_build:
        return True
    try:
        with open("/etc/os-release") as f:
            return "nixos" in f.read().lower()
    except OSError:
        return False


def install_playwright_browsers(browsers: list[str] | None = None, with_deps: bool = False) -> int:
    targets = browsers or ["chromium"]
    browsers_dir = configure_playwright_env()
    env = dict(os.environ)
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers_dir)
    print(f"ViperTLS home: {runtime_home(create=True)}")
    print(f"Installing Playwright browsers into {browsers_dir} ...")
    command = [sys.executable, "-m", "playwright", "install"]
    on_linux = platform.system().lower() == "linux"
    on_nix = _is_nixos()
    if with_deps and on_linux and not on_nix:
        command.append("--with-deps")
    command.extend(targets)
    result = subprocess.run(
        command,
        env=env,
    )
    if result.returncode == 0:
        print("Done. Playwright browsers are ready for ViperTLS.")
    else:
        print("Browser install failed.", file=sys.stderr)
        if on_linux and not on_nix and not with_deps:
            print("Tip: retry with --with-deps on Linux if the browser is crashing from missing .so libraries.", file=sys.stderr)
        elif on_nix:
            print("NixOS detected — system deps must be provided via replit.nix / shell.nix, not --with-deps.", file=sys.stderr)
    return result.returncode


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vipertls-install-browsers",
        description="Install Playwright browser binaries into the ViperTLS runtime home.",
    )
    parser.add_argument(
        "browsers",
        nargs="*",
        default=["chromium"],
        help="Playwright browser targets to install (default: chromium)",
    )
    parser.add_argument(
        "--with-deps",
        action="store_true",
        help="On Linux, ask Playwright to install required system dependencies too.",
    )
    args = parser.parse_args()
    raise SystemExit(install_playwright_browsers(args.browsers, with_deps=args.with_deps))

if __name__ == "__main__":
    main()
