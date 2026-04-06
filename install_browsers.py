#!/usr/bin/env python3
import argparse
import os
import platform
import subprocess
import sys

from vipertls.runtime import browsers_path, configure_playwright_env, runtime_home


def install_playwright_browsers(browsers: list[str] | None = None, with_deps: bool = False) -> int:
    targets = browsers or ["chromium"]
    browsers_dir = configure_playwright_env()
    env = dict(os.environ)
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers_dir)
    print(f"ViperTLS home: {runtime_home(create=True)}")
    print(f"Installing Playwright browsers into {browsers_dir} ...")
    command = [sys.executable, "-m", "playwright", "install"]
    if with_deps and platform.system().lower() == "linux":
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
        if platform.system().lower() == "linux" and not with_deps:
            print("Tip: retry with --with-deps on Linux if the browser is crashing from missing .so libraries.", file=sys.stderr)
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
