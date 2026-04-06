import argparse
import sys
import uvicorn

from install_browsers import install_playwright_browsers
from . import __version__
from .runtime import describe_runtime_paths
from .server import app


def _overview() -> str:
    return (
        f"ViperTLS {__version__}\n"
        "Pure Python TLS fingerprinting with browser challenge fallback.\n\n"
        "Main commands:\n"
        "  vipertls serve              Start the local ViperTLS proxy server\n"
        "  vipertls install-browsers   Install Playwright browser binaries\n"
        "  vipertls paths              Show runtime directories\n"
        "  vipertls version            Show installed version\n"
        "  vipertls --help             Show full CLI help\n\n"
        "Recommended presets:\n"
        "  edge_133    Best default when browser challenge solving matters\n"
        "  chrome_*    Fine for TLS-first requests\n\n"
        "Use 'vipertls serve --help' to see server options."
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vipertls",
        description="ViperTLS command line interface",
        epilog=(
            "Examples:\n"
            "  vipertls\n"
            "  vipertls serve --host 127.0.0.1 --port 5000\n"
            "  vipertls install-browsers\n"
            "  vipertls install-browsers --browser chromium --browser firefox\n"
            "  vipertls paths\n"
            "  vipertls version"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser("serve", help="Start the local ViperTLS proxy server")
    serve.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    serve.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    serve.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])

    install = subparsers.add_parser("install-browsers", help="Install Playwright browser binaries")
    install.add_argument(
        "--browser",
        dest="browsers",
        action="append",
        choices=["chromium", "firefox", "webkit"],
        help="Browser target to install (repeatable)",
    )
    install.add_argument(
        "--with-deps",
        action="store_true",
        help="On Linux, ask Playwright to install required system dependencies too.",
    )

    subparsers.add_parser("paths", help="Show the active runtime directories")
    subparsers.add_parser("version", help="Show the installed ViperTLS version")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        print(_overview())
        return

    if args.command == "paths":
        for key, value in describe_runtime_paths().items():
            print(f"{key}: {value}")
        return

    if args.command == "version":
        print(__version__)
        return

    if args.command == "install-browsers":
        raise SystemExit(install_playwright_browsers(args.browsers or ["chromium"], with_deps=args.with_deps))

    if args.command == "serve":
        print(f"ViperTLS server starting on {args.host}:{args.port}", flush=True)
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            workers=args.workers,
            log_level=args.log_level,
            access_log=False,
        )
        return

    parser.print_help(sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    main()
