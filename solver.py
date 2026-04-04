#!/usr/bin/env python3
import sys
import os
import threading
import time
import signal
import argparse

sys.path.insert(0, os.path.dirname(__file__))

import uvicorn
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box

from vipertls.solver.server import app

console = Console()

_VERSION = "0.1.0"
_request_log: list[dict] = []
_log_lock = threading.Lock()
_server_ready = threading.Event()
_start_time = time.monotonic()
_stats = {"total": 0, "solved": 0, "direct": 0, "failed": 0, "ms": 0.0}


def _fmt_ms(ms: float) -> str:
    return f"{ms:.0f}ms" if ms < 1000 else f"{ms / 1000:.2f}s"


def _shorten(url: str, w: int = 52) -> str:
    return url if len(url) <= w else url[:w - 1] + "…"


def _status_style(code: int) -> str:
    if code < 300: return "bold bright_green"
    if code < 400: return "bold bright_cyan"
    if code < 500: return "bold bright_red"
    return "bold red"


def _method_color(m: str) -> str:
    return {"browser": "bright_yellow", "browser_failed": "bright_red", "direct": "bright_green"}.get(m, "white")


def _render(host: str, port: int) -> Group:
    uptime = time.monotonic() - _start_time
    ready = _server_ready.is_set()

    title = Text()
    title.append("⚡ ", style="bright_yellow")
    title.append("V I P E R", style="bold bright_white")
    title.append("SOLVERR", style="bold bright_magenta")
    title.append(f"  v{_VERSION}", style="dim")
    header = Panel(title, box=box.ROUNDED, style="dim", padding=(0, 2))

    status_dot = Text("● ", style="bright_green" if ready else "bright_yellow")
    status_dot.append("RUNNING" if ready else "STARTING…", style="bold bright_green" if ready else "bold bright_yellow")
    server_text = Text("  ")
    server_text.append_text(status_dot)
    server_text.append(f"   http://{host}:{port}", style="bold white")
    server_text.append("   ·   uptime ", style="dim")
    server_text.append(_fmt_ms(uptime * 1000), style="bright_yellow")

    with _log_lock:
        total = _stats["total"]
        solved = _stats["solved"]
        direct = _stats["direct"]
        failed = _stats["failed"]
        avg = (_stats["ms"] / total) if total else 0.0

    stats = Text("  ")
    stats.append("◉ ", style="bright_white")
    stats.append(str(total), style="bold white")
    stats.append(" total", style="dim")
    stats.append("   🧩 ", style="bright_yellow")
    stats.append(str(solved), style="bold bright_yellow")
    stats.append(" solved", style="dim")
    stats.append("   ⚡ ", style="bright_green")
    stats.append(str(direct), style="bold bright_green")
    stats.append(" direct", style="dim")
    stats.append("   ✗ ", style="bright_red")
    stats.append(str(failed), style="bold bright_red")
    stats.append(" failed", style="dim")
    stats.append("   ⏱ ", style="bright_cyan")
    stats.append(_fmt_ms(avg) if total else "—", style="bold bright_cyan")
    stats.append(" avg", style="dim")

    log_table = Table(
        box=box.SIMPLE_HEAD, show_footer=False, show_edge=False,
        pad_edge=True, expand=True, style="dim",
        header_style="bold bright_white",
    )
    log_table.add_column("Time",   style="grey62", width=10, no_wrap=True)
    log_table.add_column("URL",    ratio=1,         no_wrap=True)
    log_table.add_column("Status", width=7,          justify="right", no_wrap=True)
    log_table.add_column("Method", width=16,         no_wrap=True)
    log_table.add_column("Time",   width=9,          justify="right", no_wrap=True)

    with _log_lock:
        rows = _request_log[:20]

    if rows:
        for r in rows:
            log_table.add_row(
                r["time"],
                Text(_shorten(r["url"]), style="white"),
                Text(str(r["status"]), style=_status_style(r["status"])),
                Text(r["method"], style=_method_color(r["method"])),
                Text(_fmt_ms(r["ms"]), style="grey85"),
            )
    else:
        log_table.add_row("", Text("No requests yet…", style="dim italic"), "", "", "")

    hint = Text()
    hint.append("  POST ", style="bold white")
    hint.append(f"http://{host}:{port}/solve", style="bright_cyan")
    hint.append('  body: {"url": "https://tempmail.la/", "timeout": 30}', style="dim")
    hint.append("\n  Stop:  ", style="bold white")
    hint.append("Ctrl+C", style="bright_red")

    return Group(header, server_text, stats, Rule(style="dim"), log_table, hint)


def _patch_app_logging() -> None:
    from vipertls.solver import server as srv
    _orig_solve = srv.solve

    async def _logged_solve(req):
        t0 = time.perf_counter()
        result = await _orig_solve(req)
        elapsed = (time.perf_counter() - t0) * 1000
        with _log_lock:
            _request_log.insert(0, {
                "time": time.strftime("%H:%M:%S"),
                "url": result.url,
                "status": result.status,
                "method": result.method,
                "ms": elapsed,
            })
            if len(_request_log) > 50:
                _request_log.pop()
            _stats["total"] += 1
            _stats["ms"] += elapsed
            if result.method == "browser":
                _stats["solved"] += 1
            elif result.method == "direct":
                _stats["direct"] += 1
            else:
                _stats["failed"] += 1
        return result

    srv.solve = _logged_solve
    for route in app.routes:
        if hasattr(route, "endpoint") and route.endpoint.__name__ == "solve":
            route.endpoint = _logged_solve
            break


def _start_server(host: str, port: int) -> None:
    config = uvicorn.Config(app, host=host, port=port, log_level="critical", access_log=False)
    server = uvicorn.Server(config)
    threading.Thread(target=lambda: (time.sleep(0.8), _server_ready.set()), daemon=True).start()
    server.run()


def main() -> None:
    parser = argparse.ArgumentParser(prog="solver", description="ViperSolverr")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()

    _patch_app_logging()

    threading.Thread(target=_start_server, args=(args.host, args.port), daemon=True).start()

    def _shutdown(sig, frame):
        console.print("\n[bright_red]Shutting down ViperSolverr…[/bright_red]")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    with Live(_render(args.host, args.port), console=console, refresh_per_second=4) as live:
        while True:
            live.update(_render(args.host, args.port))
            time.sleep(0.25)


if __name__ == "__main__":
    main()
