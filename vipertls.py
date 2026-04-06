#!/usr/bin/env python3
import sys
import os
import threading
import time
import signal
import argparse
import msvcrt

sys.path.insert(0, os.path.dirname(__file__))

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box
import uvicorn

from vipertls.server import app
from vipertls.fingerprints.presets import PRESETS

console = Console()

_VERSION = "0.1.0"
_PRESETS_ORDER = [
    ("chrome_145", "Google Chrome"),
    ("chrome_140", "Google Chrome"),
    ("chrome_136", "Google Chrome"),
    ("chrome_133", "Google Chrome"),
    ("chrome_131", "Google Chrome"),
    ("chrome_124", "Google Chrome"),
    ("chrome_120", "Google Chrome"),
    ("firefox_136", "Mozilla Firefox"),
    ("firefox_133", "Mozilla Firefox"),
    ("firefox_127", "Mozilla Firefox"),
    ("firefox_120", "Mozilla Firefox"),
    ("safari_18", "Apple Safari"),
    ("safari_17", "Apple Safari"),
    ("edge_136", "Microsoft Edge"),
    ("edge_133", "Microsoft Edge"),
    ("brave_136", "Brave"),
    ("opera_117", "Opera"),
]

_BROWSER_COLORS = {
    "Google Chrome": "bright_green",
    "Mozilla Firefox": "bright_yellow",
    "Apple Safari": "bright_cyan",
    "Microsoft Edge": "blue",
    "Brave": "bright_magenta",
    "Opera": "bright_red",
}

_request_log: list[dict] = []
_log_lock = threading.Lock()
_server_ready = threading.Event()
_start_time = time.monotonic()
_stats = {"total": 0, "ok": 0, "err": 0, "bytes": 0, "ms": 0.0}
_current_view = "main"
_selected_family_idx = 0


def _clock_now() -> str:
    return time.strftime("%I:%M:%S %p").lstrip("0")


def _install_middleware() -> None:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request as SR
    from starlette.responses import Response as SResp

    async def _log(request: SR, call_next):
        t0 = time.perf_counter()

        config = {}
        for k, v in request.headers.items():
            if k.lower().startswith("x-viper-"):
                config[k[8:].lower().replace("-", "_")] = v

        target = config.get("url", "—")
        if target != "—" and not target.startswith(("http://", "https://")):
            target = "https://" + target
        preset = config.get("impersonate", "chrome_124").strip().strip('"').strip("'")
        method = request.method

        response = await call_next(request)

        body = b""
        async for chunk in response.body_iterator:
            body += chunk

        elapsed = (time.perf_counter() - t0) * 1000
        size = len(body)
        status = response.status_code

        solved_by = response.headers.get("x-vipertls-solved-by", "fingerprint")

        with _log_lock:
            _request_log.insert(
                0,
                {
                    "time": _clock_now(),
                    "method": method,
                    "url": target,
                    "preset": preset,
                    "status": status,
                    "size": size,
                    "ms": elapsed,
                    "solved_by": solved_by,
                },
            )
            if len(_request_log) > 50:
                _request_log.pop()
            _stats["total"] += 1
            _stats["bytes"] += size
            _stats["ms"] += elapsed
            if 200 <= status < 400:
                _stats["ok"] += 1
            else:
                _stats["err"] += 1

        return SResp(
            content=body,
            status_code=status,
            headers=dict(response.headers),
            media_type=response.media_type,
        )

    app.add_middleware(BaseHTTPMiddleware, dispatch=_log)


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.2f} MB"


def _fmt_ms(ms: float) -> str:
    if ms < 1000:
        return f"{ms:.0f}ms"
    return f"{ms / 1000:.2f}s"


def _shorten(url: str, w: int = 48) -> str:
    return url if len(url) <= w else url[: w - 1] + "…"


def _status_style(code: int) -> str:
    if code < 300:
        return "bold bright_green"
    if code < 400:
        return "bold bright_cyan"
    if code < 500:
        return "bold bright_red"
    return "bold red"


def _solve_badge(mode: str) -> tuple[str, str]:
    return {
        "fingerprint": ("TLS", "bright_cyan"),
        "cache": ("Cache", "bright_green"),
        "browser": ("Browser", "bright_yellow"),
        "browser_failed": ("Failed", "red"),
        "solving": ("Solving", "bright_yellow"),
    }.get(mode, ("TLS", "bright_cyan"))


def _group_presets() -> dict[str, list[tuple[str, str]]]:
    groups: dict[str, list[tuple[str, str]]] = {}
    for key, browser in _PRESETS_ORDER:
        if key not in PRESETS:
            continue
        groups.setdefault(browser, []).append((key, PRESETS[key].user_agent))
    return groups


def _preset_families() -> list[str]:
    return list(_group_presets().keys())


def _render_nav() -> Panel:
    tabs = [
        ("main", "1 Main"),
        ("presets", "2 Presets"),
        ("guide", "3 Guide"),
        ("help", "4 Help"),
    ]
    nav = Text()
    for idx, (key, label) in enumerate(tabs):
        if idx:
            nav.append("   ", style="dim")
        style = "bold black on bright_cyan" if _current_view == key else "bold grey70 on grey19"
        nav.append(f" {label} ", style=style)
    nav.append("   ", style="dim")
    nav.append("Press 1 / 2 / 3 to switch views", style="grey62")
    return Panel(nav, box=box.ROUNDED, style="dim", padding=(0, 2))


def _build_top_panels(host: str, port: int, uptime: float) -> Table:
    ready = _server_ready.is_set()
    status_label = "RUNNING" if ready else "STARTING"
    status_style = "bold black on bright_green" if ready else "bold black on bright_yellow"

    with _log_lock:
        total = _stats["total"]
        ok = _stats["ok"]
        err = _stats["err"]
        avg = (_stats["ms"] / total) if total else 0.0
        downloaded = _stats["bytes"]

    server_info = Table.grid(expand=True)
    server_info.add_column(ratio=1)
    server_info.add_row(Text.assemble((f" {status_label} ", status_style), ("   Local endpoint", "grey62")))
    server_info.add_row(Text(f"http://{host}:{port}", style="bold bright_white"))
    server_info.add_row(
        Text.assemble(
            ("Host ", "grey62"),
            (host, "white"),
            ("   Port ", "grey62"),
            (str(port), "white"),
        )
    )
    server_info.add_row(
        Text.assemble(
            ("Uptime ", "grey62"),
            (_fmt_ms(uptime * 1000), "bright_cyan"),
            ("   Traffic ", "grey62"),
            (_fmt_size(downloaded), "bright_green"),
        )
    )
    server_panel = Panel(server_info, title="[bold]Server[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1))

    traffic = Table.grid(expand=True)
    traffic.add_column(justify="center", ratio=1)
    traffic.add_column(justify="center", ratio=1)
    traffic.add_column(justify="center", ratio=1)
    traffic.add_column(justify="center", ratio=1)
    traffic.add_row(
        Text.assemble((str(total), "bold bright_white"), ("\nRequests", "grey62")),
        Text.assemble((str(ok), "bold bright_green"), ("\nSuccess", "grey62")),
        Text.assemble((str(err), "bold bright_red"), ("\nBlocked", "grey62")),
        Text.assemble(((_fmt_ms(avg) if total else "—"), "bold bright_yellow"), ("\nAverage", "grey62")),
    )
    stats_panel = Panel(traffic, title="[bold]Traffic[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1))

    solve_legend = Table.grid(expand=True)
    solve_legend.add_column(width=10)
    solve_legend.add_column(ratio=1)
    solve_legend.add_row(Text("TLS", style="bold bright_cyan"), Text("Fast direct fingerprint path", style="grey70"))
    solve_legend.add_row(Text("Cache", style="bold bright_green"), Text("Reused clearance and session state", style="grey70"))
    solve_legend.add_row(Text("Browser", style="bold bright_yellow"), Text("Playwright fallback for JS and Turnstile", style="grey70"))
    solve_legend.add_row(Text("Failed", style="bold red"), Text("Challenge solve did not complete", style="grey70"))
    solve_panel = Panel(solve_legend, title="[bold]Solve Modes[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1))

    top_row = Table.grid(expand=True)
    top_row.add_column(ratio=3)
    top_row.add_column(ratio=3)
    top_row.add_column(ratio=4)
    top_row.add_row(server_panel, stats_panel, solve_panel)
    return top_row


def _render_main_view(host: str, port: int, uptime: float) -> Group:
    _METHOD_COLORS = {
        "GET": "bright_blue",
        "POST": "bright_yellow",
        "PUT": "bright_magenta",
        "PATCH": "orange3",
        "DELETE": "bright_red",
        "HEAD": "cyan",
    }

    log_table = Table(
        box=box.SIMPLE_HEAD,
        show_footer=False,
        show_edge=False,
        pad_edge=True,
        expand=True,
        style="dim",
        header_style="bold bright_white",
        row_styles=["none"],
    )
    log_table.add_column("Time", style="grey62", width=10, no_wrap=True)
    log_table.add_column("Method", width=8, no_wrap=True)
    log_table.add_column("URL", ratio=1, no_wrap=True)
    log_table.add_column("Status", width=7, justify="right", no_wrap=True)
    log_table.add_column("Solve", width=12, no_wrap=True)
    log_table.add_column("Size", width=9, justify="right", no_wrap=True)
    log_table.add_column("Time", width=9, justify="right", no_wrap=True)
    log_table.add_column("Preset", width=14, no_wrap=True)

    with _log_lock:
        rows = _request_log[:20]

    if rows:
        for r in rows:
            solved_mapped = _solve_badge(r["solved_by"])
            log_table.add_row(
                r["time"],
                Text(r["method"], style=f"bold {_METHOD_COLORS.get(r['method'], 'white')}"),
                Text(_shorten(r["url"]), style="white"),
                Text(str(r["status"]), style=_status_style(r["status"])),
                Text(solved_mapped[0], style=f"bold {solved_mapped[1]}"),
                Text(_fmt_size(r["size"]), style="grey85"),
                Text(_fmt_ms(r["ms"]), style="grey85"),
                Text(r["preset"], style="dim cyan"),
            )
    else:
        log_table.add_row("", "", Text("No requests yet — send one using the quick start below", style="dim italic"), "", "", "", "", "")

    requests_panel = Panel(log_table, title="[bold]Recent Requests[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1))

    quick = Table.grid(expand=True)
    quick.add_column(ratio=1)
    quick.add_row(Text('curl http://127.0.0.1:5000 -H "X-Viper-URL: https://example.com" -H "X-Viper-Impersonate: chrome_145"', style="grey70"))
    quick.add_row(Text('Use the Solve column to see whether a hit used direct TLS, cookie reuse, or the browser solver.', style="grey62"))
    quick.add_row(Text('Switch views with 1 / 2 / 3 to browse presets or help without cluttering the main screen.', style="grey62"))
    quick_panel = Panel(quick, title="[bold]Quick Start[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1))

    return Group(_build_top_panels(host, port, uptime), Rule(style="dim"), requests_panel, Rule(style="dim"), quick_panel)


def _render_presets_view() -> Group:
    groups = _group_presets()
    families = list(groups.keys())
    selected_idx = min(_selected_family_idx, max(len(families) - 1, 0))
    selected_family = families[selected_idx] if families else "Unavailable"

    family_list = Table(
        expand=True,
        box=box.SIMPLE_HEAD,
        show_edge=False,
        header_style="bold bright_white",
        style="dim",
    )
    family_list.add_column("Browser Families", ratio=1)
    for idx, family in enumerate(families):
        color = _BROWSER_COLORS.get(family, "white")
        marker = "> " if idx == selected_idx else "  "
        style = f"bold {color}" if idx == selected_idx else color
        family_list.add_row(Text(f"{marker}{family}", style=style))

    catalog = Table(expand=True, box=box.SIMPLE_HEAVY, header_style="bold bright_white", style="dim")
    catalog.add_column("Preset", width=16, no_wrap=True)
    catalog.add_column("User-Agent Preview", ratio=1)
    for key, ua in groups.get(selected_family, []):
        catalog.add_row(Text(key, style="bold cyan"), Text(ua[:92], style="grey70"))

    body = Table.grid(expand=True)
    body.add_column(ratio=2)
    body.add_column(ratio=5)
    body.add_row(
        Panel(family_list, title="[bold]Families[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1)),
        Panel(catalog, title=f"[bold]{selected_family} Presets[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1)),
    )

    tips = Table.grid(expand=True)
    tips.add_column(ratio=1)
    tips.add_row(Text('Use `4` and `5` to move between browser families while you are in this view.', style="grey70"))
    tips.add_row(Text('Use `X-Viper-Impersonate` with any preset shown on the right.', style="grey62"))
    tips.add_row(Text('Press `1` to return to the live dashboard or `3` for usage help.', style="grey62"))

    return Group(
        body,
        Rule(style="dim"),
        Panel(tips, title="[bold]Preset Tips[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1)),
    )


def _render_help_view(host: str, port: int) -> Group:
    help_table = Table.grid(expand=True)
    help_table.add_column(width=14)
    help_table.add_column(ratio=1)
    help_table.add_row(Text("1 Main", style="bold bright_cyan"), Text("Return to the live request dashboard.", style="grey70"))
    help_table.add_row(Text("2 Presets", style="bold bright_cyan"), Text("Open the preset browser and focus on one browser family at a time.", style="grey70"))
    help_table.add_row(Text("3 Guide", style="bold bright_cyan"), Text("Open solver and preset recommendations.", style="grey70"))
    help_table.add_row(Text("4 Help", style="bold bright_cyan"), Text("Show this navigation/help screen.", style="grey70"))
    help_table.add_row(Text("5 / 6", style="bold bright_cyan"), Text("Inside Presets, move left or right through the browser families.", style="grey70"))
    help_table.add_row(Text("Ctrl+C", style="bold bright_red"), Text("Stop the local ViperTLS proxy server.", style="grey70"))

    examples = Table.grid(expand=True)
    examples.add_column(ratio=1)
    examples.add_row(Text(f'curl http://{host}:{port} -H "X-Viper-URL: https://tempmail.la" -H "X-Viper-Impersonate: chrome_145"', style="grey70"))
    examples.add_row(Text('OpenBullet can hit the same localhost endpoint and control target/preset through `X-Viper-*` headers.', style="grey62"))
    examples.add_row(Text('If a site challenges the direct TLS path, the Solve column will show Browser or Cache.', style="grey62"))

    return Group(
        Panel(help_table, title="[bold]Navigation[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1)),
        Rule(style="dim"),
        Panel(examples, title="[bold]Usage Notes[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1)),
    )


def _render_guide_view() -> Group:
    guidance = Table.grid(expand=True)
    guidance.add_column(width=20)
    guidance.add_column(ratio=1)
    guidance.add_row(Text("TLS First", style="bold bright_cyan"), Text("Use browser solving only when the direct TLS path hits a challenge. Fast sites should stay on TLS or Cache.", style="grey70"))
    guidance.add_row(Text("Recommended", style="bold bright_green"), Text("Use `edge_133` when you expect browser fallback. It maps well to the current solver browser path.", style="grey70"))
    guidance.add_row(Text("Chrome Presets", style="bold bright_yellow"), Text("Chrome presets are still good for direct TLS fingerprints. Browser fallback now uses the real installed browser version.", style="grey70"))
    guidance.add_row(Text("Cache Mode", style="bold bright_green"), Text("A `Cache` solve means the browser solved it earlier and ViperTLS reused the saved cookies without relaunching the browser.", style="grey70"))
    guidance.add_row(Text("Fresh Solve", style="bold bright_yellow"), Text("A `Browser` solve is normal on first contact. If repeat requests stay on `Browser`, the site may not be issuing reusable cookies.", style="grey70"))

    matrix = Table(expand=True, box=box.SIMPLE_HEAVY, header_style="bold bright_white", style="dim")
    matrix.add_column("Use Case", width=24, no_wrap=True)
    matrix.add_column("Suggested Preset", width=18, no_wrap=True)
    matrix.add_column("Why", ratio=1)
    matrix.add_row("Fast TLS scraping", Text("chrome_124", style="bold bright_green"), Text("Stable direct fingerprint preset for lightweight targets.", style="grey70"))
    matrix.add_row("Browser challenge fallback", Text("edge_133", style="bold bright_cyan"), Text("Best current default when Turnstile or Cloudflare browser checks appear.", style="grey70"))
    matrix.add_row("Repeat challenge hits", Text("edge_133", style="bold bright_cyan"), Text("Lets the solver populate cache, then later requests can drop to `Cache` mode.", style="grey70"))
    matrix.add_row("Firefox-specific target", Text("firefox_133", style="bold bright_yellow"), Text("Only use when you specifically want Firefox TLS behavior.", style="grey70"))

    notes = Table.grid(expand=True)
    notes.add_column(ratio=1)
    notes.add_row(Text("The preset column in the dashboard shows the request preset. The solver may still use the matching real browser family/version in the background.", style="grey62"))
    notes.add_row(Text("If a site is easy, the best result is `TLS`. If it is hard once and then fast later, the best result is `Browser` followed by `Cache`.", style="grey62"))

    return Group(
        Panel(guidance, title="[bold]Recommendations[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1)),
        Rule(style="dim"),
        Panel(matrix, title="[bold]Preset Guide[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1)),
        Rule(style="dim"),
        Panel(notes, title="[bold]Notes[/bold]", box=box.ROUNDED, style="dim", padding=(0, 1)),
    )


def _render(host: str, port: int) -> Group:
    uptime = time.monotonic() - _start_time

    title = Text()
    title.append("VIPER", style="bold bright_white")
    title.append(" TLS", style="bold bright_cyan")
    title.append("  ", style="dim")
    title.append(f"v{_VERSION}", style="bold grey70")
    title.append("  ", style="dim")
    title.append("Fingerprint", style="grey62")
    title.append("  /  ", style="grey42")
    title.append("Challenge", style="grey62")
    title.append("  /  ", style="grey42")
    title.append("Control Panel", style="grey62")

    subtitle = Text()
    subtitle.append("Local TLS impersonation and browser challenge fallback", style="grey58")
    subtitle.append("   ", style="grey40")
    subtitle.append("Use 1-4 to switch views", style="grey50")

    header_body = Table.grid(expand=True)
    header_body.add_column(ratio=1)
    header_body.add_row(title)
    header_body.add_row(subtitle)

    header = Panel(header_body, box=box.ROUNDED, style="grey35", padding=(0, 2))

    if _current_view == "presets":
        body = _render_presets_view()
    elif _current_view == "guide":
        body = _render_guide_view()
    elif _current_view == "help":
        body = _render_help_view(host, port)
    else:
        body = _render_main_view(host, port, uptime)

    footer = Text()
    footer.append("Request ", style="bold white")
    footer.append(f"http://{host}:{port} ", style="bright_cyan")
    footer.append("with ", style="dim")
    footer.append("X-Viper-URL", style="green")
    footer.append(" + ", style="dim")
    footer.append("X-Viper-Impersonate", style="yellow")
    footer.append(" headers", style="dim")

    return Group(header, _render_nav(), body, Rule(style="dim"), footer)


def _poll_input() -> None:
    global _current_view, _selected_family_idx
    while msvcrt.kbhit():
        ch = msvcrt.getwch()
        if ch == "1":
            _current_view = "main"
        elif ch == "2":
            _current_view = "presets"
        elif ch == "3":
            _current_view = "guide"
        elif ch == "4":
            _current_view = "help"
        elif ch in ("5", "6") and _current_view == "presets":
            families = _preset_families()
            if not families:
                continue
            step = -1 if ch == "5" else 1
            _selected_family_idx = (_selected_family_idx + step) % len(families)


def _start_server(host: str, port: int) -> None:
    config = uvicorn.Config(
        app, host=host, port=port, log_level="critical", access_log=False
    )
    server = uvicorn.Server(config)
    threading.Thread(
        target=lambda: (time.sleep(0.8), _server_ready.set()), daemon=True
    ).start()
    server.run()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vipertls", description="ViperTLS proxy server"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    host, port = args.host, args.port

    _install_middleware()

    threading.Thread(target=_start_server, args=(host, port), daemon=True).start()

    def _shutdown(sig, frame):
        console.print("\n[bright_red]Shutting down ViperTLS…[/bright_red]")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    with Live(
        _render(host, port), console=console, refresh_per_second=4, screen=True
    ) as live:
        while True:
            _poll_input()
            live.update(_render(host, port))
            time.sleep(0.25)


if __name__ == "__main__":
    main()
