import asyncio
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .client import AsyncClient
from .core.response import ViperResponse

_VERSION = "0.1.0"

_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

_METHOD_COLORS = {
    "GET":     "bright_blue",
    "POST":    "bright_yellow",
    "PUT":     "bright_magenta",
    "PATCH":   "orange3",
    "DELETE":  "bright_red",
    "HEAD":    "cyan",
    "OPTIONS": "grey70",
}

_PROTO_COLORS = {
    "HTTP/2":   "bright_cyan",
    "HTTP/1.1": "grey62",
}


def _status_style(code: Optional[int]) -> str:
    if code is None:
        return "grey50"
    if code < 300:
        return "bright_green"
    if code < 400:
        return "bright_cyan"
    if code < 500:
        return "bright_red"
    return "red3"


def _fmt_size(n: Optional[int]) -> str:
    if n is None:
        return "—"
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.2f} MB"


def _fmt_ms(ms: Optional[float]) -> str:
    if ms is None:
        return "—"
    if ms < 1000:
        return f"{ms:.0f}ms"
    return f"{ms / 1000:.2f}s"


def _shorten_url(url: str, width: int = 44) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.replace("www.", "")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    full = f"{host}{path}"
    if len(full) <= width:
        return full
    return full[: width - 1] + "…"


@dataclass
class _Record:
    id: int
    ts: str
    method: str
    url: str
    preset: str
    status: Optional[int] = None
    http_version: Optional[str] = None
    size: Optional[int] = None
    elapsed_ms: Optional[float] = None
    error: Optional[str] = None
    pending: bool = True
    _tick: int = field(default=0, repr=False)


class ViperDashboard:
    def __init__(
        self,
        impersonate: str = "chrome_124",
        max_rows: int = 25,
        **client_kwargs,
    ) -> None:
        self._impersonate = impersonate
        self._client_kwargs = client_kwargs
        self._client: Optional[AsyncClient] = None
        self._max_rows = max_rows
        self._records: list[_Record] = []
        self._lock = threading.Lock()
        self._live: Optional[Live] = None
        self._console = Console()
        self._counter = 0
        self._total = 0
        self._success = 0
        self._failed = 0
        self._total_ms = 0.0
        self._total_bytes = 0
        self._start_time = time.monotonic()
        self._spinner_tick = 0
        self._ticker_task: Optional[asyncio.Task] = None

    async def __aenter__(self) -> "ViperDashboard":
        self._client = AsyncClient(
            impersonate=self._impersonate, **self._client_kwargs
        )
        self._live = Live(
            self._render(),
            console=self._console,
            refresh_per_second=12,
            transient=False,
        )
        self._live.__enter__()
        self._ticker_task = asyncio.create_task(self._tick_loop())
        return self

    async def __aexit__(self, *args) -> None:
        if self._ticker_task:
            self._ticker_task.cancel()
        if self._live:
            self._live.update(self._render())
            self._live.__exit__(*args)

    async def _tick_loop(self) -> None:
        while True:
            await asyncio.sleep(0.08)
            self._spinner_tick += 1
            with self._lock:
                for r in self._records:
                    if r.pending:
                        r._tick = self._spinner_tick
            if self._live:
                self._live.update(self._render())

    def _render(self) -> Group:
        return Group(
            self._render_header(),
            self._render_stats(),
            self._render_table(),
        )

    def _render_header(self) -> Panel:
        title = Text()
        title.append("⚡ ", style="bright_yellow")
        title.append("V I P E R", style="bold bright_white")
        title.append("TLS", style="bold bright_cyan")
        title.append(f"  v{_VERSION}", style="dim")
        title.append("   ·   ", style="dim")
        title.append("Live Request Monitor", style="italic dim white")
        return Panel(
            title,
            box=box.ROUNDED,
            style="dim",
            padding=(0, 2),
        )

    def _render_stats(self) -> Text:
        uptime = time.monotonic() - self._start_time
        avg = (self._total_ms / self._total) if self._total else 0.0

        t = Text("  ")
        t.append("◉ ", style="bright_white")
        t.append(str(self._total), style="bold white")
        t.append(" requests", style="dim")

        t.append("   ✓ ", style="bright_green")
        t.append(str(self._success), style="bold bright_green")
        t.append(" ok", style="dim")

        t.append("   ✗ ", style="bright_red")
        t.append(str(self._failed), style="bold bright_red")
        t.append(" failed", style="dim")

        t.append("   ⏱ ", style="bright_yellow")
        t.append(_fmt_ms(avg) if self._total else "—", style="bold bright_yellow")
        t.append(" avg", style="dim")

        t.append("   ↓ ", style="bright_cyan")
        t.append(_fmt_size(self._total_bytes), style="bold bright_cyan")

        t.append(f"   uptime {_fmt_ms(uptime * 1000)}", style="dim")
        return t

    def _render_table(self) -> Table:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_footer=False,
            show_edge=False,
            pad_edge=True,
            expand=True,
            style="dim",
            header_style="bold bright_white",
            row_styles=["none"],
        )

        table.add_column("Time", style="grey62", width=10, no_wrap=True)
        table.add_column("Method", width=8, no_wrap=True)
        table.add_column("URL", ratio=1, no_wrap=True)
        table.add_column("Status", width=7, justify="right", no_wrap=True)
        table.add_column("Proto", width=8, no_wrap=True)
        table.add_column("Size", width=9, justify="right", no_wrap=True)
        table.add_column("Time", width=8, justify="right", no_wrap=True)
        table.add_column("Preset", width=12, no_wrap=True)

        with self._lock:
            rows = self._records[: self._max_rows]

        for r in rows:
            frame = _SPINNER_FRAMES[r._tick % len(_SPINNER_FRAMES)]

            method_style = _METHOD_COLORS.get(r.method, "white")
            method_cell = Text(r.method, style=f"bold {method_style}")

            url_cell = Text(_shorten_url(r.url), style="white")

            if r.pending and r.error is None:
                status_cell = Text(f"{frame} ", style="bright_yellow")
                size_cell = Text("…", style="dim")
                elapsed_cell = Text("…", style="dim")
                proto_cell = Text("…", style="dim")
            elif r.error:
                status_cell = Text("ERR", style="bold bright_red")
                size_cell = Text("—", style="dim")
                elapsed_cell = Text(_fmt_ms(r.elapsed_ms), style="dim")
                proto_cell = Text("—", style="dim")
            else:
                status_cell = Text(
                    str(r.status), style=f"bold {_status_style(r.status)}"
                )
                size_cell = Text(_fmt_size(r.size), style="grey85")
                elapsed_cell = Text(_fmt_ms(r.elapsed_ms), style="grey85")
                proto_color = _PROTO_COLORS.get(r.http_version or "", "grey50")
                proto_cell = Text(r.http_version or "—", style=proto_color)

            table.add_row(
                r.ts,
                method_cell,
                url_cell,
                status_cell,
                proto_cell,
                size_cell,
                elapsed_cell,
                Text(r.preset, style="dim cyan"),
            )

        if not rows:
            table.add_row(
                "", "", Text("No requests yet…", style="dim italic"), "", "", "", "", ""
            )

        return table

    async def _dispatch(
        self,
        method: str,
        url: str,
        headers=None,
        body=None,
        **kwargs,
    ) -> ViperResponse:
        self._counter += 1
        record = _Record(
            id=self._counter,
            ts=datetime.now().strftime("%H:%M:%S"),
            method=method.upper(),
            url=url,
            preset=self._impersonate,
        )

        with self._lock:
            self._records.insert(0, record)
            self._total += 1

        if self._live:
            self._live.update(self._render())

        t0 = time.perf_counter()
        try:
            resp = await self._client.request(
                method, url, headers=headers, body=body, **kwargs
            )
            elapsed = (time.perf_counter() - t0) * 1000

            with self._lock:
                record.pending = False
                record.status = resp.status_code
                record.http_version = resp.http_version
                record.size = len(resp.content)
                record.elapsed_ms = elapsed
                self._total_ms += elapsed
                self._total_bytes += len(resp.content)
                if resp.ok:
                    self._success += 1
                else:
                    self._failed += 1

            return resp

        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            with self._lock:
                record.pending = False
                record.error = str(exc)
                record.elapsed_ms = elapsed
                self._failed += 1
            raise

        finally:
            if self._live:
                self._live.update(self._render())

    async def get(self, url: str, **kwargs) -> ViperResponse:
        return await self._dispatch("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> ViperResponse:
        return await self._dispatch("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> ViperResponse:
        return await self._dispatch("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> ViperResponse:
        return await self._dispatch("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> ViperResponse:
        return await self._dispatch("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> ViperResponse:
        return await self._dispatch("HEAD", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> ViperResponse:
        return await self._dispatch(method, url, **kwargs)
