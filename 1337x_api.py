import argparse
import asyncio
import re
import time
from html import unescape
from urllib.parse import quote

import uvicorn
from fastapi import FastAPI, HTTPException, Query

import vipertls


DEFAULT_QUERY = "ubuntu"
DEFAULT_PRESET = "edge_133"

app = FastAPI(title="1337x ViperTLS Demo", docs_url="/docs", redoc_url=None)


def _search_url(query: str, page: int = 1) -> str:
    return f"https://1337x.to/search/{quote(query)}/{page}/"


def _clean_html(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", unescape(text)).strip()


def _parse_rows(html: str, limit: int = 10) -> list[dict[str, str]]:
    rows = re.findall(r"<tr>(.*?)</tr>", html, flags=re.IGNORECASE | re.DOTALL)
    items: list[dict[str, str]] = []
    for row in rows:
        if "/torrent/" not in row:
            continue

        link_match = re.search(r'href="(?P<link>/torrent/[^"]+)"', row, flags=re.IGNORECASE)
        name_match = re.search(
            r'<a[^>]+href="/torrent/[^"]+"[^>]*>(?P<name>.*?)</a>',
            row,
            flags=re.IGNORECASE | re.DOTALL,
        )
        seeds_match = re.search(r'<td[^>]*class="coll-2[^"]*"[^>]*>(?P<value>.*?)</td>', row, flags=re.IGNORECASE | re.DOTALL)
        leeches_match = re.search(r'<td[^>]*class="coll-3[^"]*"[^>]*>(?P<value>.*?)</td>', row, flags=re.IGNORECASE | re.DOTALL)
        time_match = re.search(r'<td[^>]*class="coll-date[^"]*"[^>]*>(?P<value>.*?)</td>', row, flags=re.IGNORECASE | re.DOTALL)
        size_match = re.search(r'<td[^>]*class="coll-4[^"]*"[^>]*>(?P<value>.*?)</td>', row, flags=re.IGNORECASE | re.DOTALL)
        uploader_match = re.search(
            r'<td[^>]*class="coll-5[^"]*"[^>]*>.*?<a[^>]*>(?P<value>.*?)</a>.*?</td>',
            row,
            flags=re.IGNORECASE | re.DOTALL,
        )

        if not link_match or not name_match:
            continue

        item = {
            "name": _clean_html(name_match.group("name")),
            "link": "https://1337x.to" + link_match.group("link"),
            "seeds": _clean_html(seeds_match.group("value")) if seeds_match else "",
            "leeches": _clean_html(leeches_match.group("value")) if leeches_match else "",
            "uploaded": _clean_html(time_match.group("value")) if time_match else "",
            "size": _clean_html(size_match.group("value")) if size_match else "",
            "uploader": _clean_html(uploader_match.group("value")) if uploader_match else "",
        }
        items.append(item)
        if len(items) >= limit:
            break
    return items


async def _fetch_results(query: str, preset: str, limit: int, hydrate_after_solve: bool = False) -> dict:
    started = time.perf_counter()
    async with vipertls.AsyncClient(impersonate=preset, debug_messages=True) as client:
        target_url = _search_url(query)
        response = await client.get(target_url)
        items = _parse_rows(response.text, limit=limit)
        hydrated = False
        if hydrate_after_solve and not items and response.solved_by == "browser":
            response = await client.get(target_url)
            items = _parse_rows(response.text, limit=limit)
            hydrated = True
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return {
        "query": query,
        "preset": preset,
        "status": response.status_code,
        "solved_by": response.solved_by,
        "from_cache": response.from_cache,
        "hydrated_after_solve": hydrated,
        "elapsed_ms": elapsed_ms,
        "count": len(items),
        "items": items,
        "solve_info": response.solve_info,
    }


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "name": "1337x ViperTLS Demo",
        "usage": "/search?q=ubuntu or /benchmark?q=ubuntu",
        "preset": DEFAULT_PRESET,
    }


@app.get("/search")
async def search(
    q: str = Query(DEFAULT_QUERY, description="1337x search query"),
    preset: str = Query(DEFAULT_PRESET, description="ViperTLS preset"),
    limit: int = Query(10, ge=1, le=50),
) -> dict:
    result = await _fetch_results(q, preset, limit, hydrate_after_solve=True)
    if result["status"] >= 400 and not result["items"]:
        raise HTTPException(status_code=502, detail=result)
    return result


@app.get("/benchmark")
async def benchmark(
    q: str = Query(DEFAULT_QUERY, description="1337x search query"),
    preset: str = Query(DEFAULT_PRESET, description="ViperTLS preset"),
    limit: int = Query(10, ge=1, le=50),
) -> dict:
    first = await _fetch_results(q, preset, limit)
    second = await _fetch_results(q, preset, limit)
    delta_ms = round(first["elapsed_ms"] - second["elapsed_ms"], 2)
    return {
        "query": q,
        "preset": preset,
        "first_run": first,
        "second_run": second,
        "delta_ms": delta_ms,
        "second_run_faster": second["elapsed_ms"] < first["elapsed_ms"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a small 1337x demo API backed by ViperTLS.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8090, help="Bind port")
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, access_log=False)


if __name__ == "__main__":
    main()
