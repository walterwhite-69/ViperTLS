import time
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

from .browser import CloudflareSolver, SolveResult, get_cache, is_challenge

app = FastAPI(title="ViperSolverr", docs_url=None, redoc_url=None)

_solver = CloudflareSolver()

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"


class SolveRequest(BaseModel):
    url: str
    user_agent: Optional[str] = None
    preset: str = "chrome_124"
    timeout: int = 30


class SolveResponse(BaseModel):
    url: str
    status: int
    html: str
    cookies: dict[str, str]
    user_agent: str
    method: str
    elapsed_ms: float


@app.post("/solve", response_model=SolveResponse)
async def solve(req: SolveRequest) -> SolveResponse:
    ua = req.user_agent or _UA
    result = await _solver.solve(url=req.url, user_agent=ua, preset=req.preset, timeout=req.timeout)
    return SolveResponse(
        url=result.url,
        status=result.status,
        html=result.html,
        cookies=result.cookies,
        user_agent=result.user_agent,
        method=result.method,
        elapsed_ms=result.elapsed_ms,
    )


@app.delete("/cookies/{domain}")
async def clear_cookies(domain: str):
    get_cache().clear(domain)
    return {"cleared": domain}


@app.delete("/cookies")
async def clear_all_cookies():
    get_cache().clear_all()
    return {"cleared": "all"}


@app.get("/health")
async def health():
    return {"status": "ok"}
