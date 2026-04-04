import argparse
import uvicorn

from .server import app


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vipertls.solver",
        description="ViperTLS standalone browser solver server",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    args = parser.parse_args()

    print(f"ViperSolverr starting on {args.host}:{args.port}", flush=True)

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_level=args.log_level,
        access_log=False,
    )


if __name__ == "__main__":
    main()
