\
\
\
\
   

from .client import AsyncClient, Client
from .tui import ViperDashboard
from .core.response import ViperResponse, ViperHTTPError, ViperConnectionError, ViperTimeoutError
from .fingerprints.presets import resolve_preset, PRESETS, BrowserPreset
from .runtime import describe_runtime_paths
from .solver.browser import clear_cache as clear_solver_cache

__version__ = "0.1.3"
__all__ = [
    "AsyncClient",
    "Client",
    "ViperDashboard",
    "ViperResponse",
    "ViperHTTPError",
    "ViperConnectionError",
    "ViperTimeoutError",
    "resolve_preset",
    "PRESETS",
    "BrowserPreset",
    "get_runtime_paths",
    "clear_solver_cache",
]


def get_runtime_paths() -> dict[str, str]:
\
\
\
\
       
    return describe_runtime_paths()


clear_solver_cache.__doc__ = (
    "Clear saved solver cookies/cache.\n\n"
    "Call without arguments to clear all solver cache entries.\n"
    "Use domain='example.com' to clear one domain across presets, or add\n"
    "preset='edge_133' to clear only one domain+preset combination."
)
