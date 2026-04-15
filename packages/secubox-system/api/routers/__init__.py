"""SecuBox-Deb :: api.routers — Routers FastAPI système."""
from .metrics import router as metrics_router
from .remote_ui import router as remote_ui_router

__all__ = ["metrics_router", "remote_ui_router"]
