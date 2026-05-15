"""Phase 2 Rspamd router. Endpoints implemented in Tasks C2-C5."""
from fastapi import APIRouter

router = APIRouter(prefix="/rspamd", tags=["rspamd"])
