"""Phase 2 deprecation shims for /dkim/*, /spam/*, /grey/*. Implemented in Task C6."""
from fastapi import APIRouter

router = APIRouter(tags=["legacy-deprecated"])
