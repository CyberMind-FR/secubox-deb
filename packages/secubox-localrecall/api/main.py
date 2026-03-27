"""SecuBox LocalRecall - AI Memory System
Persistent memory database for SecuBox AI agents with categorization,
search, and semantic retrieval capabilities.

Memory categories:
- threats: Security threats and incidents
- decisions: AI decisions and reasoning
- patterns: Detected patterns and behaviors
- configs: Configuration changes
- conversations: AI conversation history
"""
import os
import json
import time
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/localrecall.toml")
DATA_DIR = Path("/var/lib/secubox/localrecall")
MEMORIES_FILE = DATA_DIR / "memories.jsonl"
INDEX_FILE = DATA_DIR / "index.json"

app = FastAPI(title="SecuBox LocalRecall", version="1.0.0")
logger = logging.getLogger("secubox.localrecall")


class MemoryCategory(str, Enum):
    THREATS = "threats"
    DECISIONS = "decisions"
    PATTERNS = "patterns"
    CONFIGS = "configs"
    CONVERSATIONS = "conversations"
    GENERAL = "general"


class Memory(BaseModel):
    id: Optional[str] = None
    category: MemoryCategory = MemoryCategory.GENERAL
    content: str
    context: Optional[str] = None
    importance: int = Field(default=5, ge=1, le=10)  # 1-10 scale
    tags: List[str] = []
    source: Optional[str] = None
    timestamp: Optional[str] = None
    expires_at: Optional[str] = None


class SearchQuery(BaseModel):
    query: str
    category: Optional[MemoryCategory] = None
    tags: Optional[List[str]] = None
    min_importance: Optional[int] = None
    limit: int = 10
    semantic: bool = False  # Use AI for semantic search


class MemoryStore:
    """File-based memory storage with indexing."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.memories_file = data_dir / "memories.jsonl"
        self.index_file = data_dir / "index.json"
        self.index: Dict[str, Dict] = {}
        self._ensure_dirs()
        self._load_index()

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _load_index(self):
        """Load search index."""
        if self.index_file.exists():
            try:
                with open(self.index_file) as f:
                    self.index = json.load(f)
            except Exception:
                self.index = {"by_id": {}, "by_category": {}, "by_tag": {}}
        else:
            self.index = {"by_id": {}, "by_category": {}, "by_tag": {}}

    def _save_index(self):
        """Save search index."""
        with open(self.index_file, "w") as f:
            json.dump(self.index, f)

    def _generate_id(self, content: str) -> str:
        """Generate unique ID from content hash + timestamp."""
        hash_part = hashlib.sha256(content.encode()).hexdigest()[:8]
        time_part = hex(int(time.time() * 1000))[-8:]
        return f"{hash_part}{time_part}"

    def store(self, memory: Memory) -> str:
        """Store a memory and update index."""
        if not memory.id:
            memory.id = self._generate_id(memory.content)

        if not memory.timestamp:
            memory.timestamp = datetime.utcnow().isoformat() + "Z"

        # Append to file
        with open(self.memories_file, "a") as f:
            f.write(json.dumps(memory.model_dump()) + "\n")

        # Update index
        self.index["by_id"][memory.id] = {
            "category": memory.category,
            "importance": memory.importance,
            "tags": memory.tags,
            "timestamp": memory.timestamp
        }

        category = memory.category
        if category not in self.index["by_category"]:
            self.index["by_category"][category] = []
        self.index["by_category"][category].append(memory.id)

        for tag in memory.tags:
            if tag not in self.index["by_tag"]:
                self.index["by_tag"][tag] = []
            self.index["by_tag"][tag].append(memory.id)

        self._save_index()
        return memory.id

    def get(self, memory_id: str) -> Optional[Memory]:
        """Retrieve a memory by ID."""
        if memory_id not in self.index.get("by_id", {}):
            return None

        # Search file for memory
        with open(self.memories_file) as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if data.get("id") == memory_id:
                        return Memory(**data)
                except json.JSONDecodeError:
                    continue
        return None

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_importance: int = 0,
        limit: int = 10
    ) -> List[Memory]:
        """Search memories by text, category, tags."""
        results = []
        query_lower = query.lower()

        with open(self.memories_file) as f:
            for line in f:
                try:
                    data = json.loads(line)

                    # Category filter
                    if category and data.get("category") != category:
                        continue

                    # Importance filter
                    if data.get("importance", 0) < min_importance:
                        continue

                    # Tags filter
                    if tags:
                        memory_tags = set(data.get("tags", []))
                        if not set(tags).intersection(memory_tags):
                            continue

                    # Text search
                    content = data.get("content", "").lower()
                    context = data.get("context", "").lower()
                    if query_lower in content or query_lower in context:
                        results.append(Memory(**data))

                        if len(results) >= limit:
                            break

                except json.JSONDecodeError:
                    continue

        # Sort by importance descending
        results.sort(key=lambda m: m.importance, reverse=True)
        return results[:limit]

    def list_by_category(self, category: str, limit: int = 50) -> List[Memory]:
        """List memories in a category."""
        ids = self.index.get("by_category", {}).get(category, [])[-limit:]
        return [m for mid in ids if (m := self.get(mid))]

    def delete(self, memory_id: str) -> bool:
        """Delete a memory (marks as deleted, doesn't remove from file)."""
        if memory_id not in self.index.get("by_id", {}):
            return False

        # Remove from index
        meta = self.index["by_id"].pop(memory_id, {})
        category = meta.get("category")
        if category and category in self.index["by_category"]:
            self.index["by_category"][category] = [
                i for i in self.index["by_category"][category] if i != memory_id
            ]

        for tag in meta.get("tags", []):
            if tag in self.index["by_tag"]:
                self.index["by_tag"][tag] = [
                    i for i in self.index["by_tag"][tag] if i != memory_id
                ]

        self._save_index()
        return True

    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        total = len(self.index.get("by_id", {}))
        by_category = {
            cat: len(ids)
            for cat, ids in self.index.get("by_category", {}).items()
        }
        top_tags = sorted(
            [(tag, len(ids)) for tag, ids in self.index.get("by_tag", {}).items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]

        # Calculate storage size
        storage_bytes = 0
        if self.memories_file.exists():
            storage_bytes = self.memories_file.stat().st_size

        return {
            "total_memories": total,
            "by_category": by_category,
            "top_tags": dict(top_tags),
            "storage_bytes": storage_bytes
        }

    def cleanup_expired(self) -> int:
        """Remove expired memories."""
        now = datetime.utcnow()
        expired_ids = []

        # Find expired memories in index
        for memory_id, meta in self.index.get("by_id", {}).items():
            expires_at = meta.get("expires_at")
            if expires_at:
                try:
                    exp_time = datetime.fromisoformat(expires_at.rstrip("Z"))
                    if exp_time < now:
                        expired_ids.append(memory_id)
                except Exception:
                    pass

        # Delete expired memories
        for memory_id in expired_ids:
            self.delete(memory_id)

        return len(expired_ids)

    def export_all(self) -> List[Dict]:
        """Export all memories as a list."""
        memories = []
        if not self.memories_file.exists():
            return memories

        with open(self.memories_file) as f:
            for line in f:
                try:
                    data = json.loads(line)
                    # Only include if still in index (not deleted)
                    if data.get("id") in self.index.get("by_id", {}):
                        memories.append(data)
                except Exception:
                    continue

        return memories

    def import_memories(self, memories: List[Dict]) -> Dict[str, int]:
        """Import memories from a list."""
        imported = 0
        skipped = 0

        for data in memories:
            try:
                memory = Memory(**data)
                # Skip if already exists
                if memory.id and memory.id in self.index.get("by_id", {}):
                    skipped += 1
                    continue

                self.store(memory)
                imported += 1
            except Exception:
                skipped += 1

        return {"imported": imported, "skipped": skipped}

    def bulk_delete(self, category: Optional[str] = None, older_than_days: Optional[int] = None) -> int:
        """Delete multiple memories by criteria."""
        deleted = 0
        cutoff = None
        if older_than_days:
            cutoff = datetime.utcnow() - timedelta(days=older_than_days)

        ids_to_delete = []

        for memory_id, meta in list(self.index.get("by_id", {}).items()):
            should_delete = False

            # Category filter
            if category and meta.get("category") == category:
                should_delete = True

            # Age filter
            if cutoff:
                ts = meta.get("timestamp")
                if ts:
                    try:
                        mem_time = datetime.fromisoformat(ts.rstrip("Z"))
                        if mem_time < cutoff:
                            should_delete = True
                    except Exception:
                        pass

            if should_delete:
                ids_to_delete.append(memory_id)

        for memory_id in ids_to_delete:
            if self.delete(memory_id):
                deleted += 1

        return deleted

    def list_paginated(
        self,
        category: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """List memories with pagination."""
        all_memories = []

        if not self.memories_file.exists():
            return {"memories": [], "total": 0, "limit": limit, "offset": offset}

        with open(self.memories_file) as f:
            for line in f:
                try:
                    data = json.loads(line)
                    # Only include if still in index
                    if data.get("id") not in self.index.get("by_id", {}):
                        continue
                    if category and data.get("category") != category:
                        continue
                    all_memories.append(data)
                except Exception:
                    continue

        # Sort by timestamp descending
        all_memories.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        total = len(all_memories)
        paginated = all_memories[offset:offset + limit]

        return {
            "memories": [Memory(**m) for m in paginated],
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(paginated) < total
        }

    def compact(self) -> Dict[str, Any]:
        """Compact the memories file by removing deleted entries."""
        if not self.memories_file.exists():
            return {"before": 0, "after": 0}

        # Read all valid memories
        valid_memories = []
        original_size = self.memories_file.stat().st_size

        with open(self.memories_file) as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if data.get("id") in self.index.get("by_id", {}):
                        valid_memories.append(line)
                except Exception:
                    continue

        # Rewrite file
        with open(self.memories_file, "w") as f:
            for line in valid_memories:
                f.write(line)

        new_size = self.memories_file.stat().st_size

        return {
            "before_bytes": original_size,
            "after_bytes": new_size,
            "saved_bytes": original_size - new_size,
            "valid_memories": len(valid_memories)
        }


# Global instance
store = MemoryStore(DATA_DIR)


# Optional: AI-powered semantic search
async def semantic_search(
    query: str,
    memories: List[Memory],
    limit: int = 5
) -> List[Memory]:
    """Use LocalAI for semantic similarity search."""
    try:
        async with httpx.AsyncClient() as client:
            # Get embeddings via LocalAI
            response = await client.post(
                "http://127.0.0.1:8081/v1/embeddings",
                json={"input": query, "model": "all-minilm-l6-v2"},
                timeout=10.0
            )
            if response.status_code != 200:
                return memories[:limit]

            query_embedding = response.json()["data"][0]["embedding"]

            # Score memories by similarity (simplified)
            scored = []
            for memory in memories:
                # Get memory embedding
                resp = await client.post(
                    "http://127.0.0.1:8081/v1/embeddings",
                    json={"input": memory.content, "model": "all-minilm-l6-v2"},
                    timeout=5.0
                )
                if resp.status_code == 200:
                    mem_embedding = resp.json()["data"][0]["embedding"]
                    # Cosine similarity
                    dot = sum(a*b for a, b in zip(query_embedding, mem_embedding))
                    scored.append((memory, dot))

            scored.sort(key=lambda x: x[1], reverse=True)
            return [m for m, _ in scored[:limit]]

    except Exception as e:
        logger.warning(f"Semantic search failed: {e}")
        return memories[:limit]


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    stats = store.get_stats()
    return {
        "module": "localrecall",
        "status": "ok",
        "version": "1.0.0",
        "total_memories": stats["total_memories"]
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.post("/memories", dependencies=[Depends(require_jwt)])
async def create_memory(memory: Memory):
    """Store a new memory."""
    memory_id = store.store(memory)
    return {"id": memory_id, "status": "stored"}


@app.get("/memories/{memory_id}", dependencies=[Depends(require_jwt)])
async def get_memory(memory_id: str):
    """Retrieve a memory by ID."""
    memory = store.get(memory_id)
    if not memory:
        raise HTTPException(status_code=404, detail="Memory not found")
    return memory


@app.delete("/memories/{memory_id}", dependencies=[Depends(require_jwt)])
async def delete_memory(memory_id: str):
    """Delete a memory."""
    if not store.delete(memory_id):
        raise HTTPException(status_code=404, detail="Memory not found")
    return {"status": "deleted"}


@app.post("/search", dependencies=[Depends(require_jwt)])
async def search_memories(query: SearchQuery):
    """Search memories."""
    results = store.search(
        query=query.query,
        category=query.category.value if query.category else None,
        tags=query.tags,
        min_importance=query.min_importance or 0,
        limit=query.limit * 2 if query.semantic else query.limit
    )

    # Optional semantic reranking
    if query.semantic and results:
        results = await semantic_search(query.query, results, query.limit)

    return {"results": results, "count": len(results)}


@app.get("/categories", dependencies=[Depends(require_jwt)])
async def list_categories():
    """List memory categories with counts."""
    stats = store.get_stats()
    return {"categories": stats["by_category"]}


@app.get("/categories/{category}", dependencies=[Depends(require_jwt)])
async def get_category_memories(
    category: MemoryCategory,
    limit: int = Query(default=50, le=200)
):
    """List memories in a category."""
    memories = store.list_by_category(category.value, limit)
    return {"category": category, "memories": memories, "count": len(memories)}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get memory statistics."""
    return store.get_stats()


@app.get("/memories", dependencies=[Depends(require_jwt)])
async def list_memories(
    category: Optional[MemoryCategory] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0)
):
    """List memories with pagination."""
    return store.list_paginated(
        category=category.value if category else None,
        limit=limit,
        offset=offset
    )


@app.post("/export", dependencies=[Depends(require_jwt)])
async def export_memories():
    """Export all memories for backup."""
    memories = store.export_all()
    return {
        "memories": memories,
        "count": len(memories),
        "exported_at": datetime.utcnow().isoformat() + "Z"
    }


@app.post("/import", dependencies=[Depends(require_jwt)])
async def import_memories(data: Dict[str, Any]):
    """Import memories from backup."""
    memories = data.get("memories", [])
    if not memories:
        raise HTTPException(status_code=400, detail="No memories to import")

    result = store.import_memories(memories)
    return result


@app.post("/cleanup", dependencies=[Depends(require_jwt)])
async def cleanup_expired():
    """Remove expired memories."""
    count = store.cleanup_expired()
    return {"expired_removed": count}


@app.post("/bulk-delete", dependencies=[Depends(require_jwt)])
async def bulk_delete(
    category: Optional[MemoryCategory] = None,
    older_than_days: Optional[int] = None
):
    """Delete multiple memories by criteria."""
    if not category and not older_than_days:
        raise HTTPException(status_code=400, detail="Must specify category or older_than_days")

    count = store.bulk_delete(
        category=category.value if category else None,
        older_than_days=older_than_days
    )
    return {"deleted": count}


@app.post("/compact", dependencies=[Depends(require_jwt)])
async def compact_storage():
    """Compact storage by removing deleted entries."""
    result = store.compact()
    return result


@app.post("/summarize", dependencies=[Depends(require_jwt)])
async def summarize_memories(
    category: Optional[MemoryCategory] = None,
    limit: int = 20
):
    """AI-summarize recent memories (requires LocalAI)."""
    if category:
        memories = store.list_by_category(category.value, limit)
    else:
        # Get recent from all categories
        memories = []
        for cat in MemoryCategory:
            memories.extend(store.list_by_category(cat.value, 5))

    if not memories:
        return {"summary": "No memories to summarize."}

    # Build context
    context = "\n".join([
        f"[{m.category}] {m.content}"
        for m in memories[:limit]
    ])

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://127.0.0.1:8081/v1/chat/completions",
                json={
                    "model": "mistral-7b-instruct-v0.3",
                    "messages": [
                        {"role": "system", "content": "Summarize these security memories concisely."},
                        {"role": "user", "content": context}
                    ],
                    "max_tokens": 500
                },
                timeout=30.0
            )
            if response.status_code == 200:
                summary = response.json()["choices"][0]["message"]["content"]
                return {"summary": summary, "memory_count": len(memories)}
    except Exception as e:
        logger.warning(f"Summarization failed: {e}")

    return {"summary": "Summarization unavailable (LocalAI not running)", "memory_count": len(memories)}


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not MEMORIES_FILE.exists():
        MEMORIES_FILE.touch()
    logger.info("LocalRecall started")
