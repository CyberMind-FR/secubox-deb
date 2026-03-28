"""SecuBox Vault API - Secrets management."""
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import subprocess
import json
import os
import hashlib
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = FastAPI(title="SecuBox Vault API", version="1.0.0")

VAULT_DIR = "/var/lib/secubox/vault"
SECRETS_FILE = f"{VAULT_DIR}/secrets.enc"
KEY_FILE = f"{VAULT_DIR}/.key"
AUDIT_LOG = f"{VAULT_DIR}/audit.log"
HASHICORP_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")


class Secret(BaseModel):
    key: str
    value: str
    description: str = ""
    tags: list = []


class SecretUpdate(BaseModel):
    value: str
    description: str = None


def get_or_create_key() -> bytes:
    """Get or create encryption key."""
    os.makedirs(VAULT_DIR, exist_ok=True)

    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()

    # Generate new key
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    os.chmod(KEY_FILE, 0o600)

    return key


def get_fernet() -> Fernet:
    """Get Fernet cipher instance."""
    return Fernet(get_or_create_key())


def load_secrets() -> dict:
    """Load and decrypt secrets store."""
    if not os.path.exists(SECRETS_FILE):
        return {}

    try:
        with open(SECRETS_FILE, 'rb') as f:
            encrypted = f.read()

        fernet = get_fernet()
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted.decode())
    except Exception:
        return {}


def save_secrets(secrets: dict):
    """Encrypt and save secrets store."""
    os.makedirs(VAULT_DIR, exist_ok=True)

    fernet = get_fernet()
    data = json.dumps(secrets).encode()
    encrypted = fernet.encrypt(data)

    with open(SECRETS_FILE, 'wb') as f:
        f.write(encrypted)
    os.chmod(SECRETS_FILE, 0o600)


def audit_log(action: str, key: str, details: str = ""):
    """Write to audit log."""
    os.makedirs(VAULT_DIR, exist_ok=True)

    timestamp = datetime.utcnow().isoformat()
    entry = f"{timestamp} | {action} | {key} | {details}\n"

    with open(AUDIT_LOG, 'a') as f:
        f.write(entry)


def is_hashicorp_vault_running() -> bool:
    """Check if HashiCorp Vault is running."""
    try:
        result = subprocess.run(
            ["vault", "status", "-format=json"],
            capture_output=True, text=True, timeout=5,
            env={**os.environ, "VAULT_ADDR": HASHICORP_ADDR}
        )
        return result.returncode in [0, 2]  # 0=unsealed, 2=sealed
    except Exception:
        return False


def get_hashicorp_status() -> dict:
    """Get HashiCorp Vault status."""
    try:
        result = subprocess.run(
            ["vault", "status", "-format=json"],
            capture_output=True, text=True, timeout=5,
            env={**os.environ, "VAULT_ADDR": HASHICORP_ADDR}
        )
        if result.returncode in [0, 2]:
            return json.loads(result.stdout)
    except Exception:
        pass
    return {}


@app.get("/health")
def health():
    return {"status": "ok", "service": "vault"}


@app.get("/status")
def get_status():
    """Get vault status."""
    secrets = load_secrets()
    hc_running = is_hashicorp_vault_running()
    hc_status = get_hashicorp_status() if hc_running else {}

    return {
        "local_secrets_count": len(secrets),
        "vault_dir": VAULT_DIR,
        "hashicorp_vault": {
            "available": hc_running,
            "sealed": hc_status.get("sealed", True) if hc_status else None,
            "version": hc_status.get("version"),
            "address": HASHICORP_ADDR
        },
        "encryption": "Fernet (AES-128-CBC)"
    }


@app.get("/secrets")
def list_secrets():
    """List all secret keys (without values)."""
    secrets = load_secrets()

    items = []
    for key, data in secrets.items():
        items.append({
            "key": key,
            "description": data.get("description", ""),
            "tags": data.get("tags", []),
            "created": data.get("created"),
            "updated": data.get("updated")
        })

    return {"secrets": items}


@app.get("/secrets/{key}")
def get_secret(key: str):
    """Get a specific secret."""
    secrets = load_secrets()

    if key not in secrets:
        raise HTTPException(status_code=404, detail="Secret not found")

    audit_log("READ", key)

    data = secrets[key]
    return {
        "key": key,
        "value": data["value"],
        "description": data.get("description", ""),
        "tags": data.get("tags", []),
        "created": data.get("created"),
        "updated": data.get("updated")
    }


@app.post("/secrets")
def create_secret(secret: Secret):
    """Create a new secret."""
    secrets = load_secrets()

    if secret.key in secrets:
        raise HTTPException(status_code=409, detail="Secret already exists")

    now = datetime.utcnow().isoformat()
    secrets[secret.key] = {
        "value": secret.value,
        "description": secret.description,
        "tags": secret.tags,
        "created": now,
        "updated": now
    }

    save_secrets(secrets)
    audit_log("CREATE", secret.key)

    return {"status": "created", "key": secret.key}


@app.put("/secrets/{key}")
def update_secret(key: str, update: SecretUpdate):
    """Update an existing secret."""
    secrets = load_secrets()

    if key not in secrets:
        raise HTTPException(status_code=404, detail="Secret not found")

    secrets[key]["value"] = update.value
    secrets[key]["updated"] = datetime.utcnow().isoformat()

    if update.description is not None:
        secrets[key]["description"] = update.description

    save_secrets(secrets)
    audit_log("UPDATE", key)

    return {"status": "updated", "key": key}


@app.delete("/secrets/{key}")
def delete_secret(key: str):
    """Delete a secret."""
    secrets = load_secrets()

    if key not in secrets:
        raise HTTPException(status_code=404, detail="Secret not found")

    del secrets[key]
    save_secrets(secrets)
    audit_log("DELETE", key)

    return {"status": "deleted", "key": key}


@app.post("/secrets/{key}/rotate")
def rotate_secret(key: str):
    """Rotate (regenerate) a secret value."""
    secrets = load_secrets()

    if key not in secrets:
        raise HTTPException(status_code=404, detail="Secret not found")

    # Generate new random value
    import secrets as py_secrets
    new_value = py_secrets.token_urlsafe(32)

    old_value = secrets[key]["value"]
    secrets[key]["value"] = new_value
    secrets[key]["updated"] = datetime.utcnow().isoformat()

    save_secrets(secrets)
    audit_log("ROTATE", key, f"old_hash={hashlib.sha256(old_value.encode()).hexdigest()[:8]}")

    return {"status": "rotated", "key": key, "new_value": new_value}


@app.get("/secrets/search/{query}")
def search_secrets(query: str):
    """Search secrets by key or description."""
    secrets = load_secrets()
    query_lower = query.lower()

    results = []
    for key, data in secrets.items():
        if query_lower in key.lower() or query_lower in data.get("description", "").lower():
            results.append({
                "key": key,
                "description": data.get("description", ""),
                "tags": data.get("tags", [])
            })

    return {"query": query, "results": results}


@app.get("/secrets/tag/{tag}")
def get_secrets_by_tag(tag: str):
    """Get secrets by tag."""
    secrets = load_secrets()

    results = []
    for key, data in secrets.items():
        if tag in data.get("tags", []):
            results.append({
                "key": key,
                "description": data.get("description", ""),
                "tags": data.get("tags", [])
            })

    return {"tag": tag, "secrets": results}


@app.get("/audit")
def get_audit_log(lines: int = 50):
    """Get recent audit log entries."""
    if not os.path.exists(AUDIT_LOG):
        return {"entries": []}

    with open(AUDIT_LOG, 'r') as f:
        all_lines = f.readlines()

    entries = []
    for line in all_lines[-lines:]:
        parts = line.strip().split(" | ")
        if len(parts) >= 3:
            entries.append({
                "timestamp": parts[0],
                "action": parts[1],
                "key": parts[2],
                "details": parts[3] if len(parts) > 3 else ""
            })

    return {"entries": entries}


@app.post("/generate")
def generate_secret(length: int = 32, type: str = "urlsafe"):
    """Generate a random secret value."""
    import secrets as py_secrets

    if type == "urlsafe":
        value = py_secrets.token_urlsafe(length)
    elif type == "hex":
        value = py_secrets.token_hex(length)
    elif type == "bytes":
        value = base64.b64encode(py_secrets.token_bytes(length)).decode()
    else:
        raise HTTPException(status_code=400, detail="Type must be urlsafe, hex, or bytes")

    return {"value": value, "type": type, "length": len(value)}


@app.post("/export")
def export_secrets(include_values: bool = False):
    """Export secrets (optionally with values)."""
    secrets = load_secrets()

    export_data = []
    for key, data in secrets.items():
        item = {
            "key": key,
            "description": data.get("description", ""),
            "tags": data.get("tags", []),
            "created": data.get("created"),
            "updated": data.get("updated")
        }
        if include_values:
            item["value"] = data["value"]
        export_data.append(item)

    audit_log("EXPORT", "*", f"include_values={include_values}")

    return {"secrets": export_data, "count": len(export_data)}


@app.post("/import")
def import_secrets(secrets_data: list, overwrite: bool = False):
    """Import secrets from export data."""
    secrets = load_secrets()
    imported = 0
    skipped = 0

    for item in secrets_data:
        key = item.get("key")
        if not key or "value" not in item:
            continue

        if key in secrets and not overwrite:
            skipped += 1
            continue

        now = datetime.utcnow().isoformat()
        secrets[key] = {
            "value": item["value"],
            "description": item.get("description", ""),
            "tags": item.get("tags", []),
            "created": item.get("created", now),
            "updated": now
        }
        imported += 1

    save_secrets(secrets)
    audit_log("IMPORT", "*", f"imported={imported} skipped={skipped}")

    return {"imported": imported, "skipped": skipped}
