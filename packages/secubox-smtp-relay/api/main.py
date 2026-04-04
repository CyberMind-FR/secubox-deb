"""
SecuBox-Deb :: secubox-smtp-relay
SMTP relay module for forwarding emails through a smarthost.
CyberMind — https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger
import subprocess
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Optional

app = FastAPI(title="secubox-smtp-relay", version="1.0.0", root_path="/api/v1/smtp-relay")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("smtp-relay")

CONFIG_FILE = Path("/etc/secubox/smtp-relay.toml")
POSTFIX_MAIN_CF = Path("/etc/postfix/main.cf")
POSTFIX_SASL_PASSWD = Path("/etc/postfix/sasl_passwd")


def _run(cmd: list[str], timeout: int = 30) -> tuple[bool, str]:
    """Run a command and return (success, output)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def _postfix_running() -> bool:
    """Check if postfix is running."""
    ok, _ = _run(["systemctl", "is-active", "--quiet", "postfix"])
    return ok


def _get_queue_size() -> int:
    """Get mail queue size."""
    ok, out = _run(["postqueue", "-p"])
    if not ok:
        return 0
    # Count queue entries (lines starting with queue ID)
    count = 0
    for line in out.splitlines():
        if re.match(r'^[A-F0-9]{10,}', line):
            count += 1
    return count


def _get_queue_list() -> list[dict]:
    """Get detailed mail queue list."""
    ok, out = _run(["postqueue", "-j"])
    if not ok:
        return []

    queue = []
    for line in out.splitlines():
        if line.strip():
            try:
                entry = json.loads(line)
                queue.append({
                    "id": entry.get("queue_id", ""),
                    "sender": entry.get("sender", ""),
                    "recipients": entry.get("recipients", []),
                    "arrival_time": entry.get("arrival_time", 0),
                    "message_size": entry.get("message_size", 0),
                    "queue_name": entry.get("queue_name", ""),
                    "reason": entry.get("recipients", [{}])[0].get("delay_reason", "") if entry.get("recipients") else ""
                })
            except json.JSONDecodeError:
                continue
    return queue


def _get_sent_count() -> int:
    """Get approximate sent email count from mail.log."""
    log_file = Path("/var/log/mail.log")
    if not log_file.exists():
        return 0
    try:
        ok, out = _run(["grep", "-c", "status=sent", str(log_file)])
        if ok:
            return int(out.strip())
    except:
        pass
    return 0


def _get_failed_count() -> int:
    """Get approximate failed email count from mail.log."""
    log_file = Path("/var/log/mail.log")
    if not log_file.exists():
        return 0
    try:
        ok, out = _run(["grep", "-c", "status=bounced\\|status=deferred", str(log_file)])
        if ok:
            return int(out.strip())
    except:
        pass
    return 0


def _load_config() -> dict:
    """Load relay configuration from TOML or postfix config."""
    config = {
        "smarthost": "",
        "port": 587,
        "username": "",
        "password": "",
        "tls": True,
        "from_domain": ""
    }

    # Try to read from TOML config
    if CONFIG_FILE.exists():
        try:
            import tomllib
            with open(CONFIG_FILE, "rb") as f:
                data = tomllib.load(f)
                config.update(data.get("relay", {}))
                return config
        except:
            pass

    # Fallback: read from postfix config
    if POSTFIX_MAIN_CF.exists():
        try:
            content = POSTFIX_MAIN_CF.read_text()
            # Extract relayhost
            m = re.search(r'^relayhost\s*=\s*\[?([^\]\s:]+)\]?:?(\d+)?', content, re.MULTILINE)
            if m:
                config["smarthost"] = m.group(1)
                if m.group(2):
                    config["port"] = int(m.group(2))

            # Check TLS settings
            if "smtp_tls_security_level = encrypt" in content:
                config["tls"] = True

            # Read SASL credentials
            if POSTFIX_SASL_PASSWD.exists():
                sasl_content = POSTFIX_SASL_PASSWD.read_text()
                m = re.search(r'^\S+\s+(\S+):(\S+)', sasl_content, re.MULTILINE)
                if m:
                    config["username"] = m.group(1)
                    # Don't expose password, just indicate it's set
                    config["password"] = "********" if m.group(2) else ""
        except:
            pass

    return config


def _save_config(config: dict) -> bool:
    """Save relay configuration to TOML and update postfix."""
    try:
        # Save to TOML
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

        toml_content = f"""# SecuBox SMTP Relay Configuration
[relay]
smarthost = "{config.get('smarthost', '')}"
port = {config.get('port', 587)}
username = "{config.get('username', '')}"
password = "{config.get('password', '')}"
tls = {str(config.get('tls', True)).lower()}
from_domain = "{config.get('from_domain', '')}"
"""
        CONFIG_FILE.write_text(toml_content)

        # Update postfix main.cf
        smarthost = config.get("smarthost", "")
        port = config.get("port", 587)
        tls = config.get("tls", True)

        postfix_settings = f"""
# SecuBox SMTP Relay Settings
relayhost = [{smarthost}]:{port}
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = {"encrypt" if tls else "may"}
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
"""

        # Read existing main.cf and update
        if POSTFIX_MAIN_CF.exists():
            content = POSTFIX_MAIN_CF.read_text()
            # Remove existing relay settings
            content = re.sub(r'\n# SecuBox SMTP Relay Settings.*?(?=\n[^\n]|\Z)', '', content, flags=re.DOTALL)
            content = content.rstrip() + "\n" + postfix_settings
        else:
            content = postfix_settings

        POSTFIX_MAIN_CF.write_text(content)

        # Update SASL password file
        username = config.get("username", "")
        password = config.get("password", "")
        if username and password and password != "********":
            POSTFIX_SASL_PASSWD.parent.mkdir(parents=True, exist_ok=True)
            POSTFIX_SASL_PASSWD.write_text(f"[{smarthost}]:{port} {username}:{password}\n")
            POSTFIX_SASL_PASSWD.chmod(0o600)
            # Update postmap
            _run(["postmap", str(POSTFIX_SASL_PASSWD)])

        return True
    except Exception as e:
        log.error(f"Failed to save config: {e}")
        return False


@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Get relay status including queue size and sent count."""
    running = _postfix_running()
    queue_size = _get_queue_size() if running else 0
    sent_count = _get_sent_count()
    failed_count = _get_failed_count()
    config = _load_config()

    return {
        "running": running,
        "queue_size": queue_size,
        "sent_count": sent_count,
        "failed_count": failed_count,
        "smarthost": config.get("smarthost", ""),
        "configured": bool(config.get("smarthost")),
    }


@router.get("/health")
async def health():
    """Health check endpoint (no auth required)."""
    running = _postfix_running()
    return {
        "status": "ok" if running else "degraded",
        "module": "smtp-relay",
        "version": "1.0.0",
        "postfix_running": running,
    }


@router.get("/queue")
async def queue(user=Depends(require_jwt)):
    """Get mail queue list."""
    queue_list = _get_queue_list()
    return {
        "queue": queue_list,
        "count": len(queue_list),
    }


@router.post("/queue/flush")
async def queue_flush(user=Depends(require_jwt)):
    """Flush the mail queue (attempt to deliver all queued messages)."""
    ok, out = _run(["postqueue", "-f"])
    log.info(f"Queue flush requested by {user.get('sub', 'unknown')}")
    return {"success": ok, "output": out[:500]}


@router.delete("/queue/{queue_id}")
async def queue_delete(queue_id: str, user=Depends(require_jwt)):
    """Delete a specific message from the queue."""
    # Validate queue_id format (alphanumeric, 10-20 chars)
    if not re.match(r'^[A-F0-9]{10,20}$', queue_id):
        raise HTTPException(400, "Invalid queue ID format")

    ok, out = _run(["postsuper", "-d", queue_id])
    log.info(f"Queue delete {queue_id} requested by {user.get('sub', 'unknown')}: {'success' if ok else 'failed'}")
    return {"success": ok, "output": out[:500]}


@router.get("/stats")
async def stats(user=Depends(require_jwt)):
    """Get delivery statistics."""
    sent_count = _get_sent_count()
    failed_count = _get_failed_count()
    queue_size = _get_queue_size()

    # Parse mail.log for more detailed stats
    stats_data = {
        "sent": sent_count,
        "failed": failed_count,
        "queued": queue_size,
        "deferred": 0,
        "bounced": 0,
    }

    log_file = Path("/var/log/mail.log")
    if log_file.exists():
        try:
            ok, out = _run(["grep", "-c", "status=deferred", str(log_file)])
            if ok:
                stats_data["deferred"] = int(out.strip())
        except:
            pass
        try:
            ok, out = _run(["grep", "-c", "status=bounced", str(log_file)])
            if ok:
                stats_data["bounced"] = int(out.strip())
        except:
            pass

    return stats_data


@router.post("/start")
async def start(user=Depends(require_jwt)):
    """Start postfix service."""
    ok, out = _run(["systemctl", "start", "postfix"])
    log.info(f"Postfix start requested by {user.get('sub', 'unknown')}: {'success' if ok else 'failed'}")
    return {"success": ok, "output": out[:500]}


@router.post("/stop")
async def stop(user=Depends(require_jwt)):
    """Stop postfix service."""
    ok, out = _run(["systemctl", "stop", "postfix"])
    log.info(f"Postfix stop requested by {user.get('sub', 'unknown')}: {'success' if ok else 'failed'}")
    return {"success": ok, "output": out[:500]}


@router.post("/restart")
async def restart(user=Depends(require_jwt)):
    """Restart postfix service."""
    ok, out = _run(["systemctl", "restart", "postfix"])
    log.info(f"Postfix restart requested by {user.get('sub', 'unknown')}: {'success' if ok else 'failed'}")
    return {"success": ok, "output": out[:500]}


@router.get("/config")
async def get_config(user=Depends(require_jwt)):
    """Get relay configuration."""
    config = _load_config()
    # Mask password for security
    if config.get("password"):
        config["password"] = "********"
    return config


class RelayConfig(BaseModel):
    smarthost: str
    port: int = 587
    username: str = ""
    password: str = ""
    tls: bool = True
    from_domain: str = ""


@router.post("/config")
async def set_config(config: RelayConfig, user=Depends(require_jwt)):
    """Update relay configuration."""
    config_dict = config.model_dump()

    # If password is masked, keep existing password
    if config_dict.get("password") == "********":
        existing = _load_config()
        # Load actual password from SASL file
        if POSTFIX_SASL_PASSWD.exists():
            try:
                sasl_content = POSTFIX_SASL_PASSWD.read_text()
                m = re.search(r'^\S+\s+\S+:(\S+)', sasl_content, re.MULTILINE)
                if m:
                    config_dict["password"] = m.group(1)
            except:
                pass

    ok = _save_config(config_dict)
    if ok:
        log.info(f"Config updated by {user.get('sub', 'unknown')}")
        # Reload postfix to apply changes
        _run(["systemctl", "reload", "postfix"])

    return {"success": ok}


@router.get("/logs")
async def logs(lines: int = 100, user=Depends(require_jwt)):
    """Get mail logs."""
    lines = min(lines, 500)  # Limit to 500 lines

    ok, out = _run(["journalctl", "-u", "postfix@-.service", "-n", str(lines), "--no-pager"])
    if not ok:
        # Fallback to mail.log
        log_file = Path("/var/log/mail.log")
        if log_file.exists():
            ok, out = _run(["tail", "-n", str(lines), str(log_file)])

    return {"lines": out.splitlines() if ok else [], "count": len(out.splitlines()) if ok else 0}


class TestEmail(BaseModel):
    to: EmailStr
    subject: str = "SecuBox SMTP Relay Test"
    body: str = "This is a test email from SecuBox SMTP Relay."


@router.post("/test")
async def test_email(email: TestEmail, user=Depends(require_jwt)):
    """Send a test email through the relay."""
    config = _load_config()
    if not config.get("smarthost"):
        raise HTTPException(400, "Smarthost not configured")

    from_addr = f"test@{config.get('from_domain', 'localhost')}"

    # Create email content
    email_content = f"""From: {from_addr}
To: {email.to}
Subject: {email.subject}
Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')}
X-Mailer: SecuBox-SMTP-Relay

{email.body}
"""

    # Send via sendmail
    try:
        proc = subprocess.run(
            ["/usr/sbin/sendmail", "-t", "-oi"],
            input=email_content,
            capture_output=True,
            text=True,
            timeout=30
        )
        ok = proc.returncode == 0
        log.info(f"Test email to {email.to} by {user.get('sub', 'unknown')}: {'success' if ok else 'failed'}")
        return {
            "success": ok,
            "message": "Test email queued for delivery" if ok else proc.stderr[:200],
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "message": "Sendmail timed out"}
    except Exception as e:
        log.error(f"Test email failed: {e}")
        return {"success": False, "message": str(e)[:200]}


app.include_router(router)
