# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Modem SMS Router
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>

API endpoints for SMS send/receive.
"""
import asyncio
import json
import re
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

log = get_logger("modem-sms")
router = APIRouter()


# === SMS Models ===

class SMSMessage(BaseModel):
    id: str
    number: str
    text: str
    timestamp: str
    direction: str  # "incoming" or "outgoing"
    state: str  # "received", "sent", "sending", "failed"


class SMSSendRequest(BaseModel):
    number: str = Field(..., min_length=3, max_length=20)
    text: str = Field(..., min_length=1, max_length=160)


class SMSSendResponse(BaseModel):
    success: bool
    message_id: Optional[str] = None
    error: Optional[str] = None


# === Helper Functions ===

async def _run_mmcli(*args: str, timeout: int = 30) -> Dict[str, Any]:
    """Run mmcli command."""
    cmd = ["mmcli"] + list(args)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )

        output = stdout.decode().strip()
        error = stderr.decode().strip()

        if proc.returncode != 0:
            return {"success": False, "error": error, "output": output}

        return {"success": True, "output": output}

    except asyncio.TimeoutError:
        return {"success": False, "error": "Command timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def _get_modem_index() -> int:
    """Get first modem index."""
    result = await _run_mmcli("-L", "-J")
    if result.get("success"):
        try:
            data = json.loads(result.get("output", "{}"))
            modem_list = data.get("modem-list", [])
            if modem_list:
                # Extract index from path like /org/freedesktop/ModemManager1/Modem/0
                path = modem_list[0]
                return int(path.split("/")[-1])
        except Exception:
            pass
    return 0


async def _list_sms_messages() -> List[SMSMessage]:
    """List all SMS messages from modem."""
    modem_idx = await _get_modem_index()

    result = await _run_mmcli("-m", str(modem_idx), "--messaging-list-sms", "-J")

    if not result.get("success"):
        return []

    messages = []

    try:
        data = json.loads(result.get("output", "{}"))
        sms_list = data.get("modem", {}).get("messaging", {}).get("sms", [])

        for sms_path in sms_list:
            # Get SMS details
            sms_idx = sms_path.split("/")[-1]
            sms_result = await _run_mmcli("-s", sms_idx, "-J")

            if sms_result.get("success"):
                sms_data = json.loads(sms_result.get("output", "{}"))
                sms = sms_data.get("sms", {})
                content = sms.get("content", {})
                props = sms.get("properties", {})

                messages.append(SMSMessage(
                    id=sms_idx,
                    number=content.get("number", ""),
                    text=content.get("text", ""),
                    timestamp=props.get("timestamp", datetime.now().isoformat()),
                    direction="incoming" if props.get("pdu-type") == "deliver" else "outgoing",
                    state=props.get("state", "unknown"),
                ))

    except Exception as e:
        log.error("Failed to parse SMS list: %s", e)

    return messages


async def _send_sms(number: str, text: str) -> Dict[str, Any]:
    """Send an SMS message."""
    modem_idx = await _get_modem_index()

    # Create SMS
    result = await _run_mmcli(
        "-m", str(modem_idx),
        f"--messaging-create-sms=text='{text}',number='{number}'"
    )

    if not result.get("success"):
        return {"success": False, "error": result.get("error", "Failed to create SMS")}

    # Extract SMS path from output
    output = result.get("output", "")
    match = re.search(r"/SMS/(\d+)", output)
    if not match:
        return {"success": False, "error": "Failed to get SMS ID"}

    sms_idx = match.group(1)

    # Send SMS
    result = await _run_mmcli("-s", sms_idx, "--send")

    if result.get("success"):
        return {"success": True, "message_id": sms_idx}
    else:
        return {"success": False, "error": result.get("error", "Failed to send SMS")}


async def _delete_sms(sms_id: str) -> Dict[str, Any]:
    """Delete an SMS message."""
    modem_idx = await _get_modem_index()

    result = await _run_mmcli(
        "-m", str(modem_idx),
        f"--messaging-delete-sms=/org/freedesktop/ModemManager1/SMS/{sms_id}"
    )

    return {
        "success": result.get("success", False),
        "error": result.get("error"),
    }


# === Endpoints ===

@router.get("/sms")
async def list_sms(
    direction: Optional[str] = Query(None, enum=["incoming", "outgoing"]),
    limit: int = Query(default=50, le=100),
    user=Depends(require_jwt)
):
    """List SMS messages."""
    messages = await _list_sms_messages()

    if direction:
        messages = [m for m in messages if m.direction == direction]

    # Sort by timestamp descending
    messages.sort(key=lambda m: m.timestamp, reverse=True)

    return {
        "messages": [m.model_dump() for m in messages[:limit]],
        "total": len(messages),
    }


@router.post("/sms/send", response_model=SMSSendResponse)
async def send_sms(req: SMSSendRequest, user=Depends(require_jwt)):
    """Send an SMS message."""
    log.info("Sending SMS to %s: %s...", req.number, req.text[:20])

    # Basic validation
    number = req.number.strip()
    if not re.match(r'^[\+]?[0-9]{3,20}$', number):
        raise HTTPException(400, "Invalid phone number format")

    text = req.text.strip()
    if len(text) > 160:
        # For now, don't support multipart SMS
        raise HTTPException(400, "Message too long (max 160 characters)")

    result = await _send_sms(number, text)

    return SMSSendResponse(
        success=result.get("success", False),
        message_id=result.get("message_id"),
        error=result.get("error"),
    )


@router.delete("/sms/{sms_id}")
async def delete_sms(sms_id: str, user=Depends(require_jwt)):
    """Delete an SMS message by ID."""
    result = await _delete_sms(sms_id)
    return result


@router.post("/sms/delete-all")
async def delete_all_sms(user=Depends(require_jwt)):
    """Delete all SMS messages."""
    messages = await _list_sms_messages()
    deleted = 0
    errors = 0

    for msg in messages:
        result = await _delete_sms(msg.id)
        if result.get("success"):
            deleted += 1
        else:
            errors += 1

    return {
        "success": errors == 0,
        "deleted": deleted,
        "errors": errors,
    }


@router.get("/sms/{sms_id}")
async def get_sms(sms_id: str, user=Depends(require_jwt)):
    """Get a specific SMS message."""
    result = await _run_mmcli("-s", sms_id, "-J")

    if not result.get("success"):
        raise HTTPException(404, "SMS not found")

    try:
        data = json.loads(result.get("output", "{}"))
        sms = data.get("sms", {})
        content = sms.get("content", {})
        props = sms.get("properties", {})

        return {
            "id": sms_id,
            "number": content.get("number", ""),
            "text": content.get("text", ""),
            "timestamp": props.get("timestamp", ""),
            "direction": "incoming" if props.get("pdu-type") == "deliver" else "outgoing",
            "state": props.get("state", "unknown"),
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to parse SMS: {e}")


@router.get("/sms/stats")
async def get_sms_stats(user=Depends(require_jwt)):
    """Get SMS statistics."""
    messages = await _list_sms_messages()

    incoming = [m for m in messages if m.direction == "incoming"]
    outgoing = [m for m in messages if m.direction == "outgoing"]

    return {
        "total": len(messages),
        "incoming": len(incoming),
        "outgoing": len(outgoing),
        "unread": len([m for m in incoming if m.state == "received"]),
    }
