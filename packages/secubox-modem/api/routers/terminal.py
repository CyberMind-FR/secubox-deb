# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Modem AT Terminal Router
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>

WebSocket endpoint for interactive AT command console.
"""
import asyncio
import json
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel

from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

from core.at_interface import ATInterface, ATCommandRunner
from core.modem_detect import ModemDetector

log = get_logger("modem-terminal")
router = APIRouter()

# Global AT interface
_at_interface: Optional[ATInterface] = None
_at_runner: Optional[ATCommandRunner] = None
_detector: Optional[ModemDetector] = None


def get_detector() -> ModemDetector:
    global _detector
    if _detector is None:
        _detector = ModemDetector()
    return _detector


async def get_at_interface() -> ATInterface:
    """Get or create AT interface."""
    global _at_interface

    if _at_interface is None:
        detector = get_detector()
        at_port = await detector.find_at_port()

        if at_port:
            _at_interface = ATInterface(port=at_port)
        else:
            _at_interface = ATInterface()

    return _at_interface


def get_at_runner() -> ATCommandRunner:
    """Get AT command runner (subprocess fallback)."""
    global _at_runner
    if _at_runner is None:
        _at_runner = ATCommandRunner()
    return _at_runner


# === Request Models ===

class ATCommandRequest(BaseModel):
    command: str
    timeout: float = 5.0


# === REST Endpoint (Fallback) ===

@router.post("/at/command")
async def at_command(req: ATCommandRequest, user=Depends(require_jwt)):
    """Send a single AT command (REST fallback for non-WebSocket clients)."""
    command = req.command.strip()

    if not command:
        raise HTTPException(400, "Empty command")

    # Security: block dangerous commands
    dangerous = ["AT+CFUN=0", "AT+CFUN=4", "AT+QPOWD", "AT&F"]
    if any(d in command.upper() for d in dangerous):
        raise HTTPException(403, "Command blocked for safety")

    log.info("AT command: %s", command)

    # Try pyserial interface first, fall back to subprocess
    try:
        at = await get_at_interface()
        if at.connected or await at.connect():
            result = await at.send_command(command, timeout=req.timeout)
            return result
    except Exception as e:
        log.debug("AT interface failed, using subprocess: %s", e)

    # Fallback to subprocess runner
    runner = get_at_runner()
    result = await runner.run(command, timeout=int(req.timeout))
    return result


# === WebSocket Console ===

class WebSocketConnection:
    """Manages a WebSocket connection for AT terminal."""

    def __init__(self, websocket: WebSocket):
        self.websocket = websocket
        self.at_interface: Optional[ATInterface] = None
        self._running = False

    async def connect(self):
        """Accept WebSocket and initialize AT interface."""
        await self.websocket.accept()

        try:
            at = await get_at_interface()
            if await at.connect():
                self.at_interface = at
                await self.send({"type": "status", "connected": True, "port": at.port})
            else:
                await self.send({
                    "type": "error",
                    "message": f"Failed to connect to AT port: {at.port}"
                })
        except Exception as e:
            await self.send({"type": "error", "message": str(e)})

    async def send(self, data: Dict[str, Any]):
        """Send JSON message to client."""
        await self.websocket.send_text(json.dumps(data))

    async def handle_message(self, message: str):
        """Handle incoming message from client."""
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            # Treat as raw AT command
            data = {"command": message}

        msg_type = data.get("type", "command")

        if msg_type == "command":
            command = data.get("command", "").strip()
            if command:
                await self.execute_command(command)

        elif msg_type == "ping":
            await self.send({"type": "pong"})

        elif msg_type == "reconnect":
            if self.at_interface:
                await self.at_interface.disconnect()
                if await self.at_interface.connect():
                    await self.send({"type": "status", "connected": True})
                else:
                    await self.send({"type": "error", "message": "Reconnect failed"})

    async def execute_command(self, command: str):
        """Execute AT command and send response."""
        # Security checks
        dangerous = ["AT+CFUN=0", "AT+CFUN=4", "AT+QPOWD", "AT&F"]
        if any(d in command.upper() for d in dangerous):
            await self.send({
                "type": "error",
                "message": "Command blocked for safety",
                "command": command,
            })
            return

        await self.send({"type": "tx", "data": command})

        if self.at_interface and self.at_interface.connected:
            result = await self.at_interface.send_command(command, timeout=10.0)

            # Send response lines
            response = result.get("response", [])
            for line in response:
                await self.send({"type": "rx", "data": line})

            if not result.get("success"):
                await self.send({
                    "type": "error",
                    "message": result.get("error", "Command failed"),
                })
        else:
            # Use subprocess fallback
            runner = get_at_runner()
            result = await runner.run(command, timeout=10)

            response = result.get("response", [])
            for line in response:
                await self.send({"type": "rx", "data": line})

            if not result.get("success"):
                await self.send({
                    "type": "error",
                    "message": result.get("error", "Command failed"),
                })

    async def run(self):
        """Main WebSocket loop."""
        self._running = True

        try:
            while self._running:
                try:
                    message = await asyncio.wait_for(
                        self.websocket.receive_text(),
                        timeout=60.0
                    )
                    await self.handle_message(message)
                except asyncio.TimeoutError:
                    # Send keepalive ping
                    await self.send({"type": "ping"})

        except WebSocketDisconnect:
            log.info("WebSocket disconnected")
        except Exception as e:
            log.error("WebSocket error: %s", e)
        finally:
            self._running = False

    async def close(self):
        """Close connection."""
        self._running = False
        if self.at_interface:
            await self.at_interface.disconnect()


@router.websocket("/at/console")
async def at_console_websocket(websocket: WebSocket):
    """WebSocket endpoint for interactive AT console."""
    # Note: WebSocket auth should be handled via query param or first message
    # For simplicity, we accept the connection and check auth in first message

    conn = WebSocketConnection(websocket)

    try:
        await conn.connect()
        await conn.run()
    finally:
        await conn.close()


# === Quick AT Commands ===

@router.get("/at/test")
async def at_test(user=Depends(require_jwt)):
    """Quick AT test command."""
    runner = get_at_runner()
    result = await runner.run("AT", timeout=5)
    return {
        "success": result.get("success", False),
        "modem_responds": "OK" in result.get("response", []),
    }


@router.get("/at/info")
async def at_info(user=Depends(require_jwt)):
    """Get modem info via AT commands."""
    runner = get_at_runner()

    info = {}

    # Manufacturer
    result = await runner.run("AT+GMI", timeout=5)
    if result.get("success"):
        info["manufacturer"] = result.get("data", "").strip()

    # Model
    result = await runner.run("AT+GMM", timeout=5)
    if result.get("success"):
        info["model"] = result.get("data", "").strip()

    # Firmware
    result = await runner.run("AT+GMR", timeout=5)
    if result.get("success"):
        info["firmware"] = result.get("data", "").strip()

    # IMEI
    result = await runner.run("AT+GSN", timeout=5)
    if result.get("success"):
        info["imei"] = result.get("data", "").strip()

    return info


@router.get("/at/signal")
async def at_signal(user=Depends(require_jwt)):
    """Get signal quality via AT+CSQ."""
    runner = get_at_runner()
    result = await runner.run("AT+CSQ", timeout=5)

    if result.get("success"):
        data = result.get("data", "")
        # Parse +CSQ: 18,99
        import re
        match = re.search(r"\+CSQ:\s*(\d+),(\d+)", data)
        if match:
            rssi_raw = int(match.group(1))
            ber = int(match.group(2))

            rssi_dbm = None
            if 0 <= rssi_raw <= 31:
                rssi_dbm = 2 * rssi_raw - 113

            return {
                "rssi_raw": rssi_raw,
                "rssi_dbm": rssi_dbm,
                "ber": ber if ber != 99 else None,
                "quality_percent": int(rssi_raw / 31 * 100) if rssi_raw <= 31 else None,
            }

    return {"error": "Failed to get signal"}


@router.get("/at/port")
async def at_port(user=Depends(require_jwt)):
    """Get the detected AT port."""
    detector = get_detector()
    at_port = await detector.find_at_port()

    return {
        "port": at_port,
        "available": at_port is not None,
    }
