#!/usr/bin/env python3
"""
SecuBox Eye Remote - Setup Wizard API Routes

FastAPI routes for the self-setup portal.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from ...api.setup import (
    get_setup_wizard,
    SetupStep,
    SetupStatus,
    StepStatus,
)


router = APIRouter(prefix="/setup", tags=["setup"])


# Request/Response models
class SetupStatusResponse(BaseModel):
    """Setup wizard status response."""
    status: str
    current_step: int
    current_step_name: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    secubox_detected: bool
    progress_percent: int


class StepInfoResponse(BaseModel):
    """Step information response."""
    step: int
    step_name: str
    status: str
    title: str
    description: str
    data: Dict[str, Any] = {}
    errors: List[str] = []


class ProgressResponse(BaseModel):
    """Progress information response."""
    completed_steps: int
    total_steps: int
    progress_percent: int
    current_step: int
    current_step_name: str


class SecuBoxInfoResponse(BaseModel):
    """SecuBox detection response."""
    detected: bool
    hostname: str = ""
    model: str = ""
    version: str = ""
    ip_address: str = ""
    connection_type: str = ""
    uptime: int = 0


class NetworkConfigRequest(BaseModel):
    """Network configuration request."""
    wan_interface: str = "eth0"
    wan_dhcp: bool = True
    wan_ip: Optional[str] = None
    wan_netmask: Optional[str] = None
    wan_gateway: Optional[str] = None
    wan_dns: Optional[List[str]] = None
    lan_interface: str = "eth1"
    lan_ip: str = "192.168.1.1"
    lan_netmask: str = "255.255.255.0"
    lan_dhcp_enabled: bool = True
    lan_dhcp_start: str = "192.168.1.100"
    lan_dhcp_end: str = "192.168.1.200"


class SecurityConfigRequest(BaseModel):
    """Security configuration request."""
    admin_password: Optional[str] = None
    generate_tls: bool = True
    domain: str = "secubox.local"
    install_ssh_key: Optional[str] = None


class ServicesConfigRequest(BaseModel):
    """Services configuration request."""
    crowdsec: bool = True
    wireguard: bool = True
    firewall: bool = True
    dpi: bool = False
    dns_filtering: bool = True
    ids: bool = False


class MeshConfigRequest(BaseModel):
    """Mesh configuration request."""
    mode: str = "standalone"  # "standalone", "join", "create"
    mirrornet_peer_url: Optional[str] = None
    wireguard_peer_pubkey: Optional[str] = None


class CompleteRequest(BaseModel):
    """Setup completion request."""
    reboot: bool = False


class ActionResponse(BaseModel):
    """Generic action response."""
    success: bool
    message: str
    step: Optional[int] = None
    step_name: Optional[str] = None


class VerifyResponse(BaseModel):
    """Verification results response."""
    network: bool
    api: bool
    services: Dict[str, bool]
    errors: List[str] = []


# Setup endpoints
@router.get("/status", response_model=SetupStatusResponse)
async def get_status():
    """Get current setup wizard status."""
    wizard = get_setup_wizard()
    state = wizard.state
    progress = wizard.get_progress()

    return SetupStatusResponse(
        status=state.status.value,
        current_step=state.current_step.value,
        current_step_name=state.current_step.name,
        started_at=state.started_at.isoformat() if state.started_at else None,
        completed_at=state.completed_at.isoformat() if state.completed_at else None,
        secubox_detected=state.secubox_info.detected,
        progress_percent=progress["progress_percent"],
    )


@router.post("/start", response_model=ActionResponse)
async def start_setup():
    """Start the setup wizard."""
    wizard = get_setup_wizard()

    if wizard.is_complete:
        raise HTTPException(
            status_code=400,
            detail="Setup already completed"
        )

    await wizard.start()

    return ActionResponse(
        success=True,
        message="Setup wizard started",
        step=wizard.current_step.value,
        step_name=wizard.current_step.name,
    )


@router.get("/progress", response_model=ProgressResponse)
async def get_progress():
    """Get setup progress information."""
    wizard = get_setup_wizard()
    progress = wizard.get_progress()

    return ProgressResponse(**progress)


@router.get("/step/{step_num}", response_model=StepInfoResponse)
async def get_step(step_num: int):
    """Get information about a specific step."""
    if step_num < 0 or step_num > 6:
        raise HTTPException(status_code=400, detail="Invalid step number")

    wizard = get_setup_wizard()
    step = SetupStep(step_num)
    step_data = wizard.get_step_info(step)

    return StepInfoResponse(
        step=step_data.step.value,
        step_name=step_data.step.name,
        status=step_data.status.value,
        title=step_data.title,
        description=step_data.description,
        data=step_data.data,
        errors=step_data.errors,
    )


@router.post("/next", response_model=ActionResponse)
async def next_step():
    """Move to next step."""
    wizard = get_setup_wizard()
    step_data = await wizard.next_step()

    if step_data:
        return ActionResponse(
            success=True,
            message=f"Moved to step {step_data.step.name}",
            step=step_data.step.value,
            step_name=step_data.step.name,
        )
    else:
        return ActionResponse(
            success=False,
            message="Already at final step",
        )


@router.post("/back", response_model=ActionResponse)
async def previous_step():
    """Move to previous step."""
    wizard = get_setup_wizard()
    step_data = await wizard.previous_step()

    if step_data:
        return ActionResponse(
            success=True,
            message=f"Moved back to step {step_data.step.name}",
            step=step_data.step.value,
            step_name=step_data.step.name,
        )
    else:
        return ActionResponse(
            success=False,
            message="Already at first step",
        )


@router.post("/skip", response_model=ActionResponse)
async def skip_step():
    """Skip current step (where allowed)."""
    wizard = get_setup_wizard()
    step_data = await wizard.skip_step()

    if step_data:
        return ActionResponse(
            success=True,
            message=f"Skipped to step {step_data.step.name}",
            step=step_data.step.value,
            step_name=step_data.step.name,
        )
    else:
        return ActionResponse(
            success=False,
            message="Cannot skip this step",
        )


@router.get("/detect", response_model=SecuBoxInfoResponse)
async def detect_secubox():
    """Detect connected SecuBox."""
    wizard = get_setup_wizard()
    info = await wizard.detect_secubox()

    return SecuBoxInfoResponse(
        detected=info.detected,
        hostname=info.hostname,
        model=info.model,
        version=info.version,
        ip_address=info.ip_address,
        connection_type=info.connection_type,
        uptime=info.uptime,
    )


@router.post("/network", response_model=ActionResponse)
async def configure_network(config: NetworkConfigRequest):
    """Apply network configuration."""
    wizard = get_setup_wizard()

    success = await wizard.apply_network_config(config.model_dump())

    if success:
        return ActionResponse(
            success=True,
            message="Network configuration applied",
        )
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to apply network configuration"
        )


@router.post("/security", response_model=ActionResponse)
async def configure_security(config: SecurityConfigRequest):
    """Apply security configuration."""
    wizard = get_setup_wizard()

    success = await wizard.apply_security_config(config.model_dump())

    if success:
        return ActionResponse(
            success=True,
            message="Security configuration applied",
        )
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to apply security configuration"
        )


@router.post("/services", response_model=ActionResponse)
async def configure_services(config: ServicesConfigRequest):
    """Apply services configuration."""
    wizard = get_setup_wizard()

    success = await wizard.apply_services_config(config.model_dump())

    if success:
        return ActionResponse(
            success=True,
            message="Services configuration applied",
        )
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to apply services configuration"
        )


@router.post("/mesh", response_model=ActionResponse)
async def configure_mesh(config: MeshConfigRequest):
    """Apply mesh network configuration."""
    wizard = get_setup_wizard()

    success = await wizard.apply_mesh_config(config.model_dump())

    if success:
        return ActionResponse(
            success=True,
            message="Mesh configuration applied",
        )
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to apply mesh configuration"
        )


@router.post("/verify", response_model=VerifyResponse)
async def verify_configuration():
    """Verify the configuration."""
    wizard = get_setup_wizard()
    results = await wizard.verify_configuration()

    return VerifyResponse(
        network=results.get("network", False),
        api=results.get("api", False),
        services=results.get("services", {}),
        errors=results.get("errors", []),
    )


@router.post("/complete", response_model=ActionResponse)
async def complete_setup(request: CompleteRequest):
    """Complete the setup wizard."""
    wizard = get_setup_wizard()

    success = await wizard.complete_setup(reboot=request.reboot)

    if success:
        message = "Setup completed"
        if request.reboot:
            message += " - SecuBox will reboot"
        return ActionResponse(
            success=True,
            message=message,
        )
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to complete setup"
        )


@router.post("/cancel", response_model=ActionResponse)
async def cancel_setup():
    """Cancel the setup wizard."""
    wizard = get_setup_wizard()

    await wizard.cancel_setup()

    return ActionResponse(
        success=True,
        message="Setup wizard cancelled",
    )


@router.get("/state")
async def get_full_state():
    """Get complete setup state (debug endpoint)."""
    wizard = get_setup_wizard()
    return wizard.state.to_dict()
