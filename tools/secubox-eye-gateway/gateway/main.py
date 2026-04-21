"""
SecuBox Eye Gateway — CLI entry point.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""

import click
import uvicorn

from .emulator import SecuBoxEmulator
from .server import app, set_emulator
from .profiles import PROFILES


@click.command()
@click.option(
    "--port",
    "-p",
    default=8000,
    type=int,
    help="Port to listen on (default: 8000)"
)
@click.option(
    "--host",
    "-h",
    default="0.0.0.0",
    help="Host to bind to (default: 0.0.0.0)"
)
@click.option(
    "--name",
    "-n",
    default="secubox-dev",
    help="Device name for emulation (default: secubox-dev)"
)
@click.option(
    "--profile",
    "-P",
    type=click.Choice(list(PROFILES.keys())),
    default="normal",
    help="Emulation profile: idle, normal, busy, stressed (default: normal)"
)
def main(port: int, host: str, name: str, profile: str) -> None:
    """SecuBox Eye Gateway — Development tool for Eye Remote.

    Starts an emulated SecuBox device server for testing Eye Remote
    without a physical device.

    Examples:

        # Start with default settings
        secubox-eye-gateway

        # Start stressed profile on custom port
        secubox-eye-gateway --profile stressed --port 8080

        # Custom device name
        secubox-eye-gateway --name my-secubox --profile busy
    """
    click.echo(f"SecuBox Eye Gateway v1.0.0")
    click.echo(f"----------------------------")
    click.echo(f"Device name: {name}")
    click.echo(f"Profile:     {profile}")
    click.echo(f"Listening:   http://{host}:{port}")
    click.echo(f"API docs:    http://{host}:{port}/docs")
    click.echo(f"----------------------------")
    click.echo()

    # Create and configure emulator
    emulator = SecuBoxEmulator(name=name, profile=profile)
    set_emulator(emulator)

    click.echo(f"Emulator initialized with device ID: {emulator.device_id}")
    click.echo(f"Starting server...\n")

    # Run uvicorn server
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
