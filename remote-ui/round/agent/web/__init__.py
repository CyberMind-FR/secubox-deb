"""
SecuBox Eye Remote — Web Remote Server
FastAPI-based web server for remote control of Eye Remote device.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from .server import create_app, WebServer

__all__ = ['create_app', 'WebServer']
