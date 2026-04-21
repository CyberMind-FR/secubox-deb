"""
SecuBox Eye Gateway — Setup configuration.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""

from setuptools import setup, find_packages

setup(
    name="secubox-eye-gateway",
    version="1.0.0",
    description="Development gateway for SecuBox Eye Remote",
    author="Gerald Kerma",
    author_email="gandalf@gk2.net",
    url="https://cybermind.fr",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "click>=8.0.0",
    ],
    entry_points={
        "console_scripts": [
            "secubox-eye-gateway=gateway.main:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Testing",
        "Topic :: System :: Emulators",
    ],
)
