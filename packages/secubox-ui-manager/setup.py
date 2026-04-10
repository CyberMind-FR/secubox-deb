#!/usr/bin/env python3
"""Setup script for secubox-ui-manager."""

from setuptools import setup, find_packages

setup(
    name="secubox-ui-manager",
    version="1.0.0",
    author="Gerald KERMA",
    author_email="devel@cybermind.fr",
    description="SecuBox Unified UI Manager",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://secubox.in",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[],
    extras_require={
        "textual": ["textual>=0.40.0"],
    },
    entry_points={
        "console_scripts": [
            "secubox-ui-manager=ui.manager:run",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: Other/Proprietary License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Systems Administration",
    ],
)
