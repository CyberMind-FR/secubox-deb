"""Pytest configuration for Eye Remote tests."""
import sys
from pathlib import Path

# Add the round directory to the path so 'agent' module can be imported
sys.path.insert(0, str(Path(__file__).parent))
