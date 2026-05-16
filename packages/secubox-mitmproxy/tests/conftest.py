import os
import sys

ADDONS_DIR = os.path.join(os.path.dirname(__file__), "..", "addons")
sys.path.insert(0, os.path.abspath(ADDONS_DIR))
