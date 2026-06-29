# Ensures `from api import mesh` resolves from the package root during tests.
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
