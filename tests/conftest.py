"""Make the project root importable so `crypto`, `scanner`, etc. resolve."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
