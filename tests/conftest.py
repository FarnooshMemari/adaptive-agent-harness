import os
import sys

# Run from the project root so relative paths in config (data/, logs/) resolve.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
