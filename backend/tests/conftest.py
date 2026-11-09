import sys
import os

# Add backend directory to sys.path so apiguard is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
