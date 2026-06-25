import os
import sys

# Add parent directory to sys.path to ensure 'app' is importable on Vercel
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
