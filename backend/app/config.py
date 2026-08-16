import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = BASE_DIR.parent
FRONTEND_DIR = WORKSPACE_DIR / "frontend"
ENV_FILE = WORKSPACE_DIR / ".env"

# Lightweight .env file parser (works with or without python-dotenv)
if ENV_FILE.exists():
    try:
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip().strip("\"'")
                    if k and k not in os.environ:
                        os.environ[k] = v
    except Exception as e:
        print(f"[CONFIG] Could not load .env file: {e}")

def _safe_int(key: str, default: int) -> int:
    val = os.getenv(key, "").strip()
    if not val:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

# Environment Variables & Configuration
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threat_cache.db")
RATE_LIMIT_CPM = _safe_int("RATE_LIMIT_CPM", 4)
COOLDOWN_WINDOW = _safe_int("COOLDOWN_WINDOW", 60)
HOST = os.getenv("HOST", "0.0.0.0")
PORT = _safe_int("PORT", 8000)

# Check if a real VT API key is set
def is_vt_configured() -> bool:
    return bool(VT_API_KEY and VT_API_KEY != "YOUR_FREE_API_KEY_HERE" and len(VT_API_KEY) > 10)


