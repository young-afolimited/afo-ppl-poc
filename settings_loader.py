# settings_loader.py
import os, json
from pathlib import Path

def load_settings():
    p = Path("data/settings.json")
    if p.exists():
        with p.open() as f:
            return json.load(f)

    # Fallback to environment variables
    return {
        "aitrios": {
            "portal_endpoint": os.getenv("AITRIOS_PORTAL_ENDPOINT", ""),
            "console_endpoint": os.getenv("AITRIOS_CONSOLE_ENDPOINT", ""),
            "client_id": os.getenv("AITRIOS_CLIENT_ID", ""),
            "client_secret": os.getenv("AITRIOS_CLIENT_SECRET", ""),
        },
        "email": {
            "sender_email": os.getenv("SENDER_EMAIL", ""),
            "receiver_email": os.getenv("RECEIVER_EMAIL", ""),
            "azure_connection_string": os.getenv("AZURE_CONNECTION_STRING", ""),
        },
    }
