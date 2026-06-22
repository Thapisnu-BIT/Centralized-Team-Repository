import os

# --- CONFIGURATION ---
DB_FILE = 'repository.db'
UPLOAD_DIR = 'uploads'
TEMPLATE_DIR = 'templates'

# Global in-memory session tracking mapping
SESSIONS = {}

# Ensure required storage pathways exist locally
os.makedirs(UPLOAD_DIR, exist_ok=True)
