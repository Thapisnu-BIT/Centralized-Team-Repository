import os
from config import TEMPLATE_DIR

def format_bytes(size):
    """Converts rough bytes values into human-readable data blocks."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def sanitize_filename(filename):
    """Removes path traversal strings and formatting issues from client file inputs."""
    return os.path.basename(filename).replace("/", "").replace("\\", "").replace('"', '')

def render_template(template_name, context):
    """Reads an HTML template and cleanly injects Python dictionary objects."""
    template_path = os.path.join(TEMPLATE_DIR, template_name)
    with open(template_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
    return html_content.format(**context)
