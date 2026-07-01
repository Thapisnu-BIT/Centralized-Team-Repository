import os
from string import Template  # Added for safer HTML interpolation
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

def js_escape(s):
    """Escapes a string for safe embedding in single-quoted JavaScript strings."""
    return s.replace('\\', '\\\\').replace("'", "\\'").replace('\n', '\\n').replace('\r', '\\r')

def time_ago(dt_str):
    """Converts a SQL datetime string like '2026-06-30 12:34:56' into a relative '3 min ago' string."""
    try:
        from datetime import datetime
        dt = datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S')
        now = datetime.now()
        diff = now - dt
        secs = int(diff.total_seconds())
        if secs < 60: return f"{secs}s ago" if secs else "just now"
        mins = secs // 60
        if mins < 60: return f"{mins} min ago" if mins == 1 else f"{mins} mins ago"
        hrs = mins // 60
        if hrs < 24: return f"{hrs} hour ago" if hrs == 1 else f"{hrs} hours ago"
        days = hrs // 24
        if days < 30: return f"{days} day ago" if days == 1 else f"{days} days ago"
        return dt_str
    except:
        return dt_str

def is_text_file(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext in {'.txt','.py','.md','.html','.json','.yaml','.yml','.csv','.log','.js','.css','.xml','.cfg','.ini','.sh','.bat','.env','.sql','.toml','.rb','.php','.pl','.r','.conf','.properties','.cfg'}

def html_encode(s):
    return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

def render_template(template_name, context):
    """Reads an HTML template and cleanly injects Python dictionary objects using $ placeholders."""
    template_path = os.path.join(TEMPLATE_DIR, template_name)
    with open(template_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # Using safe_substitute avoids KeyError breaks from CSS/JS curly brackets
    return Template(html_content).safe_substitute(context)
