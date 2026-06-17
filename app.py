import os
import sqlite3
import time
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import cookies
import urllib.parse

# --- CONFIGURATION ---
DB_FILE = 'repository.db'
UPLOAD_DIR = 'uploads'
TEMPLATE_DIR = 'templates'
ADMIN_USER = 'team_admin'
ADMIN_PASS = 'Password123'  # Change this for security!

SESSIONS = {}

os.makedirs(UPLOAD_DIR, exist_ok=True)

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                filesize INTEGER NOT NULL,
                uploaded_by TEXT NOT NULL,
                version INTEGER DEFAULT 1,
                upload_time DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

init_db()

def format_bytes(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def sanitize_filename(filename):
    return os.path.basename(filename).replace("/", "").replace("\\", "").replace('"', '')

def render_template(template_name, context):
    """Reads an HTML file from the templates folder and interpolates data."""
    template_path = os.path.join(TEMPLATE_DIR, template_name)
    with open(template_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
    return html_content.format(**context)


class RepositoryRequestHandler(BaseHTTPRequestHandler):

    def handle_error(self, request, client_address):
        """Silences BrokenPipe errors gracefully when users cancel transfers."""
        import sys
        exc_type, exc_value, _ = sys.exc_info()
        if exc_type is BrokenPipeError or (exc_value and '[Errno 32]' in str(exc_value)):
            return 
        super().handle_error(request, client_address)

    def get_current_user(self):
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookie = cookies.SimpleCookie(cookie_header)
            if 'session_id' in cookie:
                session_id = cookie['session_id'].value
                return SESSIONS.get(session_id)
        return None

    def redirect(self, location, set_cookie=None):
        self.send_response(303)
        self.send_header('Location', location)
        if set_cookie:
            self.send_header('Set-Cookie', set_cookie)
        self.end_headers()

    def do_GET(self):
        url_parsed = urllib.parse.urlparse(self.path)
        path = url_parsed.path
        query = urllib.parse.parse_qs(url_parsed.query)
        
        username = self.get_current_user()

        # Route: Login Screen
        if not username:
            error_msg = query.get('error', [None])[0]
            error_div = f'<div style="color: #dc3545; font-size: 14px; margin-bottom: 10px;">{error_msg}</div>' if error_msg else ''
            html = render_template('login.html', {'error_div': error_div})
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
            return

        # Route: Logout
        if path == '/logout':
            cookie_header = self.headers.get('Cookie')
            if cookie_header:
                cookie = cookies.SimpleCookie(cookie_header)
                if 'session_id' in cookie:
                    SESSIONS.pop(cookie['session_id'].value, None)
            self.redirect('/?msg=Logged+out')
            return

        # Route: Download
        if path == '/download':
            file_id = query.get('id', [None])[0]
            if file_id:
                with sqlite3.connect(DB_FILE) as conn:
                    file_data = conn.execute("SELECT filename, filepath, version FROM files WHERE id = ?", (file_id,)).fetchone()
                
                if file_data:
                    filename, unique_name, version = file_data
                    full_path = os.path.join(UPLOAD_DIR, unique_name)
                    if os.path.exists(full_path):
                        name_parts = os.path.splitext(filename)
                        download_display_name = f"{name_parts[0]}_v{version}{name_parts[1]}"

                        self.send_response(200)
                        self.send_header('Content-Type', 'application/octet-stream')
                        self.send_header('Content-Disposition', f'attachment; filename="{download_display_name}"')
                        self.send_header('Content-Length', str(os.path.getsize(full_path)))
                        self.end_headers()
                        
                        try:
                            with open(full_path, 'rb') as f:
                                self.wfile.write(f.read())
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        return
            self.redirect('/?error=File+not+found')
            return

        # Route: Delete File (or specific sub-version)
        if path == '/delete':
            file_id = query.get('id', [None])[0]
            if file_id:
                with sqlite3.connect(DB_FILE) as conn:
                    file_data = conn.execute("SELECT filename, filepath FROM files WHERE id = ?", (file_id,)).fetchone()
                
                if file_data:
                    filename, unique_name = file_data
                    full_path = os.path.join(UPLOAD_DIR, unique_name)
                    
                    if os.path.exists(full_path):
                        os.remove(full_path)
                    
                    with sqlite3.connect(DB_FILE) as conn:
                        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
                        conn.commit()
                        
                    self.redirect(f'/?msg=Deleted+{urllib.parse.quote(filename)}+successfully')
                    return
            self.redirect('/?error=Could+not+delete+file')
            return

        # Route: Dashboard UI
        with sqlite3.connect(DB_FILE) as conn:
            latest_files = conn.execute('''
                SELECT id, filename, filepath, filesize, uploaded_by, max(version) as latest_v, upload_time 
                FROM files 
                GROUP BY filename 
                ORDER BY upload_time DESC
            ''').fetchall()
            all_versions = conn.execute("SELECT id, filename, filepath, filesize, uploaded_by, version, upload_time FROM files ORDER BY version DESC").fetchall()
        
        msg = query.get('msg', [None])[0]
        err = query.get('error', [None])[0]
        
        alert_div = ''
        if msg or err:
            color = "#f8d7da" if err else "#d4edda"
            text_color = "#721c24" if err else "#155724"
            alert_div = f'<div style="background: {color}; color: {text_color}; padding: 10px; margin-bottom: 15px; border-radius: 4px;">{err or msg}</div>'

        table_rows = ""
        if not latest_files:
            table_rows = '<tr><td colspan="6" style="text-align: center; color: #777;">No files uploaded yet.</td></tr>'
        else:
            for f in latest_files:
                file_id, filename, filepath, filesize, uploaded_by, version, upload_time = f
                history_rows = ""
                history_list = [v for v in all_versions if v[1] == filename and v[5] < version]
                
                if history_list:
                    history_rows += f'<tr class="history-row-{file_id}" style="display:none; background:#fdfdfd;"><td colspan="6" style="padding-left: 30px; font-size:13px; color:#555;"><strong>Version History:</strong><table style="width:100%; margin-top:5px; border:1px solid #eee;">'
                    for hv in history_list:
                        history_rows += f"""
                        <tr style="background:#f9f9f9;">
                            <td>v{hv[5]}</td>
                            <td>{format_bytes(hv[3])}</td>
                            <td>Uploaded by {hv[4]}</td>
                            <td>{hv[6]}</td>
                            <td style="text-align:right;">
                                <a href="/download?id={hv[0]}" style="color: #28a745; text-decoration:none; margin-right:15px;">Download v{hv[5]}</a>
                                <a href="/delete?id={hv[0]}" onclick="return confirm('Delete this version completely?');" style="color: #dc3545; text-decoration:none; font-weight:bold;">× Delete This Version</a>
                            </td>
                        </tr>"""
                    history_rows += "</table></td></tr>"

                toggle_btn = ""
                if history_list:
                    toggle_btn = f"""<button onclick="var el=document.getElementsByClassName('history-row-{file_id}'); for(var i=0;i<el.length;i++) {{ el[i].style.display = el[i].style.display==='none'?'table-row':'none'; }}" style="margin-left:8px; background:none; border:none; color:#007bff; cursor:pointer; font-size:12px; text-decoration:underline;">🕒 View History ({len(history_list)})</button>"""

                table_rows += f"""
                <tr style="background:#fff; font-weight: 500;">
                    <td><strong>{filename}</strong>{toggle_btn}</td>
                    <td><span style="background:#e2e8f0; padding:2px 6px; border-radius:4px; font-size:12px;">v{version}</span></td>
                    <td>{format_bytes(filesize)}</td>
                    <td>{uploaded_by}</td>
                    <td>{upload_time}</td>
                    <td style="text-align:right;">
                        <a href="/download?id={file_id}" style="background: #28a745; padding: 6px 12px; text-decoration: none; border-radius: 4px; color: white; font-size: 14px; margin-right: 5px;">Download Latest</a>
                        <a href="/delete?id={file_id}" onclick="return confirm('Are you sure you want to delete this file and its history?');" style="background: #dc3545; padding: 6px 12px; text-decoration: none; border-radius: 4px; color: white; font-size: 14px;">Delete File</a>
                    </td>
                </tr>
                {history_rows}"""

        html = render_template('dashboard.html', {
            'username': username,
            'alert_div': alert_div,
            'table_rows': table_rows
        })

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def do_POST(self):
        url_parsed = urllib.parse.urlparse(self.path)
        path = url_parsed.path
        
        if path == '/login':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            
            if username == ADMIN_USER and password == ADMIN_PASS:
                session_id = secrets.token_hex(16)
                SESSIONS[session_id] = username
                cookie = cookies.SimpleCookie()
                cookie['session_id'] = session_id
                cookie['session_id']['path'] = '/'
                cookie['session_id']['httponly'] = True
                self.redirect('/', set_cookie=cookie.output(header=''))
            else:
                self.redirect('/?error=Invalid+credentials')
            return

        username = self.get_current_user()
        if not username:
            self.redirect('/')
            return

        if path == '/upload':
            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' in content_type:
                boundary = content_type.split("boundary=")[1].encode('utf-8')
                content_length = int(self.headers.get('Content-Length', 0))
                
                raw_data = self.rfile.read(content_length)
                parts = raw_data.split(b'--' + boundary)
                
                for part in parts:
                    if b'Content-Disposition' in part and b'name="repo_file"' in part:
                        headers_part, file_body = part.split(b'\r\n\r\n', 1)
                        
                        if file_body.endswith(b'\r\n'):
                            file_body = file_body[:-2]
                        if file_body.endswith(b'--'):
                            file_body = file_body[:-2]
                            if file_body.endswith(b'\r\n'):
                                file_body = file_body[:-2]

                        header_str = headers_part.decode('utf-8', errors='ignore')
                        if 'filename="' in header_str:
                            orig_filename = header_str.split('filename="')[1].split('"')[0]
                            if not orig_filename:
                                continue
                                
                            safe_name = sanitize_filename(orig_filename)
                            
                            with sqlite3.connect(DB_FILE) as conn:
                                cursor = conn.execute("SELECT max(version) FROM files WHERE filename = ?", (orig_filename,))
                                row = cursor.fetchone()
                                next_version = (row[0] + 1) if (row and row[0] is not None) else 1
                            
                            unique_name = f"{int(time.time())}_v{next_version}_{safe_name}"
                            dest_path = os.path.join(UPLOAD_DIR, unique_name)
                            
                            with open(dest_path, 'wb') as output_file:
                                output_file.write(file_body)
                            
                            file_size = len(file_body)
                            
                            with sqlite3.connect(DB_FILE) as conn:
                                conn.execute(
                                    "INSERT INTO files (filename, filepath, filesize, uploaded_by, version) VALUES (?, ?, ?, ?, ?)",
                                    (orig_filename, unique_name, file_size, username, next_version)
                                )
                                conn.commit()
                                
                            self.redirect(f'/?msg=Uploaded+{urllib.parse.quote(orig_filename)}+(v{next_version})+successfully')
                            return

            self.redirect('/?error=Failed+to+process+upload')

if __name__ == '__main__':
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RepositoryRequestHandler)
    print("Serving Split HTML Repository on http://127.0.0.1:8000 ...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()
