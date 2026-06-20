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
ADMIN_PASS = 'Password123'

SESSIONS = {}

os.makedirs(UPLOAD_DIR, exist_ok=True)

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        # Added tracking support partition 'project' 
        conn.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL DEFAULT 'Default',
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
    template_path = os.path.join(TEMPLATE_DIR, template_name)
    with open(template_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
    return html_content.format(**context)


class RepositoryRequestHandler(BaseHTTPRequestHandler):

    def handle_error(self, request, client_address):
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

        # Fetch active context parameters
        active_project = query.get('project', ['Default'])[0]

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
            self.redirect(f'/?project={urllib.parse.quote(active_project)}&error=File+not+found')
            return

        # Route: Delete File
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
                        
                    self.redirect(f'/?project={urllib.parse.quote(active_project)}&msg=Deleted+{urllib.parse.quote(filename)}+successfully')
                    return
            self.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Could+not+delete+file')
            return

        # Route: Dashboard UI
        with sqlite3.connect(DB_FILE) as conn:
            # 1. Fetch available projects dynamically to build sidebar navigation menu maps
            distinct_projects = conn.execute("SELECT DISTINCT project FROM files").fetchall()
            project_pool = {row[0] for row in distinct_projects}
            project_pool.add('Default')
            if active_project not in project_pool:
                project_pool.add(active_project)
                
            # 2. Filter target dashboard rows strictly based on contextual active project partitions
            latest_files = conn.execute('''
                SELECT id, filename, filepath, filesize, uploaded_by, max(version) as latest_v, upload_time 
                FROM files 
                WHERE project = ?
                GROUP BY filename 
                ORDER BY upload_time DESC
            ''', (active_project,)).fetchall()
            
            all_versions = conn.execute(
                "SELECT id, filename, filepath, filesize, uploaded_by, version, upload_time FROM files WHERE project = ? ORDER BY version DESC", 
                (active_project,)
            ).fetchall()
        
        msg = query.get('msg', [None])[0]
        err = query.get('error', [None])[0]
        
        alert_div = ''
        if msg or err:
            color = "#f8d7da" if err else "#d4edda"
            text_color = "#721c24" if err else "#155724"
            alert_div = f'<div style="background: {color}; color: {text_color}; padding: 10px; margin-bottom: 15px; border-radius: 4px;">{err or msg}</div>'

        # Build project list navigation HTML
        project_list_items = ""
        for p_name in sorted(list(project_pool)):
            active_class = "active" if p_name == active_project else ""
            project_list_items += f'<li class="project-item {active_class}"><a href="/?project={urllib.parse.quote(p_name)}">📁 {p_name}</a></li>'

        table_rows = ""
        if not latest_files:
            table_rows = '<tr><td colspan="6" style="text-align: center; color: #777;">No files uploaded in this project space yet.</td></tr>'
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
                                <a href="/download?id={hv[0]}&project={urllib.parse.quote(active_project)}" style="color: #28a745; text-decoration:none; margin-right:15px;">Download v{hv[5]}</a>
                                <a href="/delete?id={hv[0]}&project={urllib.parse.quote(active_project)}" onclick="return confirm('Delete this version completely?');" style="color: #dc3545; text-decoration:none; font-weight:bold;">× Delete This Version</a>
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
                        <a href="/download?id={file_id}&project={urllib.parse.quote(active_project)}" style="background: #28a745; padding: 6px 12px; text-decoration: none; border-radius: 4px; color: white; font-size: 14px; margin-right: 5px;">Download Latest</a>
                        <a href="/delete?id={file_id}&project={urllib.parse.quote(active_project)}" onclick="return confirm('Are you sure you want to delete this file and its history?');" style="background: #dc3545; padding: 6px 12px; text-decoration: none; border-radius: 4px; color: white; font-size: 14px;">Delete File</a>
                    </td>
                </tr>
                {history_rows}"""

        html = render_template('dashboard.html', {
            'username': username,
            'active_project': active_project,
            'project_list_items': project_list_items,
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

        # Route: Create New Project Space
        if path == '/create-project':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            new_p_name = params.get('project_name', ['Default'])[0].strip()
            # Redirect to the project route context space to initialize it cleanly
            self.redirect(f'/?project={urllib.parse.quote(new_p_name)}&msg=Project+{urllib.parse.quote(new_p_name)}+initialized')
            return

        if path == '/upload':
            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' in content_type:
                boundary = content_type.split("boundary=")[1].encode('utf-8')
                content_length = int(self.headers.get('Content-Length', 0))
                
                raw_data = self.rfile.read(content_length)
                parts = raw_data.split(b'--' + boundary)
                
                # Pre-extract target active project field out of multi-part payload block stream 
                target_project = "Default"
                for part in parts:
                    if b'name="active_project"' in part:
                        target_project = part.split(b'\r\n\r\n')[1].strip().decode('utf-8')

                for part in parts:
                    if b'Content-Disposition' in part and b'name="repo_file"' in part:
                        headers_part, file_body = part.split(b'\r\n\r\n', 1)
                        
                        if file_body.endswith(b'\r\n'): file_body = file_body[:-2]
                        if file_body.endswith(b'--'): file_body = file_body[:-2]
                        if file_body.endswith(b'\r\n'): file_body = file_body[:-2]

                        header_str = headers_part.decode('utf-8', errors='ignore')
                        if 'filename="' in header_str:
                            orig_filename = header_str.split('filename="')[1].split('"')[0]
                            if not orig_filename:
                                continue
                                
                            safe_name = sanitize_filename(orig_filename)
                            
                            with sqlite3.connect(DB_FILE) as conn:
                                # Look up the highest existing version number strictly within this project space partition
                                cursor = conn.execute("SELECT max(version) FROM files WHERE filename = ? AND project = ?", (orig_filename, target_project))
                                row = cursor.fetchone()
                                next_version = (row[0] + 1) if (row and row[0] is not None) else 1
                            
                            unique_name = f"{int(time.time())}_v{next_version}_{safe_name}"
                            dest_path = os.path.join(UPLOAD_DIR, unique_name)
                            
                            with open(dest_path, 'wb') as output_file:
                                output_file.write(file_body)
                            
                            file_size = len(file_body)
                            
                            with sqlite3.connect(DB_FILE) as conn:
                                conn.execute(
                                    "INSERT INTO files (project, filename, filepath, filesize, uploaded_by, version) VALUES (?, ?, ?, ?, ?, ?)",
                                    (target_project, orig_filename, unique_name, file_size, username, next_version)
                                )
                                conn.commit()
                                
                            self.redirect(f'/?project={urllib.parse.quote(target_project)}&msg=Uploaded+{urllib.parse.quote(orig_filename)}+(v{next_version})+successfully')
                            return

            self.redirect('/?error=Failed+to+process+upload')


if __name__ == '__main__':
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RepositoryRequestHandler)
    print("Serving Split HTML Multi-Project Repository on http://127.0.0.1:8000 ...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()
