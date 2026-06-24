import os
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import cookies

import config
import database
import routes

# Initialize database schemas automatically upon server booting sequence
database.init_db()

class RepositoryRequestHandler(BaseHTTPRequestHandler):
    
    def get_session_user(self):
        """Extracts and verifies the session token cookie from inbound requests."""
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookie = cookies.SimpleCookie(cookie_header)
            if 'session_id' in cookie:
                session_id = cookie['session_id'].value
                return config.SESSIONS.get(session_id)
        return None

    def redirect(self, location, set_cookie=None):
        """Sends a clean 303 browser redirection header."""
        self.send_response(303)
        self.send_header('Location', location)
        if set_cookie:
            self.send_header('Set-Cookie', set_cookie)
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)
        
        # Enforce authentication walls across all pages except the primary login screen
        username = self.get_session_user()
        if not username:
            if path == '/':
                routes.handle_login_route(self, query)
                return
            else:
                self.redirect('/')
                return
                
        # If logged-in user hits root domain, redirect into active workspace dashboards
        if path == '/':
            active_project = query.get('project', ['Default'])[0]
            routes.handle_dashboard_route(self, query, username, active_project)
        elif path == '/download':
            active_project = query.get('project', ['Default'])[0]
            routes.handle_download_route(self, query, active_project, username)
        elif path == '/delete':
            active_project = query.get('project', ['Default'])[0]
            routes.handle_delete_route(self, query, active_project, username)
        elif path == '/rename':
            active_project = query.get('project', ['Default'])[0]
            routes.handle_rename_route(self, query, active_project, username)
        elif path == '/share':
            # Added target route mapping for multi-user resource assignment
            active_project = query.get('project', ['Default'])[0]
            routes.handle_share_route(self, query, username, active_project)
        elif path == '/revoke':
            active_project = query.get('project', ['Default'])[0]
            routes.handle_revoke_route(self, query, username, active_project)
        elif path == '/logout':
            routes.handle_logout_route(self)
        else:
            self.send_error(404, "Endpoint Not Found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b''

        # Handle the login/registration page submission before session checks
        if path == '/login':
            params = urllib.parse.parse_qs(post_data.decode('utf-8'))
            routes.handle_post_login(self, params)
            return

        # Secure check for protected file operations
        username = self.get_session_user()
        if not username:
            self.redirect('/')
            return

        if path == '/upload':
            # Extract standard boundary delimiters for multi-part encoding formats
            content_type = self.headers.get('Content-Type', '')
            if 'boundary=' in content_type:
                boundary = content_type.split('boundary=')[1].encode('utf-8')
                parts = post_data.split(b'--' + boundary)
                routes.handle_post_upload(self, parts, username)
                return
            self.redirect('/?error=Malformed+form+data')
            
        elif path == '/create-project':
            params = urllib.parse.parse_qs(post_data.decode('utf-8'))
            new_project = params.get('project_name', ['Default'])[0].strip()
            if new_project:
                self.redirect(f'/?project={urllib.parse.quote(new_project)}&msg=Project+Workspace+Ready')
            else:
                self.redirect('/?error=Invalid+project+name')
        else:
            self.send_error(404, "Endpoint Not Found")

if __name__ == '__main__':
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RepositoryRequestHandler)
    print("Serving secure distributed workspace on http://127.0.0.1:8000 ...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down file repository engine server.")
        httpd.server_close()
