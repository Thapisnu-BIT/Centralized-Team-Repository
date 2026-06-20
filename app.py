import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import cookies

import config
import database
import routes

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
                return config.SESSIONS.get(session_id)
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

        # Route Interceptor Gateways
        if not username:
            routes.handle_login_route(self, query)
            return

        if path == '/logout':
            routes.handle_logout_route(self)
            return

        active_project = query.get('project', ['Default'])[0]

        if path == '/download':
            routes.handle_download_route(self, query, active_project)
            return

        if path == '/delete':
            routes.handle_delete_route(self, query, active_project)
            return

        routes.handle_dashboard_route(self, query, username, active_project)

    def do_POST(self):
        url_parsed = urllib.parse.urlparse(self.path)
        path = url_parsed.path
        
        if path == '/login':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            routes.handle_post_login(self, params)
            return

        username = self.get_current_user()
        if not username:
            self.redirect('/')
            return

        if path == '/create-project':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            new_p_name = params.get('project_name', ['Default'])[0].strip()
            self.redirect(f'/?project={urllib.parse.quote(new_p_name)}&msg=Project+{urllib.parse.quote(new_p_name)}+initialized')
            return

        if path == '/upload':
            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' in content_type:
                boundary = content_type.split("boundary=")[1].encode('utf-8')
                content_length = int(self.headers.get('Content-Length', 0))
                
                raw_data = self.rfile.read(content_length)
                parts = raw_data.split(b'--' + boundary)
                routes.handle_post_upload(self, parts, username)
                return

            self.redirect('/?error=Failed+to+process+upload')


if __name__ == '__main__':
    # Bootstrap DB schema layer initialization components
    database.init_db()
    
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RepositoryRequestHandler)
    print("Serving Connected Modular Application on http://127.0.0.1:8000 ...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()
