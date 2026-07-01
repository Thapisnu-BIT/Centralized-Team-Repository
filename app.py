import os
import re
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import cookies

import config
import database
import routes

database.init_db()


class RepositoryRequestHandler(BaseHTTPRequestHandler):

    ROUTES = {
        'GET': {
            '/': ('handle_dashboard_or_login', True),
            '/download': 'handle_download',
            '/preview': 'handle_preview',
            '/logout': 'handle_logout_route',
            '/api/projects': 'api_list_projects',
            '/api/files': 'api_list_files',
            '/api/files/{id}': 'api_get_file',
            '/api/files/{id}/download': 'api_download_file',
            '/api/files/{id}/preview': 'api_preview_file',
            '/api/users': 'api_list_users',
        },
        'POST': {
            '/login': ('handle_post_login', True),
            '/upload': 'handle_upload',
            '/delete': 'handle_delete',
            '/rename': 'handle_rename',
            '/share': 'handle_share',
            '/revoke': 'handle_revoke',
            '/create-project': 'handle_create_project',
            '/api/auth/login': ('api_login', True),
            '/api/auth/logout': 'api_logout',
            '/api/upload': 'api_upload',
            '/api/files/{id}/share': 'api_share_file',
            '/api/files/{id}/revoke': 'api_revoke_file',
            '/api/files/{id}/rename': 'api_rename_file',
        },
        'DELETE': {
            '/api/files/{id}': 'api_delete_file',
        },
    }

    ROUTE_CACHE = {}

    @classmethod
    def _compile_routes(cls):
        if cls.ROUTE_CACHE:
            return cls.ROUTE_CACHE
        compiled = {}
        for method, routes_dict in cls.ROUTES.items():
            compiled[method] = []
            for pattern, handler in routes_dict.items():
                public = False
                handler_name = handler
                if isinstance(handler, tuple):
                    handler_name, public = handler
                regex = '^' + re.sub(r'\{(\w+)\}', r'(?P<\1>[^/]+)', pattern) + '$'
                compiled[method].append((re.compile(regex), handler_name, public, pattern))
        cls.ROUTE_CACHE = compiled
        return compiled

    def get_session_user(self):
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookie = cookies.SimpleCookie(cookie_header)
            if 'session_id' in cookie:
                session_id = cookie['session_id'].value
                return config.SESSIONS.get(session_id)
        auth = self.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            return config.SESSIONS.get(auth[7:])
        return None

    def redirect(self, location, set_cookie=None):
        self.send_response(303)
        self.send_header('Location', location)
        if set_cookie:
            self.send_header('Set-Cookie', set_cookie)
        self.end_headers()

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def parse_body(self):
        content_length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(content_length) if content_length > 0 else b''
        if not raw:
            return {}
        content_type = self.headers.get('Content-Type', '')
        if 'application/json' in content_type:
            try:
                return json.loads(raw.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {}
        if 'multipart/form-data' in content_type:
            return raw
        try:
            return urllib.parse.parse_qs(raw.decode('utf-8'))
        except UnicodeDecodeError:
            return {}

    def dispatch(self, method):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        routes_table = self._compile_routes()
        username = None

        for regex, handler_name, public, pattern in routes_table.get(method, []):
            m = regex.match(path)
            if not m:
                continue
            path_params = m.groupdict()

            if not public:
                username = self.get_session_user()
                if not username:
                    if path.startswith('/api/'):
                        return self.send_json({'ok': False, 'error': 'Authentication required'}, 401)
                    return self.redirect('/')
            else:
                username = self.get_session_user() or None

            body = None
            if method in ('POST', 'PUT', 'DELETE', 'PATCH'):
                body = self.parse_body()

            handler_fn = getattr(routes, handler_name, None)
            if not handler_fn:
                return self.send_error(404)

            if path.startswith('/api/'):
                return handler_fn(self, body, username, query, **path_params)

            return handler_fn(self, query, username, path, body)

        if path.startswith('/api/'):
            return self.send_json({'ok': False, 'error': 'Endpoint not found'}, 404)
        self.send_error(404)

    def do_GET(self):
        self.dispatch('GET')

    def do_POST(self):
        self.dispatch('POST')

    def do_DELETE(self):
        self.dispatch('DELETE')


if __name__ == '__main__':
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RepositoryRequestHandler)
    print("Serving API and dashboard on http://127.0.0.1:8000 ...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        httpd.server_close()
