# Centralized Team File Repository

Multi-user file server with versioning, sharing, and a REST API — built with Python's standard library (zero external dependencies).

## Features

- **User auth** — register/login with hashed passwords, session-based
- **Project spaces** — organize files into named projects
- **File versioning** — every upload creates a new version (v1, v2, …)
- **Role-based sharing** — share files as Viewer (read-only) or Editor (modify/delete)
- **File preview** — view text files (.py, .txt, .md, .json, …) in-browser
- **Live search** — filter projects in the sidebar, filter files in the table
- **Dark/light mode** — auto-detects system preference, persists choice
- **Project stats banner** — file count, total size, last activity, shared users
- **Resizable / collapsible sidebar**
- **REST JSON API** — programmatic access to all features

## Quick Start

```bash
python3 app.py
# → http://127.0.0.1:8000
```

Open the URL, create an account, and start uploading.

## Project Structure

```
├── app.py          # HTTP server, route table, auth middleware
├── routes.py       # Route handlers (HTML + JSON API)
├── database.py     # SQLite queries
├── helpers.py      # Template rendering, formatting, escaping
├── config.py       # Paths, session store
├── templates/      # HTML templates (login.html, dashboard.html, preview.html)
├── uploads/        # Stored files
└── repository.db   # SQLite database (auto-created)
```

## Routes

### HTML (dashboard)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard or login page |
| POST | `/login` | Login / register |
| GET | `/logout` | Logout |
| POST | `/upload` | Upload file (multipart) |
| POST | `/delete` | Delete file |
| POST | `/rename` | Rename file |
| POST | `/share` | Share file with user |
| POST | `/revoke` | Revoke file share |
| POST | `/create-project` | Create a new project |
| GET | `/download?id=X` | Download file |
| GET | `/preview?id=X` | Preview text file |

### JSON API

Auth via `Authorization: Bearer <session_id>` header or session cookie.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/login` | Login, returns `token` |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/projects` | List projects |
| GET | `/api/files?project=X` | List files in project |
| GET | `/api/files/{id}` | File metadata |
| GET | `/api/files/{id}/download` | Download file |
| GET | `/api/files/{id}/preview` | Preview text content |
| POST | `/api/upload` | Upload file (multipart) |
| DELETE | `/api/files/{id}` | Delete file |
| POST | `/api/files/{id}/rename` | Rename file |
| POST | `/api/files/{id}/share` | Share file |
| POST | `/api/files/{id}/revoke` | Revoke share |
| GET | `/api/users` | List other users |

All API responses follow the format `{"ok": true, "data": ...}` on success or `{"ok": false, "error": "..."}` on error.

## API Example

```bash
# Login
curl -s http://127.0.0.1:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"secret"}'

# → {"ok": true, "data": {"token": "abc123...", "username": "alice"}}

# List files
curl -s http://127.0.0.1:8000/api/files?project=Default \
  -H 'Authorization: Bearer abc123...'

# → {"ok": true, "data": [{"id": 1, "filename": "notes.txt", ...}]}

# Upload
curl -s http://127.0.0.1:8000/api/upload \
  -H 'Authorization: Bearer abc123...' \
  -F 'repo_file=@notes.txt' \
  -F 'active_project=Default'

# → {"ok": true, "data": {"filename": "notes.txt", "version": 1, ...}}
```

## Dependencies

Zero. Built entirely on Python 3 standard library.

## License

[MIT](LICENSE)
