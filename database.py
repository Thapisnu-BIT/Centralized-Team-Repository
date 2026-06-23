import sqlite3
import hashlib
import os
from config import DB_FILE

def init_db():
    """Initializes the database schema with explicit privilege levels."""
    with sqlite3.connect(DB_FILE) as conn:
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
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS file_shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                shared_with_user TEXT NOT NULL,
                privilege TEXT NOT NULL DEFAULT 'Viewer', -- 'Viewer' or 'Editor'
                shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
                UNIQUE(file_id, shared_with_user)
            )
        ''')
        conn.commit()

def register_user(username, password):
    username = username.strip()
    if not username or not password:
        return False, "Username and password cannot be empty."
    salt = os.urandom(16).hex()
    p_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, p_hash, salt))
            conn.commit()
        return True, "Success"
    except sqlite3.IntegrityError:
        return False, "Username is already taken."

def verify_user_credentials(username, password):
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        return False
    stored_hash, salt = row
    test_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    import secrets
    return secrets.compare_digest(stored_hash, test_hash)

def share_file_with_user(file_id, target_username, current_user, privilege='Viewer'):
    """Grants custom access permissions targeting another system profile user."""
    target_username = target_username.strip()
    if target_username == current_user:
        return False, "You cannot share a file with yourself."
    if privilege not in ['Viewer', 'Editor']:
        privilege = 'Viewer'
        
    with sqlite3.connect(DB_FILE) as conn:
        user_exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (target_username,)).fetchone()
        if not user_exists:
            return False, f"User '{target_username}' does not exist."
            
        file_ownership = conn.execute("SELECT filename FROM files WHERE id = ? AND uploaded_by = ?", (file_id, current_user)).fetchone()
        if not file_ownership:
            return False, "Access Denied: You do not own this file reference."
            
        filename = file_ownership[0]
        all_file_ids = conn.execute("SELECT id FROM files WHERE filename = ? AND uploaded_by = ?", (filename, current_user)).fetchall()
        
        try:
            for (f_id,) in all_file_ids:
                conn.execute('''
                    INSERT INTO file_shares (file_id, shared_with_user, privilege) 
                    VALUES (?, ?, ?)
                    ON CONFLICT(file_id, shared_with_user) DO UPDATE SET privilege=excluded.privilege
                ''', (f_id, target_username, privilege))
            conn.commit()
            return True, f"Successfully shared '{filename}' with {target_username} as {privilege}."
        except Exception as e:
            return False, f"Database error: {str(e)}"

def check_file_write_access(file_id, username):
    """Validates whether a user can alter or manipulate a specific file record."""
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute('''
            SELECT 1 FROM files WHERE id = ? AND uploaded_by = ?
            UNION
            SELECT 1 FROM file_shares WHERE file_id = ? AND shared_with_user = ? AND privilege = 'Editor'
        ''', (file_id, username, file_id, username)).fetchone()
        return row is not None

def check_file_read_access(file_id, username):
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute('''
            SELECT 1 FROM files WHERE id = ? AND uploaded_by = ? 
            UNION 
            SELECT 1 FROM file_shares WHERE file_id = ? AND shared_with_user = ?
        ''', (file_id, username, file_id, username)).fetchone()
        return row is not None

def fetch_other_users(current_user):
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute("SELECT username FROM users WHERE username != ? ORDER BY username ASC", (current_user,)).fetchall()
        return [row[0] for row in rows]

def fetch_dashboard_data(active_project, username):
    with sqlite3.connect(DB_FILE) as conn:
        distinct_projects = conn.execute('''
            SELECT DISTINCT project FROM files WHERE uploaded_by = ? 
            UNION 
            SELECT DISTINCT f.project FROM files f 
            JOIN file_shares s ON f.id = s.file_id WHERE s.shared_with_user = ?
        ''', (username, username)).fetchall()
        
        latest_files = conn.execute('''
            SELECT f.id, f.filename, f.filepath, f.filesize, f.uploaded_by, max(f.version) as latest_v, f.upload_time,
                   (SELECT s.privilege FROM file_shares s WHERE s.file_id = f.id AND s.shared_with_user = ?) as user_role
            FROM files f
            WHERE (f.uploaded_by = ? OR f.id IN (SELECT file_id FROM file_shares WHERE shared_with_user = ?))
              AND f.project = ?
            GROUP BY f.filename, f.uploaded_by
            ORDER BY f.upload_time DESC
        ''', (username, username, username, active_project)).fetchall()
        
        all_versions = conn.execute('''
            SELECT id, filename, filepath, filesize, uploaded_by, version, upload_time 
            FROM files 
            WHERE (uploaded_by = ? OR id IN (SELECT file_id FROM file_shares WHERE shared_with_user = ?))
              AND project = ?
            ORDER BY version DESC
        ''', (username, username, active_project)).fetchall()
        
    return distinct_projects, latest_files, all_versions

def get_file_by_id(file_id):
    with sqlite3.connect(DB_FILE) as conn:
        return conn.execute("SELECT filename, filepath, version FROM files WHERE id = ?", (file_id,)).fetchone()

def get_file_metadata(file_id):
    with sqlite3.connect(DB_FILE) as conn:
        return conn.execute("SELECT filename, filepath, project FROM files WHERE id = ?", (file_id,)).fetchone()

def delete_file_record(file_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()

def update_filename_history(old_name, new_name, project):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("UPDATE files SET filename = ? WHERE filename = ? AND project = ?", (new_name, old_name, project))
        conn.commit()

def get_next_version(orig_filename, target_project, username):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.execute("SELECT max(version) FROM files WHERE filename = ? AND project = ? AND uploaded_by = ?", (orig_filename, target_project, username))
        row = cursor.fetchone()
        return (row[0] + 1) if (row and row[0] is not None) else 1

def insert_file_record(target_project, orig_filename, unique_name, file_size, username, next_version):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO files (project, filename, filepath, filesize, uploaded_by, version) VALUES (?, ?, ?, ?, ?, ?)", (target_project, orig_filename, unique_name, file_size, username, next_version))
        conn.commit()

def get_shared_users_for_file(file_id):
    """Retrieves a list of users a specific file is shared with, along with their privileges."""
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute("SELECT shared_with_user, privilege FROM file_shares WHERE file_id = ?", (file_id,)).fetchall()
        return rows
