import sqlite3
from config import DB_FILE

def init_db():
    """Initializes the database schema with multi-project support partition."""
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
        conn.commit()

def get_file_by_id(file_id):
    with sqlite3.connect(DB_FILE) as conn:
        return conn.execute("SELECT filename, filepath, version FROM files WHERE id = ?", (file_id,)).fetchone()

def get_file_metadata(file_id):
    with sqlite3.connect(DB_FILE) as conn:
        return conn.execute("SELECT filename, filepath FROM files WHERE id = ?", (file_id,)).fetchone()

def delete_file_record(file_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()

def fetch_dashboard_data(active_project):
    with sqlite3.connect(DB_FILE) as conn:
        distinct_projects = conn.execute("SELECT DISTINCT project FROM files").fetchall()
        
        latest_files = conn.execute('''
            SELECT id, filename, filepath, filesize, uploaded_by, max(version) as latest_v, upload_time 
            FROM files 
            WHERE project = ?
            GROUP BY filename 
            ORDER BY upload_time DESC
        ''', (active_project,)).fetchall()
        
        all_versions = conn.execute('''
            SELECT id, filename, filepath, filesize, uploaded_by, version, upload_time 
            FROM files 
            WHERE project = ? 
            ORDER BY version DESC
        ''', (active_project,)).fetchall()
        
    return distinct_projects, latest_files, all_versions

def get_next_version(orig_filename, target_project):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.execute("SELECT max(version) FROM files WHERE filename = ? AND project = ?", (orig_filename, target_project))
        row = cursor.fetchone()
        return (row[0] + 1) if (row and row[0] is not None) else 1

def insert_file_record(target_project, orig_filename, unique_name, file_size, username, next_version):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO files (project, filename, filepath, filesize, uploaded_by, version) VALUES (?, ?, ?, ?, ?, ?)",
            (target_project, orig_filename, unique_name, file_size, username, next_version)
        )
        conn.commit()
