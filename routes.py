import os
import time
import urllib.parse
from http import cookies
import secrets

import config
import database
import helpers

def handle_login_route(handler, query):
    error_msg = query.get('error', [None])[0]
    msg = query.get('msg', [None])[0]
    alert_div = ''
    if error_msg:
        alert_div = f'<div style="color: #dc3545; font-size: 14px; margin-bottom: 15px; text-align:center;">{error_msg}</div>'
    elif msg:
        alert_div = f'<div style="color: #155724; font-size: 14px; margin-bottom: 15px; text-align:center;">{msg}</div>'
    html = helpers.render_template('login.html', {'error_div': alert_div})
    handler.send_response(200)
    handler.send_header('Content-type', 'text/html; charset=utf-8')
    handler.end_headers()
    handler.wfile.write(html.encode('utf-8'))

def handle_logout_route(handler):
    cookie_header = handler.headers.get('Cookie')
    if cookie_header:
        cookie = cookies.SimpleCookie(cookie_header)
        if 'session_id' in cookie:
            config.SESSIONS.pop(cookie['session_id'].value, None)
    handler.redirect('/?msg=Logged+out')

def handle_post_login(handler, params):
    username = params.get('username', [''])[0].strip()
    password = params.get('password', [''])[0]
    action = params.get('action', ['login'])[0]
    if action == 'register':
        success, message = database.register_user(username, password)
        if success:
            handler.redirect(f'/?msg={urllib.parse.quote("Account created! Please sign in.")}')
        else:
            handler.redirect(f'/?error={urllib.parse.quote(message)}')
        return
    if database.verify_user_credentials(username, password):
        session_id = secrets.token_hex(16)
        config.SESSIONS[session_id] = username
        cookie = cookies.SimpleCookie()
        cookie['session_id'] = session_id
        cookie['session_id']['path'] = '/'
        cookie['session_id']['httponly'] = True
        handler.redirect('/', set_cookie=cookie.output(header=''))
    else:
        handler.redirect('/?error=Invalid+username+or+password')

def handle_share_route(handler, query, username, active_project):
    """Processes access assignments targeting other authenticated accounts."""
    file_id = query.get('id', [None])[0]
    target_user = query.get('with', [''])[0].strip()
    
    if file_id and target_user:
        success, message = database.share_file_with_user(file_id, target_user, username)
        if success:
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&msg={urllib.parse.quote(message)}')
            return
        else:
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error={urllib.parse.quote(message)}')
            return
            
    handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Invalid+Share+Parameters')

def handle_download_route(handler, query, active_project, username):
    file_id = query.get('id', [None])[0]
    if file_id:
        # Enforce multi-user read security clearance
        if not database.check_file_read_access(file_id, username):
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Access+Denied+to+Target+File')
            return
            
        file_data = database.get_file_by_id(file_id)
        if file_data:
            filename, unique_name, version = file_data
            full_path = os.path.join(config.UPLOAD_DIR, unique_name)
            if os.path.exists(full_path):
                name_parts = os.path.splitext(filename)
                download_display_name = f"{name_parts[0]}_v{version}{name_parts[1]}"
                handler.send_response(200)
                handler.send_header('Content-Type', 'application/octet-stream')
                handler.send_header('Content-Disposition', f'attachment; filename="{download_display_name}"')
                handler.send_header('Content-Length', str(os.path.getsize(full_path)))
                handler.end_headers()
                try:
                    with open(full_path, 'rb') as f:
                        handler.wfile.write(f.read())
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
    handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=File+not+found')

def handle_delete_route(handler, query, active_project, username):
    file_id = query.get('id', [None])[0]
    if file_id:
        file_data = database.get_file_metadata(file_id)
        if file_data:
            filename, unique_name, project = file_data
            
            # Restrict destructive operations solely to owners
            if file_data[2] != username:
                # Fallback safeguard double-check tracking query
                with sqlite3_connect_owner_test(file_id, username) as is_owner:
                    if not is_owner:
                        handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Only+file+owners+can+delete+assets')
                        return

            full_path = os.path.join(config.UPLOAD_DIR, unique_name)
            if os.path.exists(full_path):
                os.remove(full_path)
            database.delete_file_record(file_id)
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&msg=Deleted+{urllib.parse.quote(filename)}+successfully')
            return
    handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Could+not+delete+file')

def sqlite3_connect_owner_test(file_id, username):
    import sqlite3
    with sqlite3.connect(config.DB_FILE) as conn:
        res = conn.execute("SELECT 1 FROM files WHERE id = ? AND uploaded_by = ?", (file_id, username)).fetchone()
        return res is not None

def handle_rename_route(handler, query, active_project, username):
    file_id = query.get('id', [None])[0]
    new_name = query.get('new_name', [''])[0].strip()
    if file_id and new_name:
        if not sqlite3_connect_owner_test(file_id, username):
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Only+file+owners+can+rename+assets')
            return
            
        file_data = database.get_file_metadata(file_id)
        if file_data:
            old_name, _, project = file_data
            sanitized_new = helpers.sanitize_filename(new_name)
            if sanitized_new:
                import sqlite3
                with sqlite3.connect(config.DB_FILE) as conn:
                    versions = conn.execute("SELECT id, filepath FROM files WHERE filename = ? AND project = ?", (old_name, project)).fetchall()
                    for row_id, old_filepath in versions:
                        old_disk_path = os.path.join(config.UPLOAD_DIR, old_filepath)
                        if "_" in old_filepath:
                            parts = old_filepath.split('_', 2)
                            new_filepath = f"{parts[0]}_{parts[1]}_{sanitized_new}" if len(parts) >= 3 else f"{int(time.time())}_{sanitized_new}"
                        else:
                            new_filepath = f"{int(time.time())}_{sanitized_new}"
                        new_disk_path = os.path.join(config.UPLOAD_DIR, new_filepath)
                        if os.path.exists(old_disk_path):
                            os.rename(old_disk_path, new_disk_path)
                        conn.execute("UPDATE files SET filepath = ? WHERE id = ?", (new_filepath, row_id))
                database.update_filename_history(old_name, sanitized_new, project)
                handler.redirect(f'/?project={urllib.parse.quote(active_project)}&msg=Renamed+successfully+to+{urllib.parse.quote(sanitized_new)}')
                return
    handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Invalid+rename+request')

def handle_dashboard_route(handler, query, username, active_project):
    distinct_projects, latest_files, all_versions = database.fetch_dashboard_data(active_project, username)
    
    # Fetch other system users for the sharing dropdown selection
    other_users = database.fetch_other_users(username)
    user_options = "".join([f'<option value="{u}">{u}</option>' for u in other_users])
    
    project_pool = {row[0] for row in distinct_projects}
    project_pool.add('Default')
    if active_project not in project_pool:
        project_pool.add(active_project)
        
    msg = query.get('msg', [None])[0]
    err = query.get('error', [None])[0]
    
    alert_div = ''
    if msg or err:
        color = "#f8d7da" if err else "#d4edda"
        text_color = "#721c24" if err else "#155724"
        alert_div = f'<div style="background: {color}; color: {text_color}; padding: 10px; margin-bottom: 15px; border-radius: 4px;">{err or msg}</div>'

    project_list_items = ""
    for p_name in sorted(list(project_pool)):
        active_class = "active" if p_name == active_project else ""
        project_list_items += f'<li class="project-item {active_class}"><a href="/?project={urllib.parse.quote(p_name)}">📁 {p_name}</a></li>'

    table_rows = ""
    if not latest_files:
        table_rows = '<tr><td colspan="6" style="text-align: center; color: #777;">No files uploaded or shared in this project space yet.</td></tr>'
    else:
        for f in latest_files:
            file_id, filename, filepath, filesize, uploaded_by, version, upload_time = f
            history_rows = ""
            history_list = [v for v in all_versions if v[1] == filename and v[4] == uploaded_by and v[5] < version]
            
            if history_list:
                history_rows += f'<tr class="history-row-{file_id}" style="display:none; background:#fdfdfd;"><td colspan="6" style="padding-left: 30px; font-size:13px; color:#555;"><strong>Version History:</strong><table style="width:100%; margin-top:5px; border:1px solid #eee;">'
                for hv in history_list:
                    history_rows += f"""
                    <tr style="background:#f9f9f9;">
                        <td>v{hv[5]}</td>
                        <td>{helpers.format_bytes(hv[3])}</td>
                        <td>Uploaded by {hv[4]}</td>
                        <td>{hv[6]}</td>
                        <td style="text-align:right;">
                            <a href="/download?id={hv[0]}&project={urllib.parse.quote(active_project)}" style="color: #28a745; text-decoration:none; margin-right:15px;">Download v{hv[5]}</a>
                        </td>
                    </tr>"""
                history_rows += "</table></td></tr>"

            toggle_btn = ""
            if history_list:
                toggle_btn = f"""<button onclick="var el=document.getElementsByClassName('history-row-{file_id}'); for(var i=0;i<el.length;i++) {{ el[i].style.display = el[i].style.display==='none'?'table-row':'none'; }}" style="margin-left:8px; background:none; border:none; color:#007bff; cursor:pointer; font-size:12px; text-decoration:underline;">🕒 View History ({len(history_list)})</button>"""

            # Updated to pass the context parameters into our custom JS dialog opener instead of standard prompts
            share_js = f"openShareModal('{file_id}', '{filename}')"
            rename_js = f"var n=prompt('Enter new filename:', '{filename}'); if(n && n.trim()!=''){{window.location.href='/rename?id={file_id}&project={urllib.parse.quote(active_project)}&new_name='+encodeURIComponent(n.trim());}}"

            is_owner = (uploaded_by == username)
            owner_actions = ""
            if is_owner:
                owner_actions = f"""
                    <a href="javascript:void(0);" onclick="{share_js}" style="background: #10b981; padding: 6px 12px; text-decoration: none; border-radius: 4px; color: white; font-size: 14px; margin-right: 5px; font-weight:bold;">Share</a>
                    <a href="javascript:void(0);" onclick="{rename_js}" style="background: #ffc107; padding: 6px 12px; text-decoration: none; border-radius: 4px; color: #212529; font-size: 14px; margin-right: 5px; font-weight:bold;">Rename</a>
                    <a href="/delete?id={file_id}&project={urllib.parse.quote(active_project)}" onclick="return confirm('Are you sure you want to delete this file and its history?');" style="background: #dc3545; padding: 6px 12px; text-decoration: none; border-radius: 4px; color: white; font-size: 14px; margin-right: 5px;">Delete</a>
                """
            
            owner_badge = f'<span style="color:#2563eb; font-size:11px;">(You)</span>' if is_owner else f'<span style="color:#64748b; font-size:11px;">(Shared by {uploaded_by})</span>'

            table_rows += f"""
            <tr style="background:#fff; font-weight: 500;">
                <td><strong>{filename}</strong> {owner_badge} {toggle_btn}</td>
                <td><span style="background:#e2e8f0; padding:2px 6px; border-radius:4px; font-size:12px;">v{version}</span></td>
                <td>{helpers.format_bytes(filesize)}</td>
                <td>{uploaded_by}</td>
                <td>{upload_time}</td>
                <td style="text-align:right;">
                    {owner_actions}
                    <a href="/download?id={file_id}&project={urllib.parse.quote(active_project)}" style="background: #28a745; padding: 6px 12px; text-decoration: none; border-radius: 4px; color: white; font-size: 14px;">Download Latest</a>
                </td>
            </tr>
            {history_rows}"""

    # Added 'user_options' template rendering parameters context entry logic
    html = helpers.render_template('dashboard.html', {
        'username': username,
        'active_project': active_project,
        'project_list_items': project_list_items,
        'alert_div': alert_div,
        'table_rows': table_rows,
        'user_options': user_options
    })

    handler.send_response(200)
    handler.send_header('Content-type', 'text/html; charset=utf-8')
    handler.end_headers()
    handler.wfile.write(html.encode('utf-8'))

def handle_post_upload(handler, parts, username):
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
                if not orig_filename: continue
                safe_name = helpers.sanitize_filename(orig_filename)
                next_version = database.get_next_version(safe_name, target_project, username)
                unique_name = f"{int(time.time())}_v{next_version}_{safe_name}"
                dest_path = os.path.join(config.UPLOAD_DIR, unique_name)
                with open(dest_path, 'wb') as output_file:
                    output_file.write(file_body)
                file_size = len(file_body)
                database.insert_file_record(target_project, safe_name, unique_name, file_size, username, next_version)
                handler.redirect(f'/?project={urllib.parse.quote(target_project)}&msg=Uploaded+{urllib.parse.quote(safe_name)}+(v{next_version})+successfully')
                return
    handler.redirect('/?error=Failed+to+process+upload')
