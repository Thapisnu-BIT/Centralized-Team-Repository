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
        alert_div = f'<div style="color: var(--error); font-size: 14px; margin-bottom: 15px; text-align:center;">{error_msg}</div>'
    elif msg:
        alert_div = f'<div style="color: var(--success); font-size: 14px; margin-bottom: 15px; text-align:center;">{msg}</div>'
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
    file_id = query.get('id', [None])[0]
    target_user = query.get('with', [''])[0].strip()
    privilege = query.get('privilege', ['Viewer'])[0].strip()
    
    if file_id and target_user:
        success, message = database.share_file_with_user(file_id, target_user, username, privilege)
        if success:
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&msg={urllib.parse.quote(message)}')
            return
        else:
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error={urllib.parse.quote(message)}')
            return
    handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Invalid+Share+Parameters')

def handle_revoke_route(handler, query, username, active_project):
    file_id = query.get('id', [None])[0]
    target_user = query.get('with', [''])[0].strip()
    if file_id and target_user:
        success, message = database.revoke_file_share(file_id, target_user, username)
        if success:
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&msg={urllib.parse.quote(message)}')
        else:
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error={urllib.parse.quote(message)}')
    else:
        handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Invalid+Revoke+Parameters')

def handle_download_route(handler, query, active_project, username):
    file_id = query.get('id', [None])[0]
    if file_id:
        if not database.check_file_read_access(file_id, username):
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Access+Denied')
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
        if not database.check_file_write_access(file_id, username):
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Access+Denied:+Insufficient+Permissions')
            return
        file_data = database.get_file_metadata(file_id)
        if file_data:
            filename, unique_name, project = file_data
            full_path = os.path.join(config.UPLOAD_DIR, unique_name)
            if os.path.exists(full_path):
                os.remove(full_path)
            database.delete_file_record(file_id)
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&msg=Deleted+{urllib.parse.quote(filename)}+successfully')
            return
    handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Could+not+delete+file')

def handle_rename_route(handler, query, active_project, username):
    file_id = query.get('id', [None])[0]
    new_name = query.get('new_name', [''])[0].strip()
    if file_id and new_name:
        if not database.check_file_write_access(file_id, username):
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Access+Denied:+Insufficient+Permissions')
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
    other_users = database.fetch_other_users(username)
    user_options = "".join([f'<option value="{u}">{u}</option>' for u in other_users])

    file_shared_with_data = {}
    for f in latest_files:
        file_id = f[0]
        shared_users = database.get_shared_users_for_file(file_id)
        file_shared_with_data[file_id] = shared_users
    
    project_pool = {row[0] for row in distinct_projects}
    project_pool.add('Default')
    if active_project not in project_pool:
        project_pool.add(active_project)
    
    msg = query.get('msg', [None])[0]
    err = query.get('error', [None])[0]
    
    alert_div = ''
    if msg or err:
        cls = "alert-error" if err else "alert-success"
        alert_div = f'<div class="{cls}">{err or msg}</div>'

    project_list_items = ""
    for p_name in sorted(list(project_pool)):
        active_class = "active" if p_name == active_project else ""
        project_list_items += f'<li class="project-item {active_class}"><a href="/?project={urllib.parse.quote(p_name)}">📁 {p_name}</a></li>'

    table_rows = ""
    if not latest_files:
        table_rows = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No files uploaded or shared in this project space yet.</td></tr>'
    else:
        for f in latest_files:
            file_id, filename, filepath, filesize, uploaded_by, version, upload_time, user_role = f
            history_rows = ""
            history_list = [v for v in all_versions if v[1] == filename and v[4] == uploaded_by and v[5] < version]
            
            is_owner = (uploaded_by == username)
            allowed_to_modify = is_owner or (user_role == 'Editor')
            
            shared_users_parts = []
            for user, priv in file_shared_with_data.get(file_id, []):
                label = f'<span>{user} <em>({priv})</em>'
                if is_owner:
                    label += f' <a href="/revoke?id={file_id}&project={urllib.parse.quote(active_project)}&with={urllib.parse.quote(user)}" class="btn-revoke" title="Revoke access">&#x2716;</a>'
                label += '</span>'
                shared_users_parts.append(label)
            shared_users_str = f'<div class="shared-grid">{" ".join(shared_users_parts)}</div>' if shared_users_parts else '<span class="text-muted">None</span>'

            if history_list:
                history_rows += f'<tr class="history-row-{file_id}" style="display:none;"><td colspan="7" style="padding-left: 30px; font-size:13px;"><strong>Version History:</strong><table class="history-inner">'
                for hv in history_list:
                    history_rows += f'<tr><td>v{hv[5]}</td><td>{helpers.format_bytes(hv[3])}</td><td>Uploaded by {hv[4]}</td><td>{hv[6]}</td><td style="text-align:right;"><a href="/download?id={hv[0]}&project={urllib.parse.quote(active_project)}" class="btn-action btn-download" title="Download v{hv[5]}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></a></td></tr>'
                history_rows += "</table></td></tr>"

            toggle_btn = ""
            if history_list:
                toggle_btn = f"<button onclick=\"var el=document.getElementsByClassName('history-row-{file_id}'); for(var i=0;i<el.length;i++) {{ el[i].style.display = el[i].style.display==='none'?'table-row':'none'; }}\" class=\"btn-view\">View History ({len(history_list)})</button>"

            share_js = f"openShareModal('{file_id}', '{helpers.js_escape(filename)}')"
            rename_js = f"var n=prompt('Enter new filename:', '{helpers.js_escape(filename)}'); if(n && n.trim()!=''){{window.location.href='/rename?id={file_id}&project={urllib.parse.quote(active_project)}&new_name='+encodeURIComponent(n.trim());}}"
            
            owner_actions = ""
            if is_owner:
                owner_actions += f'''<a href="javascript:void(0);" onclick="{share_js}" class="btn-action btn-share" title="Share">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
                </a>'''
            
            if allowed_to_modify:
                owner_actions += f"""
                    <a href="javascript:void(0);" onclick="{rename_js}" class="btn-action btn-rename" title="Rename">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
                    </a>
                    <a href="/delete?id={file_id}&project={urllib.parse.quote(active_project)}" onclick="return confirm('Are you sure you want to delete this file and its history?');" class="btn-action btn-delete" title="Delete">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                    </a>
                """
            
            owner_badge = f'<span class="badge-owner">(You)</span>' if is_owner else f'<span class="badge-shared">(Shared - {user_role})</span>'

            table_rows += f"""
            <tr class="file-row">
                <td><strong>{filename}</strong> {owner_badge} {toggle_btn}</td>
                <td><span class="version-badge">v{version}</span></td>
                <td>{helpers.format_bytes(filesize)}</td>
                <td>{uploaded_by}</td>
                <td>{upload_time}</td>
                <td>{shared_users_str}</td>
                <td style="text-align:right;">
                    <div class="actions-grid">
                        {owner_actions}
                        <a href="/download?id={file_id}&project={urllib.parse.quote(active_project)}" class="btn-action btn-download" title="Download">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        </a>
                    </div>
                </td>
            </tr>
            {history_rows}"""

    html = helpers.render_template('dashboard.html', {
        'username': username,
        'active_project': active_project,
        'project_list_items': project_list_items,
        'alert_div': alert_div,
        'table_rows': table_rows,
        'user_options': user_options,
        'file_shared_with_data': file_shared_with_data
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
