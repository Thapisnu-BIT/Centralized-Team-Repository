import os
import time
import json
import urllib.parse
from http import cookies
import secrets

import config
import database
import helpers


def _val(d, key, default=None):
    if not isinstance(d, dict):
        return default
    v = d.get(key, default)
    return v[0] if isinstance(v, list) and v else (v if v is not None else default)

def _project(query, default='Default'):
    return _val(query, 'project', default)

def _send_redirect(handler, project, msg=None, err=None):
    qs = f'project={urllib.parse.quote(project)}'
    if err:
        qs += f'&error={urllib.parse.quote(err)}'
    elif msg:
        qs += f'&msg={urllib.parse.quote(msg)}'
    handler.redirect('/?' + qs)


# ── Auth routes ──────────────────────────────────────────────

def handle_dashboard_or_login(handler, query, username, path, body):
    if username:
        return handle_dashboard_route(handler, query, username, _project(query), body)
    return handle_login_route(handler, query, username, _project(query), body)

def handle_login_route(handler, query, username, active_project, body):
    error_msg = _val(query, 'error')
    msg = _val(query, 'msg')
    alert_div = ''
    if error_msg:
        alert_div = f'<div style="color: var(--error); font-size: 14px; margin-bottom: 15px; text-align:center;">{error_msg}</div>'
    elif msg:
        alert_div = f'<div style="color: var(--success); font-size: 14px; margin-bottom: 15px; text-align:center;">{msg}</div>'
    html = helpers.render_template('login.html', {'error_div': alert_div})
    handler.send_html(html)

def handle_post_login(handler, query, username, active_project, body):
    username_param = _val(body, 'username', '')
    password = _val(body, 'password', '')
    action = _val(body, 'action', 'login')
    if action == 'register':
        ok, msg = database.register_user(username_param, password)
        if ok:
            handler.redirect('/?msg=' + urllib.parse.quote("Account created! Please sign in."))
        else:
            handler.redirect('/?error=' + urllib.parse.quote(msg))
        return
    if database.verify_user_credentials(username_param, password):
        session_id = secrets.token_hex(16)
        config.SESSIONS[session_id] = username_param
        c = cookies.SimpleCookie()
        c['session_id'] = session_id
        c['session_id']['path'] = '/'
        c['session_id']['httponly'] = True
        handler.redirect('/', set_cookie=c.output(header=''))
    else:
        handler.redirect('/?error=Invalid+username+or+password')

def handle_logout_route(handler, query, username, active_project, body):
    cookie_header = handler.headers.get('Cookie')
    if cookie_header:
        c = cookies.SimpleCookie(cookie_header)
        if 'session_id' in c:
            config.SESSIONS.pop(c['session_id'].value, None)
    handler.redirect('/?msg=Logged+out')


# ── File routes (POST mutations, GET reads) ──────────────────

def handle_delete(handler, query, username, active_project, body):
    file_id = _val(body, 'id') or _val(query, 'id')
    project = _val(body, 'project') or _project(query)
    if not file_id:
        return _send_redirect(handler, project, err='No file specified')
    if not database.check_file_write_access(file_id, username):
        return _send_redirect(handler, project, err='Access Denied: Insufficient Permissions')
    file_data = database.get_file_metadata(file_id)
    if not file_data:
        return _send_redirect(handler, project, err='File not found')
    filename, unique_name, _ = file_data
    full_path = os.path.join(config.UPLOAD_DIR, unique_name)
    if os.path.exists(full_path):
        os.remove(full_path)
    database.delete_file_record(file_id)
    _send_redirect(handler, project, msg=f'Deleted {filename} successfully')

def handle_rename(handler, query, username, active_project, body):
    file_id = _val(body, 'id') or _val(query, 'id')
    new_name = _val(body, 'new_name') or _val(query, 'new_name')
    project = _val(body, 'project') or _project(query)
    if not file_id or not new_name:
        return _send_redirect(handler, project, err='Invalid rename request')
    if not database.check_file_write_access(file_id, username):
        return _send_redirect(handler, project, err='Access Denied: Insufficient Permissions')
    file_data = database.get_file_metadata(file_id)
    if not file_data:
        return _send_redirect(handler, project, err='File not found')
    old_name, _, file_project = file_data
    sanitized = helpers.sanitize_filename(new_name)
    if not sanitized:
        return _send_redirect(handler, project, err='Invalid filename')
    import sqlite3
    with sqlite3.connect(config.DB_FILE) as conn:
        versions = conn.execute("SELECT id, filepath FROM files WHERE filename = ? AND project = ?", (old_name, file_project)).fetchall()
        for row_id, old_fp in versions:
            old_disk = os.path.join(config.UPLOAD_DIR, old_fp)
            if "_" in old_fp:
                parts = old_fp.split('_', 2)
                new_fp = f"{parts[0]}_{parts[1]}_{sanitized}" if len(parts) >= 3 else f"{int(time.time())}_{sanitized}"
            else:
                new_fp = f"{int(time.time())}_{sanitized}"
            new_disk = os.path.join(config.UPLOAD_DIR, new_fp)
            if os.path.exists(old_disk):
                os.rename(old_disk, new_disk)
            conn.execute("UPDATE files SET filepath = ? WHERE id = ?", (new_fp, row_id))
    database.update_filename_history(old_name, sanitized, file_project)
    _send_redirect(handler, project, msg=f'Renamed to {sanitized}')

def handle_share(handler, query, username, active_project, body):
    file_id = _val(body, 'id') or _val(query, 'id')
    target_user = _val(body, 'with') or _val(query, 'with')
    privilege = _val(body, 'privilege') or _val(query, 'privilege') or 'Viewer'
    project = _val(body, 'project') or _project(query)
    if file_id and target_user:
        ok, msg = database.share_file_with_user(file_id, target_user, username, privilege)
        if ok:
            return _send_redirect(handler, project, msg=msg)
        return _send_redirect(handler, project, err=msg)
    _send_redirect(handler, project, err='Invalid Share Parameters')

def handle_revoke(handler, query, username, active_project, body):
    file_id = _val(body, 'id') or _val(query, 'id')
    target_user = _val(body, 'with') or _val(query, 'with')
    project = _val(body, 'project') or _project(query)
    if file_id and target_user:
        ok, msg = database.revoke_file_share(file_id, target_user, username)
        if ok:
            return _send_redirect(handler, project, msg=msg)
        return _send_redirect(handler, project, err=msg)
    _send_redirect(handler, project, err='Invalid Revoke Parameters')

def handle_upload(handler, query, username, active_project, body):
    if not isinstance(body, bytes):
        return _send_redirect(handler, active_project, err='Malformed upload data')
    parts = body.split(b'--' + handler.headers.get('Content-Type', '').split('boundary=')[1].encode('utf-8'))
    target_project = active_project
    for part in parts:
        if b'name="active_project"' in part:
            tp = part.split(b'\r\n\r\n')[1].strip().decode('utf-8')
            if tp:
                target_project = tp
    for part in parts:
        if b'Content-Disposition' in part and b'name="repo_file"' in part:
            hdrs, payload = part.split(b'\r\n\r\n', 1)
            if payload.endswith(b'\r\n'): payload = payload[:-2]
            if payload.endswith(b'--'): payload = payload[:-2]
            if payload.endswith(b'\r\n'): payload = payload[:-2]
            hdr_str = hdrs.decode('utf-8', errors='ignore')
            if 'filename="' in hdr_str:
                orig = hdr_str.split('filename="')[1].split('"')[0]
                if not orig:
                    continue
                safe = helpers.sanitize_filename(orig)
                nv = database.get_next_version(safe, target_project, username)
                uname = f"{int(time.time())}_v{nv}_{safe}"
                with open(os.path.join(config.UPLOAD_DIR, uname), 'wb') as f:
                    f.write(payload)
                database.insert_file_record(target_project, safe, uname, len(payload), username, nv)
                return _send_redirect(handler, target_project, msg=f'Uploaded {safe} (v{nv})')
    _send_redirect(handler, target_project, err='Failed to process upload')

def handle_create_project(handler, query, username, active_project, body):
    name = _val(body, 'project_name', '').strip()
    if name:
        handler.redirect(f'/?project={urllib.parse.quote(name)}&msg=Project+Workspace+Ready')
    else:
        handler.redirect('/?error=Invalid+project+name')


# ── GET file routes (download, preview) ──────────────────────

def handle_download(handler, query, username, active_project, body):
    file_id = _val(query, 'id')
    project = _project(query)
    if not file_id:
        return _send_redirect(handler, project, err='No file specified')
    if not database.check_file_read_access(file_id, username):
        return _send_redirect(handler, project, err='Access Denied')
    file_data = database.get_file_by_id(file_id)
    if not file_data:
        return _send_redirect(handler, project, err='File not found')
    filename, unique_name, version = file_data
    full_path = os.path.join(config.UPLOAD_DIR, unique_name)
    if not os.path.exists(full_path):
        return _send_redirect(handler, project, err='File not found on disk')
    name_parts = os.path.splitext(filename)
    display_name = f"{name_parts[0]}_v{version}{name_parts[1]}"
    handler.send_response(200)
    handler.send_header('Content-Type', 'application/octet-stream')
    handler.send_header('Content-Disposition', f'attachment; filename="{display_name}"')
    handler.send_header('Content-Length', str(os.path.getsize(full_path)))
    handler.end_headers()
    try:
        with open(full_path, 'rb') as f:
            handler.wfile.write(f.read())
    except (BrokenPipeError, ConnectionResetError):
        pass

def handle_preview(handler, query, username, active_project, body):
    file_id = _val(query, 'id')
    project = _project(query)
    if not file_id:
        return _send_redirect(handler, project, err='No file specified')
    if not database.check_file_read_access(file_id, username):
        return _send_redirect(handler, project, err='Access Denied')
    file_data = database.get_file_by_id(file_id)
    if not file_data:
        return _send_redirect(handler, project, err='File not found')
    filename, unique_name, version = file_data
    full_path = os.path.join(config.UPLOAD_DIR, unique_name)
    if not os.path.exists(full_path):
        return _send_redirect(handler, project, err='File not found on disk')
    file_size = os.path.getsize(full_path)
    size_str = helpers.format_bytes(file_size)
    PREVIEW_MAX = 102400
    if file_size > PREVIEW_MAX:
        dl = f'/download?id={file_id}&project={urllib.parse.quote(project)}'
        content = f'<div class="file-too-large">…<p>File too large ({size_str}).<br><a href="{dl}" style="color:var(--accent);">Download</a></p></div>'
    elif not helpers.is_text_file(filename):
        dl = f'/download?id={file_id}&project={urllib.parse.quote(project)}'
        content = f'<div class="unsupported">…<p>Preview not available.<br><a href="{dl}" style="color:var(--accent);">Download</a></p></div>'
    else:
        try:
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                raw = f.read(PREVIEW_MAX)
        except Exception:
            raw = '(Error reading file)'
        content = f'<pre>{helpers.html_encode(raw)}</pre>'
    html = helpers.render_template('preview.html', {
        'filename': filename,
        'project': project,
        'file_info': f"v{version} &middot; {size_str}",
        'content': content,
    })
    handler.send_html(html)


# ── Dashboard ────────────────────────────────────────────────

def handle_dashboard_route(handler, query, username, active_project, body):
    distinct_projects, latest_files, all_versions = database.fetch_dashboard_data(active_project, username)
    other_users = database.fetch_other_users(username)
    user_options = "".join(f'<option value="{u}">{u}</option>' for u in other_users)

    file_shared_with_data = {}
    for f in latest_files:
        fid = f[0]
        file_shared_with_data[fid] = database.get_shared_users_for_file(fid)

    project_pool = {r[0] for r in distinct_projects}
    project_pool.add('Default')
    if active_project not in project_pool:
        project_pool.add(active_project)

    # Stats banner
    total_files = len(latest_files)
    total_size = sum(f[3] for f in latest_files if f[3] is not None)
    total_size_str = helpers.format_bytes(total_size) if total_size else "0 B"
    latest_time = max((f[6] for f in all_versions if f[6]), default=None)
    last_activity = helpers.time_ago(latest_time) if latest_time else "Never"
    shared_user_set = set()
    for u_list in file_shared_with_data.values():
        for user, _ in u_list:
            shared_user_set.add(user)
    shared_count = len(shared_user_set)
    stats_parts = [f"📦 {total_files} file{'s' if total_files != 1 else ''}", total_size_str, f"Last: {last_activity}"]
    if shared_count:
        stats_parts.append(f"Shared: {shared_count} user{'s' if shared_count != 1 else ''}")
    stats_banner = '<div class="stats-banner">' + " · ".join(stats_parts) + '</div>'

    msg = _val(query, 'msg')
    err = _val(query, 'error')
    alert_div = ''
    if msg or err:
        cls = "alert-error" if err else "alert-success"
        alert_div = f'<div class="{cls}">{err or msg}</div>'

    project_list_items = ""
    for p in sorted(project_pool):
        cls = "active" if p == active_project else ""
        project_list_items += f'<li class="project-item {cls}"><a href="/?project={urllib.parse.quote(p)}">📁 {p}</a></li>'

    table_rows = ""
    if not latest_files:
        table_rows = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);">No files in this project.</td></tr>'
    else:
        for f in latest_files:
            fid, filename, _, filesize, uploaded_by, version, upload_time, user_role = f
            history_list = [v for v in all_versions if v[1] == filename and v[4] == uploaded_by and v[5] < version]
            is_owner = (uploaded_by == username)
            allowed = is_owner or (user_role == 'Editor')

            history_rows = ""
            if history_list:
                history_rows += f'<tr class="history-row-{fid}" style="display:none;"><td colspan="7" style="padding-left:30px;font-size:13px;"><strong>History:</strong><table class="history-inner">'
                for hv in history_list:
                    dl = f'/download?id={hv[0]}&project={urllib.parse.quote(active_project)}'
                    history_rows += f'<tr><td>v{hv[5]}</td><td>{helpers.format_bytes(hv[3])}</td><td>by {hv[4]}</td><td>{hv[6]}</td><td style="text-align:right;"><a href="{dl}" class="btn-action btn-download" title="Download v{hv[5]}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></a></td></tr>'
                history_rows += "</table></td></tr>"

            toggle_btn = ""
            if history_list:
                toggle_btn = f'<button onclick="var el=document.getElementsByClassName(\'history-row-{fid}\');for(var i=0;i<el.length;i++){{el[i].style.display=el[i].style.display===\'none\'?\'table-row\':\'none\';}}" class="btn-view">History ({len(history_list)})</button>'

            shared_parts = []
            for user, priv in file_shared_with_data.get(fid, []):
                label = f'<span>{user} <em>({priv})</em>'
                if is_owner:
                    form_id = f'revoke-{fid}-{hash(user)}'
                    label += f' <form method="POST" action="/revoke" style="display:inline"><input type="hidden" name="id" value="{fid}"><input type="hidden" name="with" value="{user}"><input type="hidden" name="project" value="{active_project}"><button type="submit" class="btn-revoke" title="Revoke">&#x2716;</button></form>'
                label += '</span>'
                shared_parts.append(label)
            shared_str = f'<div class="shared-grid">{" ".join(shared_parts)}</div>' if shared_parts else '<span class="text-muted">None</span>'

            owner_actions = ""
            if is_owner:
                owner_actions += f'''<a href="javascript:void(0);" onclick="openShareModal('{fid}', '{helpers.js_escape(filename)}')" class="btn-action btn-share" title="Share">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
                </a>'''
            if allowed:
                rename_form_id = f'rename-form-{fid}'
                owner_actions += f'''
                    <form id="{rename_form_id}" method="POST" action="/rename" style="display:inline">
                        <input type="hidden" name="id" value="{fid}">
                        <input type="hidden" name="project" value="{active_project}">
                        <input type="hidden" name="new_name" id="rename-input-{fid}" value="">
                    </form>
                    <a href="javascript:void(0);" onclick="var n=prompt('New filename:','{helpers.js_escape(filename)}');if(n&&n.trim()!=''){{document.getElementById('rename-input-{fid}').value=n.trim();document.getElementById('{rename_form_id}').submit();}}" class="btn-action btn-rename" title="Rename">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
                    </a>
                    <form method="POST" action="/delete" style="display:inline" onsubmit="return confirm('Delete this file and its history?');">
                        <input type="hidden" name="id" value="{fid}">
                        <input type="hidden" name="project" value="{active_project}">
                        <button type="submit" class="btn-action btn-delete" title="Delete">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                        </button>
                    </form>'''

            badge = '<span class="badge-owner">(You)</span>' if is_owner else f'<span class="badge-shared">(Shared - {user_role})</span>'
            dl = f'/download?id={fid}&project={urllib.parse.quote(active_project)}'
            pv = f'/preview?id={fid}&project={urllib.parse.quote(active_project)}'

            table_rows += f'''
            <tr class="file-row">
                <td><strong>{filename}</strong> {badge} {toggle_btn}</td>
                <td><span class="version-badge">v{version}</span></td>
                <td>{helpers.format_bytes(filesize)}</td>
                <td>{uploaded_by}</td>
                <td>{upload_time}</td>
                <td>{shared_str}</td>
                <td style="text-align:right;">
                    <div class="actions-grid">
                        {owner_actions}
                        <a href="{pv}" class="btn-action btn-preview" title="Preview">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                        </a>
                        <a href="{dl}" class="btn-action btn-download" title="Download">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        </a>
                    </div>
                </td>
            </tr>
            {history_rows}'''

    html = helpers.render_template('dashboard.html', {
        'username': username,
        'active_project': active_project,
        'project_list_items': project_list_items,
        'alert_div': alert_div,
        'table_rows': table_rows,
        'user_options': user_options,
        'stats_banner': stats_banner,
        'file_shared_with_data': file_shared_with_data,
    })
    handler.send_html(html)


# ── JSON API ─────────────────────────────────────────────────

def _api_result(data, status=200):
    return {'ok': True, 'data': data}, status

def _api_error(msg, status=400):
    return {'ok': False, 'error': msg}, status

def api_list_projects(handler, body, username, query, **kw):
    distinct, _, _ = database.fetch_dashboard_data('Default', username)
    projects = sorted({r[0] for r in distinct})
    if 'Default' not in projects:
        projects.insert(0, 'Default')
    handler.send_json(*_api_result(projects))

def api_list_files(handler, body, username, query, **kw):
    project = _val(query, 'project') or 'Default'
    _, latest, _ = database.fetch_dashboard_data(project, username)
    files = []
    for f in latest:
        files.append({
            'id': f[0],
            'filename': f[1],
            'size': f[3],
            'uploaded_by': f[4],
            'version': f[5],
            'upload_time': f[6],
        })
    handler.send_json(*_api_result(files))

def api_get_file(handler, body, username, query, **kw):
    file_id = kw.get('id')
    if not file_id:
        return handler.send_json(*_api_error('No file ID'))
    if not database.check_file_read_access(file_id, username):
        return handler.send_json(*_api_error('Access denied', 403))
    row = database.get_file_by_id(file_id)
    if not row:
        return handler.send_json(*_api_error('Not found', 404))
    filename, unique_name, version = row
    handler.send_json(*_api_result({
        'id': int(file_id),
        'filename': filename,
        'version': version,
    }))

def api_download_file(handler, body, username, query, **kw):
    file_id = kw.get('id')
    if not file_id:
        return handler.send_json(*_api_error('No file ID'))
    if not database.check_file_read_access(file_id, username):
        return handler.send_json(*_api_error('Access denied', 403))
    row = database.get_file_by_id(file_id)
    if not row:
        return handler.send_json(*_api_error('Not found', 404))
    filename, unique_name, version = row
    full_path = os.path.join(config.UPLOAD_DIR, unique_name)
    if not os.path.exists(full_path):
        return handler.send_json(*_api_error('Not found on disk', 404))
    name_parts = os.path.splitext(filename)
    display_name = f"{name_parts[0]}_v{version}{name_parts[1]}"
    handler.send_response(200)
    handler.send_header('Content-Type', 'application/octet-stream')
    handler.send_header('Content-Disposition', f'attachment; filename="{display_name}"')
    handler.send_header('Content-Length', str(os.path.getsize(full_path)))
    handler.end_headers()
    try:
        with open(full_path, 'rb') as f:
            handler.wfile.write(f.read())
    except (BrokenPipeError, ConnectionResetError):
        pass

def api_preview_file(handler, body, username, query, **kw):
    file_id = kw.get('id')
    if not file_id:
        return handler.send_json(*_api_error('No file ID'))
    if not database.check_file_read_access(file_id, username):
        return handler.send_json(*_api_error('Access denied', 403))
    row = database.get_file_by_id(file_id)
    if not row:
        return handler.send_json(*_api_error('Not found', 404))
    filename, unique_name, version = row
    full_path = os.path.join(config.UPLOAD_DIR, unique_name)
    if not os.path.exists(full_path):
        return handler.send_json(*_api_error('Not found on disk', 404))
    file_size = os.path.getsize(full_path)
    PREVIEW_MAX = 102400
    if file_size > PREVIEW_MAX:
        return handler.send_json(*_api_result({
            'type': 'too_large',
            'size': file_size,
            'message': f'File too large ({helpers.format_bytes(file_size)}). Use /download endpoint.',
        }))
    if not helpers.is_text_file(filename):
        return handler.send_json(*_api_result({
            'type': 'binary',
            'message': 'Preview not available for this file type.',
        }))
    try:
        with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read(PREVIEW_MAX)
    except Exception as e:
        return handler.send_json(*_api_error(f'Read error: {e}'))
    handler.send_json(*_api_result({
        'type': 'text',
        'filename': filename,
        'version': version,
        'size': file_size,
        'content': content,
    }))

def api_upload(handler, body, username, query, **kw):
    if not isinstance(body, bytes):
        return handler.send_json(*_api_error('Multipart data required'))
    ct = handler.headers.get('Content-Type', '')
    if 'boundary=' not in ct:
        return handler.send_json(*_api_error('Missing boundary'))
    boundary = ct.split('boundary=')[1].encode('utf-8')
    parts = body.split(b'--' + boundary)
    target_project = 'Default'
    for part in parts:
        if b'name="active_project"' in part:
            tp = part.split(b'\r\n\r\n')[1].strip().decode('utf-8')
            if tp:
                target_project = tp
    for part in parts:
        if b'Content-Disposition' in part and b'name="repo_file"' in part:
            hdrs, payload = part.split(b'\r\n\r\n', 1)
            if payload.endswith(b'\r\n'): payload = payload[:-2]
            if payload.endswith(b'--'): payload = payload[:-2]
            if payload.endswith(b'\r\n'): payload = payload[:-2]
            hdr_str = hdrs.decode('utf-8', errors='ignore')
            if 'filename="' in hdr_str:
                orig = hdr_str.split('filename="')[1].split('"')[0]
                if not orig:
                    continue
                safe = helpers.sanitize_filename(orig)
                nv = database.get_next_version(safe, target_project, username)
                uname = f"{int(time.time())}_v{nv}_{safe}"
                with open(os.path.join(config.UPLOAD_DIR, uname), 'wb') as f:
                    f.write(payload)
                database.insert_file_record(target_project, safe, uname, len(payload), username, nv)
                return handler.send_json(*_api_result({'id': None, 'filename': safe, 'version': nv, 'project': target_project}))
    handler.send_json(*_api_error('Upload failed'))

def api_delete_file(handler, body, username, query, **kw):
    file_id = kw.get('id') or _val(query, 'id')
    if not file_id:
        return handler.send_json(*_api_error('No file ID'))
    if not database.check_file_write_access(file_id, username):
        return handler.send_json(*_api_error('Access denied', 403))
    row = database.get_file_metadata(file_id)
    if not row:
        return handler.send_json(*_api_error('Not found', 404))
    filename, unique_name, _ = row
    full_path = os.path.join(config.UPLOAD_DIR, unique_name)
    if os.path.exists(full_path):
        os.remove(full_path)
    database.delete_file_record(file_id)
    handler.send_json(*_api_result({'message': f'Deleted {filename}'}))

def api_share_file(handler, body, username, query, **kw):
    project = _val(query, 'project') or 'Default'
    file_id = kw.get('id') or _val(body, 'id')
    target = _val(body, 'with') or _val(query, 'with')
    priv = _val(body, 'privilege') or 'Viewer'
    if not file_id or not target:
        return handler.send_json(*_api_error('id and with required'))
    ok, msg = database.share_file_with_user(file_id, target, username, priv)
    if not ok:
        return handler.send_json(*_api_error(msg))
    handler.send_json(*_api_result({'message': msg}))

def api_revoke_file(handler, body, username, query, **kw):
    project = _val(query, 'project') or 'Default'
    file_id = kw.get('id') or _val(body, 'id')
    target = _val(body, 'with') or _val(query, 'with')
    if not file_id or not target:
        return handler.send_json(*_api_error('id and with required'))
    ok, msg = database.revoke_file_share(file_id, target, username)
    if not ok:
        return handler.send_json(*_api_error(msg))
    handler.send_json(*_api_result({'message': msg}))

def api_rename_file(handler, body, username, query, **kw):
    project = _val(query, 'project') or 'Default'
    file_id = kw.get('id') or _val(body, 'id')
    new_name = _val(body, 'new_name') or _val(query, 'new_name')
    if not file_id or not new_name:
        return handler.send_json(*_api_error('id and new_name required'))
    if not database.check_file_write_access(file_id, username):
        return handler.send_json(*_api_error('Access denied', 403))
    row = database.get_file_metadata(file_id)
    if not row:
        return handler.send_json(*_api_error('Not found', 404))
    old_name, _, file_project = row
    sanitized = helpers.sanitize_filename(new_name)
    if not sanitized:
        return handler.send_json(*_api_error('Invalid filename'))
    import sqlite3
    with sqlite3.connect(config.DB_FILE) as conn:
        versions = conn.execute("SELECT id, filepath FROM files WHERE filename = ? AND project = ?", (old_name, file_project)).fetchall()
        for rid, old_fp in versions:
            old_disk = os.path.join(config.UPLOAD_DIR, old_fp)
            if "_" in old_fp:
                parts = old_fp.split('_', 2)
                new_fp = f"{parts[0]}_{parts[1]}_{sanitized}" if len(parts) >= 3 else f"{int(time.time())}_{sanitized}"
            else:
                new_fp = f"{int(time.time())}_{sanitized}"
            new_disk = os.path.join(config.UPLOAD_DIR, new_fp)
            if os.path.exists(old_disk):
                os.rename(old_disk, new_disk)
            conn.execute("UPDATE files SET filepath = ? WHERE id = ?", (new_fp, rid))
    database.update_filename_history(old_name, sanitized, file_project)
    handler.send_json(*_api_result({'message': f'Renamed to {sanitized}'}))

def api_list_users(handler, body, username, query, **kw):
    users = database.fetch_other_users(username)
    handler.send_json(*_api_result(users))

def api_login(handler, body, username, query, **kw):
    username_param = _val(body, 'username', '')
    password = _val(body, 'password', '')
    if not username_param or not password:
        return handler.send_json(*_api_error('Username and password required'))
    if database.verify_user_credentials(username_param, password):
        session_id = secrets.token_hex(16)
        config.SESSIONS[session_id] = username_param
        return handler.send_json(*_api_result({'token': session_id, 'username': username_param}))
    handler.send_json(*_api_error('Invalid credentials', 401))

def api_logout(handler, body, username, query, **kw):
    cookie_header = handler.headers.get('Cookie')
    if cookie_header:
        c = cookies.SimpleCookie(cookie_header)
        if 'session_id' in c:
            config.SESSIONS.pop(c['session_id'].value, None)
    auth = handler.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        config.SESSIONS.pop(auth[7:], None)
    handler.send_json(*_api_result({'message': 'Logged out'}))
