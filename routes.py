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
    error_div = f'<div style="color: #dc3545; font-size: 14px; margin-bottom: 10px;">{error_msg}</div>' if error_msg else ''
    html = helpers.render_template('login.html', {'error_div': error_div})
    
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

def handle_download_route(handler, query, active_project):
    file_id = query.get('id', [None])[0]
    if file_id:
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

def handle_delete_route(handler, query, active_project):
    file_id = query.get('id', [None])[0]
    if file_id:
        file_data = database.get_file_metadata(file_id)
        if file_data:
            filename, unique_name = file_data
            full_path = os.path.join(config.UPLOAD_DIR, unique_name)
            
            if os.path.exists(full_path):
                os.remove(full_path)
            
            database.delete_file_record(file_id)
            handler.redirect(f'/?project={urllib.parse.quote(active_project)}&msg=Deleted+{urllib.parse.quote(filename)}+successfully')
            return
    handler.redirect(f'/?project={urllib.parse.quote(active_project)}&error=Could+not+delete+file')

def handle_dashboard_route(handler, query, username, active_project):
    distinct_projects, latest_files, all_versions = database.fetch_dashboard_data(active_project)
    
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
                        <td>{helpers.format_bytes(hv[3])}</td>
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
                <td>{helpers.format_bytes(filesize)}</td>
                <td>{uploaded_by}</td>
                <td>{upload_time}</td>
                <td style="text-align:right;">
                    <a href="/download?id={file_id}&project={urllib.parse.quote(active_project)}" style="background: #28a745; padding: 6px 12px; text-decoration: none; border-radius: 4px; color: white; font-size: 14px; margin-right: 5px;">Download Latest</a>
                    <a href="/delete?id={file_id}&project={urllib.parse.quote(active_project)}" onclick="return confirm('Are you sure you want to delete this file and its history?');" style="background: #dc3545; padding: 6px 12px; text-decoration: none; border-radius: 4px; color: white; font-size: 14px;">Delete File</a>
                </td>
            </tr>
            {history_rows}"""

    html = helpers.render_template('dashboard.html', {
        'username': username,
        'active_project': active_project,
        'project_list_items': project_list_items,
        'alert_div': alert_div,
        'table_rows': table_rows
    })

    handler.send_response(200)
    handler.send_header('Content-type', 'text/html; charset=utf-8')
    handler.end_headers()
    handler.wfile.write(html.encode('utf-8'))

def handle_post_login(handler, params):
    username = params.get('username', [''])[0]
    password = params.get('password', [''])[0]
    
    if username == config.ADMIN_USER and password == config.ADMIN_PASS:
        session_id = secrets.token_hex(16)
        config.SESSIONS[session_id] = username
        cookie = cookies.SimpleCookie()
        cookie['session_id'] = session_id
        cookie['session_id']['path'] = '/'
        cookie['session_id']['httponly'] = True
        handler.redirect('/', set_cookie=cookie.output(header=''))
    else:
        handler.redirect('/?error=Invalid+credentials')

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
                if not orig_filename:
                    continue
                    
                safe_name = helpers.sanitize_filename(orig_filename)
                next_version = database.get_next_version(orig_filename, target_project)
                
                unique_name = f"{int(time.time())}_v{next_version}_{safe_name}"
                dest_path = os.path.join(config.UPLOAD_DIR, unique_name)
                
                with open(dest_path, 'wb') as output_file:
                    output_file.write(file_body)
                
                file_size = len(file_body)
                database.insert_file_record(target_project, orig_filename, unique_name, file_size, username, next_version)
                
                handler.redirect(f'/?project={urllib.parse.quote(target_project)}&msg=Uploaded+{urllib.parse.quote(orig_filename)}+(v{next_version})+successfully')
                return
    handler.redirect('/?error=Failed+to+process+upload')
