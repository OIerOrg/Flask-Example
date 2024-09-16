from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, join_room, leave_room, emit
import sqlite3
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
import time
import psutil

app = Flask(__name__)
app.secret_key = '一键三连'  # 请替换为一个安全的密钥
socketio = SocketIO(app)

DATABASE = 'chat.db'
INITIAL_GROUP_ID = 10000
MAX_ADMINS_PER_GROUP = 3

# 记录服务器启动时间
server_start_time = time.time()

# 数据库初始化
def init_db():
    with app.app_context():
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        # 创建用户表
        c.execute('''CREATE TABLE IF NOT EXISTS users
                    (username TEXT PRIMARY KEY,
                    password TEXT,
                    is_admin INTEGER,
                    is_banned INTEGER)''')
        # 创建群组表
        c.execute('''CREATE TABLE IF NOT EXISTS groups
                    (group_id INTEGER PRIMARY KEY,
                    group_name TEXT UNIQUE)''')
        # 创建消息表
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id INTEGER,
                    username TEXT,
                    message TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (group_id) REFERENCES groups(group_id),
                    FOREIGN KEY (username) REFERENCES users(username))''')
        # 创建群组成员表
        c.execute('''CREATE TABLE IF NOT EXISTS group_members
                    (group_id INTEGER,
                    username TEXT,
                    role TEXT DEFAULT 'member',
                    PRIMARY KEY (group_id, username),
                    FOREIGN KEY (group_id) REFERENCES groups(group_id),
                    FOREIGN KEY (username) REFERENCES users(username))''')
        # 检查是否有群组，如果没有则插入一个虚拟群组
        c.execute("SELECT COUNT(*) FROM groups")
        group_count = c.fetchone()[0]
        if group_count == 0:
            # 插入一个虚拟群组，群号为9999，将在应用逻辑中忽略
            c.execute("INSERT INTO groups (group_id, group_name) VALUES (?, ?)", (9999, '虚拟群组'))
        conn.commit()
        conn.close()
with app.app_context():
    init_db()

# 用户注册路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = request.form['password']

        if not username or not password:
            flash("用户名和密码不能为空")
            return redirect(url_for('register'))

        # 连接数据库
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        # 查询用户数量
        c.execute("SELECT COUNT(*) FROM users")
        user_count = c.fetchone()[0]

        # 如果没有用户，当前用户为管理员
        is_admin = 1 if user_count == 0 else 0

        # 哈希密码
        hashed_password = generate_password_hash(password)

        # 尝试插入用户数据
        try:
            c.execute("INSERT INTO users (username, password, is_admin, is_banned) VALUES (?, ?, ?, 0)",
                      (username, hashed_password, is_admin))
            conn.commit()
            flash("注册成功，请登录")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("用户名已存在")
            return redirect(url_for('register'))
        finally:
            conn.close()

    return render_template('register.html')

# 用户登录路由
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = request.form['password']

        if not username or not password:
            flash("用户名和密码不能为空")
            return redirect(url_for('login'))

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT password, is_admin, is_banned FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user:
            hashed_password, is_admin, is_banned = user
            if is_banned:
                flash("你已被封禁")
                return redirect(url_for('login'))
            if check_password_hash(hashed_password, password):
                session['username'] = username
                session['is_admin'] = is_admin
                flash("登录成功")
                return redirect(url_for('index'))
            else:
                flash("用户名或密码错误")
                return redirect(url_for('login'))
        else:
            flash("用户名或密码错误")
            return redirect(url_for('login'))

    return render_template('login.html')

# 用户登出路由
@app.route('/logout')
def logout():
    session.clear()
    flash("已登出")
    return redirect(url_for('login'))

# 主页路由
@app.route('/index')
def index():
    if 'username' in session:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        username = session['username']
        # 获取用户所属的群组
        c.execute("""
            SELECT g.group_id, g.group_name
            FROM groups g
            JOIN group_members gm ON g.group_id = gm.group_id
            WHERE gm.username=?
              AND gm.role NOT IN ('blacklist')
        """, (username,))
        groups = c.fetchall()
        conn.close()
        return render_template('index.html', username=username, groups=groups)
    else:
        return redirect(url_for('login'))

# 创建群组路由
@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        group_name = escape(request.form['group_name'])
        username = session['username']

        if not group_name:
            flash("群组名称不能为空")
            return redirect(url_for('create_group'))

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        try:
            # 获取下一个群号
            c.execute("SELECT MAX(group_id) FROM groups")
            max_group_id = c.fetchone()[0]
            next_group_id = max_group_id + 1 if max_group_id and max_group_id >= INITIAL_GROUP_ID else INITIAL_GROUP_ID

            # 插入新群组
            c.execute("INSERT INTO groups (group_id, group_name) VALUES (?, ?)", (next_group_id, group_name))
            # 将创建者加入群组并设为所有者
            c.execute("INSERT INTO group_members (group_id, username, role) VALUES (?, ?, 'owner')",
                      (next_group_id, username))
            conn.commit()
            flash(f"群组 '{group_name}' 创建成功，群号为 {next_group_id}")
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash("群组名称已存在")
            return redirect(url_for('create_group'))
        finally:
            conn.close()

    return render_template('create_group.html')

# 加入群组路由
@app.route('/join_group', methods=['GET', 'POST'])
def join_group():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            group_id = int(request.form['group_id'])
        except ValueError:
            flash("群号必须是数字")
            return redirect(url_for('join_group'))

        username = session['username']
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT * FROM groups WHERE group_id=?", (group_id,))
        group = c.fetchone()

        if group and group_id >= INITIAL_GROUP_ID:
            # 检查是否在黑名单
            c.execute("SELECT * FROM group_members WHERE group_id=? AND username=? AND role='blacklist'",
                      (group_id, username))
            blacklist_entry = c.fetchone()
            if blacklist_entry and not is_group_owner_or_admin(group_id, session['username']):
                flash("你已被加入黑名单，无法加入该群组")
                conn.close()
                return redirect(url_for('join_group'))

            try:
                c.execute("INSERT INTO group_members (group_id, username, role) VALUES (?, ?, 'member')",
                          (group_id, username))
                conn.commit()
                flash(f"成功加入群组 '{group[1]}'")
                return redirect(url_for('index'))
            except sqlite3.IntegrityError:
                flash("你已在该群组中")
                return redirect(url_for('join_group'))
        else:
            flash("群组不存在")
            return redirect(url_for('join_group'))
        conn.close()

    return render_template('join_group.html')

def get_group_owner(group_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT username FROM group_members WHERE group_id=? AND role='owner'", (group_id,))
    owners = c.fetchall()
    conn.close()
    return [owner[0] for owner in owners]

def is_group_owner_or_admin(group_id, username):
    return username in get_group_owner(group_id) or session.get('is_admin')
# 聊天路由
@app.route('/chat/<int:group_id>')
def chat(group_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    username = session['username']
    # 检查用户是否属于该群组且群号有效
    c.execute("""
        SELECT g.group_name, gm.role
        FROM group_members gm
        JOIN groups g ON gm.group_id = g.group_id
        WHERE gm.group_id=? AND gm.username=?
    """, (group_id, username))
    result = c.fetchone()
    conn.close()

    if result and group_id >= INITIAL_GROUP_ID:
        group_name, role = result
        if role == 'blacklist':
            flash("你已被加入黑名单，无法访问该群组")
            return redirect(url_for('index'))
        return render_template('chat.html', username=username, group_id=group_id, group_name=group_name, canedit=is_group_owner_or_admin(group_id, session['username']))
    else:
        flash("你没有权限访问该群组")
        return redirect(url_for('index'))
# 聊天设置路由



@app.route('/chat/<int:group_id>/settings', methods=['GET', 'POST'])
def group_settings(group_id):
    # 检查用户是否有权限访问此页面
    if 'username' not in session or not is_group_owner_or_admin(group_id, session['username']):
        flash("你没有权限访问这个页面")
        return redirect(url_for('index'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM groups WHERE group_id=?", (group_id,))
    group = c.fetchone()

    c.execute("SELECT * FROM group_members WHERE group_id=?", (group_id,))
    members = c.fetchall()

    c.execute("SELECT username FROM users WHERE is_banned=0")
    users = c.fetchall()

    c.execute("SELECT username FROM users WHERE is_admin=1")
    cantremove = c.fetchall()
    
    # 在 Cantremove 中添加群主用户名
    for member in members:
        if member[2] == 'owner':
            cantremove.append((member[2],))
    # 如果是POST请求，处理表单提交的操作
    if request.method == 'POST':
        action = request.form.get('action')  # 获取操作类型
        member = escape(request.form.get('member'))  # 获取成员用户名
        if action == 'add_member':  # 添加成员到群组
            try:
                c.execute("INSERT INTO group_members (group_id, username, role) VALUES (?, ?, 'member')", (group_id, member))
                conn.commit()
                flash(f"用户 '{member}' 已被添加到群组 '{group_id}'")
            except sqlite3.IntegrityError:
                flash("用户已在该群组中或群组不存在")

        elif action == 'remove_member':  # 从群组移除成员
            # 判断 member 是否在 cantremove 中
            if member not in [user[0] for user in cantremove]:
                c.execute("DELETE FROM group_members WHERE group_id=? AND username=?", (group_id, member))
                conn.commit()
                flash(f"用户 '{member}' 已被从群组 '{group_id}' 移除")
            else :
                flash(f"用户 '{member}' 是管理员，无法移除")
        elif action == 'insertblacklist':  # 从群组移除成员
            if member not in [user[0] for user in cantremove]:
                c.execute("DELETE FROM group_members WHERE group_id=? AND username=?", (group_id, member))
                c.execute("INSERT INTO group_members (group_id, username, role) VALUES (?, ?, 'blacklist')", (group_id, member))
                conn.commit()
                flash(f"用户 '{member}' 已被从群组 '{group_id}' 移除并加入黑名单")
            else :
                flash(f"用户 '{member}' 是管理员，无法移除")
            
        elif action == 'promote_admin':  # 提升成员为管理员
            c.execute("UPDATE group_members SET role='admin' WHERE group_id=? AND username=?", (group_id, member))
            if c.rowcount == 0:
                flash("用户未在该群组中或群组不存在")
            else:
                conn.commit()
                flash(f"用户 '{member}' 已被提升为管理员")

        elif action == 'demote_admin':  # 降级管理员为普通成员
            c.execute("UPDATE group_members SET role='member' WHERE group_id=? AND username=?", (group_id, member))
            if c.rowcount == 0:
                flash("用户未在该群组中或群组不存在")
            else:
                conn.commit()
                flash(f"用户 '{member}' 已被降级为成员")

        conn.close()
        return redirect(url_for('group_settings', group_id=group_id))
    
    for member in members:
        if member[1] in [user[0] for user in users]:
            users.remove((member[1],))

    conn.close()
    return render_template('group_settings.html', group=group, members=members, group_id=group_id, users=users)


# 管理员路由
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session or not session.get('is_admin'):
        flash("你没有管理员权限")
        return redirect(url_for('index'))

    if request.method == 'POST':
        action = request.form.get('action')
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        if action == 'ban':
            target_user = escape(request.form.get('target_user'))
            if target_user == session['username']:
                flash("你不能禁止自己")
            else:
                # 将用户从所有群组中移除，并加入黑名单
                c.execute("UPDATE users SET is_banned=1 WHERE username=?", (target_user,))
                c.execute("DELETE FROM group_members WHERE username=?", (target_user,))
                c.execute("INSERT INTO group_members (group_id, username, role) SELECT group_id, ?, 'blacklist' FROM groups", (target_user,))
                conn.commit()
                flash(f"用户 '{target_user}' 已被封禁并加入所有群组的黑名单")
        
        conn.close()
        return redirect(url_for('admin'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # 获取所有用户（管理）
    c.execute("SELECT username FROM users WHERE is_admin=1")
    admin = c.fetchall()
    # 获取所有用户（未被封禁）
    c.execute("SELECT username FROM users WHERE is_banned=0 AND is_admin=0")
    users = c.fetchall()
    # 获取所有用户（被封禁）
    c.execute("SELECT username FROM users WHERE is_banned=1")
    baned = c.fetchall()
    # 获取所有群组（排除虚拟群组）
    c.execute("SELECT group_id, group_name FROM groups WHERE group_id != 9999")
    groups = c.fetchall()
    # 获取群组成员
    c.execute("SELECT group_id, username, role FROM group_members")
    members = c.fetchall()
    conn.close()

    return render_template('admin.html', users=users, baned = baned, groups=groups, members=members, admin = admin)

# 邀请用户加入群组路由
@app.route('/invite', methods=['POST'])
def invite():
    if 'username' not in session:
        return redirect(url_for('login'))

    inviter = session['username']
    group_id = request.form.get('group_id')
    invitee = escape(request.form.get('invitee'))

    try:
        group_id = int(group_id)
    except ValueError:
        flash("群号必须是数字")
        return redirect(url_for('admin'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # 检查邀请者是否是群组管理员或所有者
    c.execute("""
        SELECT role FROM group_members
        WHERE group_id=? AND username=?
    """, (group_id, inviter))
    role = c.fetchone()
    if role and role[0] in ['admin', 'owner']:
        # 检查被邀请者是否存在且未被封禁
        c.execute("SELECT is_banned FROM users WHERE username=?", (invitee,))
        user = c.fetchone()
        if not user:
            flash("被邀请的用户不存在")
        elif user[0]:
            flash("被邀请的用户已被封禁")
        else:
            # 检查邀请者是否为所有者或管理员
            # 确保邀请者没有超过管理员数量限制
            if role[0] == 'admin':
                # 检查是否超过管理员数量限制
                c.execute("SELECT COUNT(*) FROM group_members WHERE group_id=? AND role='admin'", (group_id,))
                admin_count = c.fetchone()[0]
                if admin_count >= MAX_ADMINS_PER_GROUP:
                    flash(f"群组 {group_id} 已达到最大管理员数量 ({MAX_ADMINS_PER_GROUP})")
                    conn.close()
                    return redirect(url_for('admin'))
            try:
                # 将邀请者添加为成员（默认为 'member')
                c.execute("INSERT INTO group_members (group_id, username, role) VALUES (?, ?, 'member')", (group_id, invitee))
                conn.commit()
                flash(f"用户 '{invitee}' 已被邀请加入群组 {group_id}")
            except sqlite3.IntegrityError:
                flash("用户已在该群组中或群组不存在")
    else:
        flash("你不是该群组的管理员或所有者")
    conn.close()
    return redirect(url_for('admin'))

# 服务器状态路由
@app.route('/server_status')
def server_status():
    if 'username' not in session or not session.get('is_admin'):
        flash("你没有访问服务器状态的权限")
        return redirect(url_for('index'))
    
    # 计算运行时间
    current_time = time.time()
    uptime_seconds = int(current_time - server_start_time)
    uptime_str = time.strftime('%H:%M:%S', time.gmtime(uptime_seconds))
    
    # 获取内存使用情况
    memory_info = psutil.virtual_memory()
    memory_used_mb = round(memory_info.used / (1024 * 1024), 2)
    
    # 获取CPU使用率
    cpu_usage = psutil.cpu_percent(interval=1)
    
    # 获取磁盘空间
    disk_info = psutil.disk_usage('/')
    disk_used_gb = round(disk_info.used / (1024 * 1024 * 1024), 2)
    
    return render_template('server_status.html',
                           uptime=uptime_str,
                           memory=memory_used_mb,
                           cpu_usage=cpu_usage,
                           disk_space=disk_used_gb)

# SocketIO 事件：加入群组
@socketio.on('join')
def handle_join(data):
    username = session.get('username')
    if not username:
        return

    group_id = data.get('group_id')
    if not isinstance(group_id, int):
        emit('error', {'msg': '无效的群组 ID'})
        return

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # 检查用户是否属于该群组且不在黑名单
    c.execute("""
        SELECT role FROM group_members
        WHERE group_id=? AND username=?
    """, (group_id, username))
    membership = c.fetchone()
    conn.close()

    if membership and group_id >= INITIAL_GROUP_ID and membership[0] != 'blacklist':
        join_room(str(group_id))
        # 发送历史消息
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("""
            SELECT username, message, strftime('%Y-%m-%d %H:%M:%S', timestamp)
            FROM messages
            WHERE group_id=?
            ORDER BY timestamp DESC
            LIMIT 10 OFFSET 0
        """, (group_id,))
        messages = c.fetchall()
        conn.close()
        for message in reversed(messages):
            timestamp = message[2]
            emit('message', {'msg': f"[{timestamp}] {message[0]}: {message[1]}"}, to=request.sid)
        emit('loaded_messages', {'count': len(messages)}, to=request.sid)
    else:
        emit('error', {'msg': '你没有权限加入该群组'})

# SocketIO 事件：发送消息
@socketio.on('message')
def handle_message(data):
    username = session.get('username')
    if not username:
        return

    group_id = data.get('group_id')
    msg = escape(data.get('msg', ''))

    if not isinstance(group_id, int) or not msg:
        emit('error', {'msg': '无效的群组 ID 或空消息'})
        return

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # 检查用户是否属于该群组且不在黑名单
    c.execute("""
        SELECT role FROM group_members
        WHERE group_id=? AND username=?
    """, (group_id, username))
    membership = c.fetchone()

    if membership and group_id >= INITIAL_GROUP_ID and membership[0] != 'blacklist':
        # 将消息存储到数据库
        c.execute("INSERT INTO messages (group_id, username, message) VALUES (?, ?, ?)",
                  (group_id, username, msg))
        last_id = c.lastrowid
        conn.commit()

        # 获取刚插入的消息的时间戳
        c.execute("SELECT strftime('%Y-%m-%d %H:%M:%S', timestamp) FROM messages WHERE id = ?", (last_id,))
        timestamp = c.fetchone()[0]
        conn.close()

        # 发送消息到房间
        emit('message', {'msg': f"[{timestamp}] {username}: {msg}"}, to=str(group_id))
    else:
        conn.close()
        emit('error', {'msg': '你没有权限发送消息到该群组'})

# SocketIO 事件：加载更多消息
@socketio.on('load_more_messages')
def handle_load_more_messages(data):
    username = session.get('username')
    if not username:
        return

    group_id = data.get('group_id')
    offset = data.get('offset', 0)

    if not isinstance(group_id, int) or not isinstance(offset, int):
        emit('error', {'msg': '无效的群组 ID 或偏移量'})
        return

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # 检查用户是否属于该群组且不在黑名单
    c.execute("""
        SELECT role FROM group_members
        WHERE group_id=? AND username=?
    """, (group_id, username))
    membership = c.fetchone()

    if membership and group_id >= INITIAL_GROUP_ID and membership[0] != 'blacklist':
        # 加载更多消息
        c.execute("""
            SELECT username, message, strftime('%Y-%m-%d %H:%M:%S', timestamp)
            FROM messages
            WHERE group_id=?
            ORDER BY timestamp DESC
            LIMIT 10 OFFSET ?
        """, (group_id, offset))
        messages = c.fetchall()
        conn.close()

        if messages:
            emit('loaded_more_messages', {'count': len(messages)}, to=request.sid)
            for message in reversed(messages):
                timestamp = message[2]
                emit('previous_message', {'msg': f"[{timestamp}] {message[0]}: {message[1]}"}, to=request.sid)
        else:
            emit('loaded_more_messages', {'count': 0}, to=request.sid)
    else:
        conn.close()
        emit('error', {'msg': '你没有权限加载该群组的消息'})

# SocketIO 事件：离开群组
@socketio.on('leave')
def handle_leave(data):
    username = session.get('username')
    if not username:
        return

    group_id = data.get('group_id')
    if not isinstance(group_id, int):
        emit('error', {'msg': '无效的群组 ID'})
        return

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # 检查用户是否属于该群组
    c.execute("SELECT role FROM group_members WHERE group_id=? AND username=?", (group_id, username))
    membership = c.fetchone()
    conn.close()

    if membership and group_id >= INITIAL_GROUP_ID and membership[0] != 'blacklist':
        leave_room(str(group_id))
        emit('message', {'msg': f'{username} 已离开群组'}, to=str(group_id))
    else:
        emit('error', {'msg': '你没有权限离开该群组'})

# 运行应用
if __name__ == '__main__':
    socketio.run(app, debug=True)