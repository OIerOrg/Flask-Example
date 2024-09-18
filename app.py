import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, join_room, leave_room, emit
import sqlite3
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
import time
import psutil
from flask_wtf import CSRFProtect
import logging

# 配置日志记录
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# 使用环境变量或随机生成的密钥
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

# 初始化 CSRF 保护
csrf = CSRFProtect(app)

socketio = SocketIO(app, manage_session=False)  # 不管理会话以避免与 Flask 会话冲突

DATABASE = 'chat.db'
INITIAL_GROUP_ID = 10000
MAX_ADMINS_PER_GROUP = 3

# 记录服务器启动时间
app.config['SERVER_START_TIME'] = time.time()

# 数据库初始化
def init_db():
    with app.app_context():
        conn = get_db()
        c = conn.cursor()
        # 创建用户表
        c.execute('''CREATE TABLE IF NOT EXISTS users
                    (username TEXT PRIMARY KEY,
                    password TEXT,
                    is_admin INTEGER,
                    is_banned INTEGER)''')
        # 创建群组表，使用自增主键
        c.execute('''CREATE TABLE IF NOT EXISTS groups
                    (group_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        logger.info("数据库初始化完成")
        # 不需要关闭连接，因为使用了 Flask 的 g
        

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()
        logger.info("数据库连接关闭")

with app.app_context():
    init_db()

# 辅助函数：检查用户是否在群组中，并排除特定角色
def is_user_in_group(group_id, username, role_exclude=None):
    conn = get_db()
    c = conn.cursor()
    query = "SELECT role FROM group_members WHERE group_id=? AND username=?"
    c.execute(query, (group_id, username))
    membership = c.fetchone()
    if membership:
        if role_exclude and membership['role'] in role_exclude:
            return False
        return True
    return False

# 辅助函数：获取群组所有者
def get_group_owner(group_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT username FROM group_members WHERE group_id=? AND role='owner'", (group_id,))
    owners = c.fetchall()
    return [owner['username'] for owner in owners]

# 辅助函数：检查用户是否是群组所有者或管理员
def is_group_owner_or_admin(group_id, username):
    if session.get('is_admin'):
        return True
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT role FROM group_members WHERE group_id=? AND username=?", (group_id, username))
    role = c.fetchone()
    return role and role['role'] in ['owner', 'admin']

# 用户注册路由
@app.route('/register', methods=['GET', 'POST'])
@csrf.exempt  # 如果使用 AJAX 进行注册，需要处理 CSRF
def register():
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = request.form['password']

        if not username or not password:
            flash("用户名和密码不能为空")
            return redirect(url_for('register'))

        conn = get_db()
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
            logger.info(f"新用户注册: {username}, 是否管理员: {is_admin}")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("用户名已存在")
            logger.warning(f"注册失败，用户名已存在: {username}")
            return redirect(url_for('register'))

    return render_template('register.html')

# 用户登录路由
@app.route('/', methods=['GET', 'POST'])
@csrf.exempt
def login():
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = request.form['password']

        if not username or not password:
            flash("用户名和密码不能为空")
            return redirect(url_for('login'))

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT password, is_admin, is_banned FROM users WHERE username=?", (username,))
        user = c.fetchone()

        if user:
            hashed_password, is_admin, is_banned = user
            if is_banned:
                flash("你已被封禁")
                logger.warning(f"封禁用户尝试登录: {username}")
                return redirect(url_for('login'))
            if check_password_hash(hashed_password, password):
                session['username'] = username
                session['is_admin'] = is_admin
                flash("登录成功")
                logger.info(f"用户登录: {username}")
                return redirect(url_for('index'))
            else:
                flash("用户名或密码错误")
                logger.warning(f"登录失败，密码错误: {username}")
                return redirect(url_for('login'))
        else:
            flash("用户名或密码错误")
            logger.warning(f"登录失败，用户名不存在: {username}")
            return redirect(url_for('login'))

    return render_template('login.html')

# 用户登出路由
@app.route('/logout')
def logout():
    username = session.get('username')
    session.clear()
    flash("已登出")
    logger.info(f"用户登出: {username}")
    return redirect(url_for('login'))

# 主页路由
@app.route('/index')
def index():
    if 'username' in session:
        conn = get_db()
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

        conn = get_db()
        c = conn.cursor()
        try:
            # 使用自增主键，避免手动管理群号
            c.execute("INSERT INTO groups (group_name) VALUES (?)", (group_name,))
            group_id = c.lastrowid
            # 将创建者加入群组并设为所有者
            c.execute("INSERT INTO group_members (group_id, username, role) VALUES (?, ?, 'owner')",
                      (group_id, username))
            conn.commit()
            flash(f"群组 '{group_name}' 创建成功，群号为 {group_id}")
            logger.info(f"群组创建: {group_name} (ID: {group_id}) by {username}")
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash("群组名称已存在")
            logger.warning(f"群组创建失败，名称已存在: {group_name}")
            return redirect(url_for('create_group'))

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
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM groups WHERE group_id=?", (group_id,))
        group = c.fetchone()

        if group and group_id >= INITIAL_GROUP_ID:
            # 检查是否在黑名单
            if not is_group_owner_or_admin(group_id, username):
                c.execute("SELECT * FROM group_members WHERE group_id=? AND username=? AND role='blacklist'",
                          (group_id, username))
                blacklist_entry = c.fetchone()
                if blacklist_entry:
                    flash("你已被加入黑名单，无法加入该群组")
                    logger.warning(f"黑名单用户尝试加入群组: {username} -> {group_id}")
                    return redirect(url_for('join_group'))

            try:
                c.execute("INSERT INTO group_members (group_id, username, role) VALUES (?, ?, 'member')",
                          (group_id, username))
                conn.commit()
                flash(f"成功加入群组 '{group['group_name']}'")
                logger.info(f"用户加入群组: {username} -> {group_id}")
                return redirect(url_for('index'))
            except sqlite3.IntegrityError:
                flash("你已在该群组中")
                logger.warning(f"用户已在群组中: {username} -> {group_id}")
                return redirect(url_for('join_group'))
        else:
            flash("群组不存在")
            logger.warning(f"尝试加入不存在的群组: {group_id}")
            return redirect(url_for('join_group'))

    return render_template('join_group.html')

# 聊天路由
@app.route('/chat/<int:group_id>')
def chat(group_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db()
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
            logger.warning(f"黑名单用户尝试访问群组: {username} -> {group_id}")
            return redirect(url_for('index'))
        return render_template('chat.html', username=username, group_id=group_id, group_name=group_name, canedit=is_group_owner_or_admin(group_id, session['username']))
    else:
        flash("你没有权限访问该群组")
        logger.warning(f"用户无权限访问群组: {username} -> {group_id}")
        return redirect(url_for('index'))

# 群组设置路由
@app.route('/chat/<int:group_id>/settings', methods=['GET', 'POST'])
def group_settings(group_id):
    # 检查用户是否有权限访问此页面
    if 'username' not in session or not is_group_owner_or_admin(group_id, session['username']):
        flash("你没有权限访问这个页面")
        logger.warning(f"无权限访问群组设置: {session.get('username')} -> {group_id}")
        return redirect(url_for('index'))

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM groups WHERE group_id=?", (group_id,))
    group = c.fetchone()

    c.execute("SELECT * FROM group_members WHERE group_id=?", (group_id,))
    members = c.fetchall()

    c.execute("SELECT username FROM users WHERE is_banned=0")
    users = [row['username'] for row in c.fetchall()]

    c.execute("SELECT username FROM users WHERE is_admin=1")
    cantremove = [row['username'] for row in c.fetchall()]

    # 在 cantremove 中添加群主用户名
    for member in members:
        if member['role'] == 'owner':
            cantremove.append(member['username'])

    # 如果是POST请求，处理表单提交的操作
    if request.method == 'POST':
        action = request.form.get('action')  # 获取操作类型
        member = escape(request.form.get('member'))  # 获取成员用户名
        if not member:
            flash("请选择一个用户")
            return redirect(url_for('group_settings', group_id=group_id))

        if action == 'add_member':  # 添加成员到群组
            try:
                c.execute("INSERT INTO group_members (group_id, username, role) VALUES (?, ?, 'member')", (group_id, member))
                conn.commit()
                flash(f"用户 '{member}' 已被添加到群组 '{group['group_name']}'")
                logger.info(f"用户添加到群组: {member} -> {group_id}")
            except sqlite3.IntegrityError:
                flash("用户已在该群组中或群组不存在")
                logger.warning(f"添加用户失败，用户已在群组中或群组不存在: {member} -> {group_id}")

        elif action == 'remove_member':  # 从群组移除成员
            if member not in cantremove:
                c.execute("DELETE FROM group_members WHERE group_id=? AND username=?", (group_id, member))
                conn.commit()
                flash(f"用户 '{member}' 已被从群组 '{group['group_name']}' 移除")
                logger.info(f"用户从群组移除: {member} -> {group_id}")
            else:
                flash(f"用户 '{member}' 是管理员，无法移除")
                logger.warning(f"尝试移除管理员用户: {member} -> {group_id}")

        elif action == 'insertblacklist':  # 将成员加入黑名单
            if member not in cantremove:
                c.execute("DELETE FROM group_members WHERE group_id=? AND username=?", (group_id, member))
                c.execute("INSERT INTO group_members (group_id, username, role) VALUES (?, ?, 'blacklist')", (group_id, member))
                conn.commit()
                flash(f"用户 '{member}' 已被从群组 '{group['group_name']}' 移除并加入黑名单")
                logger.info(f"用户加入黑名单: {member} -> {group_id}")
            else:
                flash(f"用户 '{member}' 是管理员，无法移除")
                logger.warning(f"尝试将管理员用户加入黑名单: {member} -> {group_id}")

        elif action == 'promote_admin':  # 提升成员为管理员
            # 检查管理员数量
            c.execute("SELECT COUNT(*) as admin_count FROM group_members WHERE group_id=? AND role='admin'", (group_id,))
            admin_count = c.fetchone()['admin_count']
            if admin_count >= MAX_ADMINS_PER_GROUP:
                flash(f"群组 {group_id} 已达到最大管理员数量 ({MAX_ADMINS_PER_GROUP})")
                logger.warning(f"提升管理员失败，群组管理员数量已达上限: {group_id}")
            else:
                c.execute("UPDATE group_members SET role='admin' WHERE group_id=? AND username=?", (group_id, member))
                if c.rowcount == 0:
                    flash("用户未在该群组中或群组不存在")
                    logger.warning(f"提升管理员失败，用户未在群组中: {member} -> {group_id}")
                else:
                    conn.commit()
                    flash(f"用户 '{member}' 已被提升为管理员")
                    logger.info(f"用户提升为管理员: {member} -> {group_id}")

        elif action == 'demote_admin':  # 降级管理员为普通成员
            c.execute("UPDATE group_members SET role='member' WHERE group_id=? AND username=?", (group_id, member))
            if c.rowcount == 0:
                flash("用户未在该群组中或群组不存在")
                logger.warning(f"降级管理员失败，用户未在群组中: {member} -> {group_id}")
            else:
                conn.commit()
                flash(f"用户 '{member}' 已被降级为成员")
                logger.info(f"用户降级为成员: {member} -> {group_id}")

        conn.close()
        return redirect(url_for('group_settings', group_id=group_id))

    # 获取可添加的用户列表
    current_members = [member['username'] for member in members]
    available_users = [user for user in users if user not in current_members]

    return render_template('group_settings.html', group=group, members=members, group_id=group_id, users=available_users)

# 管理员路由
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session or not session.get('is_admin'):
        flash("你没有管理员权限")
        logger.warning(f"非管理员用户尝试访问管理员页面: {session.get('username')}")
        return redirect(url_for('index'))

    if request.method == 'POST':
        action = request.form.get('action')
        conn = get_db()
        c = conn.cursor()

        if action == 'ban':
            target_user = escape(request.form.get('target_user'))
            if target_user == session['username']:
                flash("你不能禁止自己")
                logger.warning(f"管理员尝试禁止自己: {target_user}")
            else:
                # 将用户标记为被封禁
                c.execute("UPDATE users SET is_banned=1 WHERE username=?", (target_user,))
                # 从所有群组中移除用户
                c.execute("DELETE FROM group_members WHERE username=?", (target_user,))
                # 将用户加入所有群组的黑名单
                c.execute("INSERT INTO group_members (group_id, username, role) SELECT group_id, ?, 'blacklist' FROM groups WHERE group_id != 9999", (target_user,))
                conn.commit()
                flash(f"用户 '{target_user}' 已被封禁并加入所有群组的黑名单")
                logger.info(f"用户被封禁: {target_user}")

        conn.close()
        return redirect(url_for('admin'))

    conn = get_db()
    c = conn.cursor()
    # 获取所有管理员用户
    c.execute("SELECT username FROM users WHERE is_admin=1")
    admin_users = [row['username'] for row in c.fetchall()]
    # 获取所有未被封禁的普通用户
    c.execute("SELECT username FROM users WHERE is_banned=0 AND is_admin=0")
    users = [row['username'] for row in c.fetchall()]
    # 获取所有被封禁的用户
    c.execute("SELECT username FROM users WHERE is_banned=1")
    baned = [row['username'] for row in c.fetchall()]
    # 获取所有群组（排除虚拟群组）
    c.execute("SELECT group_id, group_name FROM groups WHERE group_id != 9999")
    groups = c.fetchall()
    # 获取群组成员
    c.execute("SELECT group_id, username, role FROM group_members")
    members = c.fetchall()
    conn.close()

    return render_template('admin.html', users=users, baned=baned, groups=groups, members=members, admin=admin_users)

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

    conn = get_db()
    c = conn.cursor()
    # 检查邀请者是否是群组管理员或所有者
    c.execute("""
        SELECT role FROM group_members
        WHERE group_id=? AND username=?
    """, (group_id, inviter))
    role = c.fetchone()
    if role and role['role'] in ['admin', 'owner']:
        # 检查被邀请者是否存在且未被封禁
        c.execute("SELECT is_banned FROM users WHERE username=?", (invitee,))
        user = c.fetchone()
        if not user:
            flash("被邀请的用户不存在")
            logger.warning(f"邀请失败，被邀请用户不存在: {invitee}")
        elif user['is_banned']:
            flash("被邀请的用户已被封禁")
            logger.warning(f"邀请失败，被邀请用户已被封禁: {invitee}")
        else:
            # 检查邀请者是否为所有者或管理员
            # 确保邀请者没有超过管理员数量限制
            if role['role'] == 'admin':
                # 检查是否超过管理员数量限制
                c.execute("SELECT COUNT(*) as admin_count FROM group_members WHERE group_id=? AND role='admin'", (group_id,))
                admin_count = c.fetchone()['admin_count']
                if admin_count >= MAX_ADMINS_PER_GROUP:
                    flash(f"群组 {group_id} 已达到最大管理员数量 ({MAX_ADMINS_PER_GROUP})")
                    logger.warning(f"邀请失败，群组管理员数量已达上限: {group_id}")
                    conn.close()
                    return redirect(url_for('admin'))
            try:
                # 将被邀请者添加为成员（默认为 'member')
                c.execute("INSERT INTO group_members (group_id, username, role) VALUES (?, ?, 'member')", (group_id, invitee))
                conn.commit()
                flash(f"用户 '{invitee}' 已被邀请加入群组 {group_id}")
                logger.info(f"用户被邀请加入群组: {invitee} -> {group_id}")
            except sqlite3.IntegrityError:
                flash("用户已在该群组中或群组不存在")
                logger.warning(f"邀请用户失败，用户已在群组中或群组不存在: {invitee} -> {group_id}")
    else:
        flash("你不是该群组的管理员或所有者")
        logger.warning(f"邀请失败，邀请者不是群组管理员或所有者: {inviter} -> {group_id}")
    conn.close()
    return redirect(url_for('admin'))

# 服务器状态路由
@app.route('/server_status')
def server_status():
    if 'username' not in session or not session.get('is_admin'):
        flash("你没有访问服务器状态的权限")
        logger.warning(f"非管理员用户尝试访问服务器状态: {session.get('username')}")
        return redirect(url_for('index'))

    # 计算运行时间
    current_time = time.time()
    uptime_seconds = int(current_time - app.config['SERVER_START_TIME'])
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
        emit('error', {'msg': '未登录'})
        return

    group_id = data.get('group_id')
    if not isinstance(group_id, int):
        emit('error', {'msg': '无效的群组 ID'})
        return

    if is_user_in_group(group_id, username, role_exclude=['blacklist']):
        join_room(str(group_id))
        logger.info(f"用户加入房间: {username} -> {group_id}")
        # 发送历史消息
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            SELECT username, message, strftime('%Y-%m-%d %H:%M:%S', timestamp) as timestamp
            FROM messages
            WHERE group_id=?
            ORDER BY timestamp DESC
            LIMIT 10
        """, (group_id,))
        messages = c.fetchall()
        conn.close()
        for message in reversed(messages):
            timestamp = message['timestamp']
            emit('message', {'msg': f"[{timestamp}] {message['username']}: {message['message']}"}, to=request.sid)
        emit('loaded_messages', {'count': len(messages)}, to=request.sid)
    else:
        emit('error', {'msg': '你没有权限加入该群组'})
        logger.warning(f"用户尝试加入无权限的群组: {username} -> {group_id}")

# SocketIO 事件：发送消息
@socketio.on('message')
def handle_message(data):
    username = session.get('username')
    if not username:
        emit('error', {'msg': '未登录'})
        return

    group_id = data.get('group_id')
    msg = escape(data.get('msg', ''))

    if not isinstance(group_id, int) or not msg:
        emit('error', {'msg': '无效的群组 ID 或空消息'})
        return

    if is_user_in_group(group_id, username, role_exclude=['blacklist']):
        conn = get_db()
        c = conn.cursor()
        # 将消息存储到数据库
        c.execute("INSERT INTO messages (group_id, username, message) VALUES (?, ?, ?)",
                  (group_id, username, msg))
        last_id = c.lastrowid
        conn.commit()

        # 获取刚插入的消息的时间戳
        c.execute("SELECT strftime('%Y-%m-%d %H:%M:%S', timestamp) as timestamp FROM messages WHERE id = ?", (last_id,))
        timestamp = c.fetchone()['timestamp']
        conn.close()

        # 发送消息到房间
        emit('message', {'msg': f"[{timestamp}] {username}: {msg}"}, to=str(group_id))
        logger.info(f"用户发送消息: {username} -> {group_id}: {msg}")
    else:
        emit('error', {'msg': '你没有权限发送消息到该群组'})
        logger.warning(f"用户尝试发送消息到无权限群组: {username} -> {group_id}")

# SocketIO 事件：加载更多消息
@socketio.on('load_more_messages')
def handle_load_more_messages(data):
    username = session.get('username')
    if not username:
        emit('error', {'msg': '未登录'})
        return

    group_id = data.get('group_id')
    offset = data.get('offset', 0)

    if not isinstance(group_id, int) or not isinstance(offset, int):
        emit('error', {'msg': '无效的群组 ID 或偏移量'})
        return

    if is_user_in_group(group_id, username, role_exclude=['blacklist']):
        conn = get_db()
        c = conn.cursor()
        # 加载更多消息
        c.execute("""
            SELECT username, message, strftime('%Y-%m-%d %H:%M:%S', timestamp) as timestamp
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
                timestamp = message['timestamp']
                emit('previous_message', {'msg': f"[{timestamp}] {message['username']}: {message['message']}"}, to=request.sid)
            logger.info(f"加载更多消息: {username} -> {group_id}, 偏移量: {offset}")
        else:
            emit('loaded_more_messages', {'count': 0}, to=request.sid)
            logger.info(f"没有更多消息可加载: {username} -> {group_id}, 偏移量: {offset}")
    else:
        emit('error', {'msg': '你没有权限加载该群组的消息'})
        logger.warning(f"用户尝试加载无权限群组的消息: {username} -> {group_id}")

# SocketIO 事件：离开群组
@socketio.on('leave')
def handle_leave(data):
    username = session.get('username')
    if not username:
        emit('error', {'msg': '未登录'})
        return

    group_id = data.get('group_id')
    if not isinstance(group_id, int):
        emit('error', {'msg': '无效的群组 ID'})
        return

    if is_user_in_group(group_id, username, role_exclude=['blacklist']):
        leave_room(str(group_id))
        emit('message', {'msg': f'{username} 已离开群组'}, to=str(group_id))
        logger.info(f"用户离开群组: {username} -> {group_id}")
    else:
        emit('error', {'msg': '你没有权限离开该群组'})
        logger.warning(f"用户尝试离开无权限群组: {username} -> {group_id}")

# 运行应用
if __name__ == '__main__':
    socketio.run(app, debug=True)
