# app/routes.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import current_user, login_user, logout_user, login_required
from . import db
from .models import User, List, Memo
from werkzeug.security import check_password_hash, generate_password_hash
from urllib.parse import urlparse as url_parse
import uuid
from .forms import LoginForm, RegistrationForm, ListForm, MemoForm  # 新增导入

main = Blueprint('main', __name__)

# 用户认证路由

@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return redirect(url_for('main.register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('注册成功，请登录')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('无效的用户名或密码')
            return redirect(url_for('main.login'))
        login_user(user)
        flash(f'欢迎, {user.username}！')
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    return render_template('login.html', form=form)

@main.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.login'))

# 列表管理路由
@main.route('/')
@main.route('/index')
@login_required
def index():
    my_lists = List.query.filter_by(user_id=current_user.id).all()
    shared_lists = current_user.shared_lists.all()
    form = ListForm()
    return render_template('index.html', my_lists=my_lists, shared_lists=shared_lists, form=form)


@main.route('/create_list', methods=['POST'])
@login_required
def create_list():
    form = ListForm()
    if form.validate_on_submit():
        list_name = form.list_name.data
        new_list = List(name=list_name, owner=current_user)
        db.session.add(new_list)
        db.session.commit()
        flash('列表创建成功')
        return redirect(url_for('main.index'))
    flash('列表名称不能为空')
    return redirect(url_for('main.index'))

@main.route('/delete_list/<int:list_id>', methods=['POST'])
@login_required
def delete_list(list_id):
    lst = List.query.get_or_404(list_id)
    if lst.owner != current_user:
        abort(403)  # 仅所有者可以删除列表
    db.session.delete(lst)
    db.session.commit()
    flash('列表已删除')
    return redirect(url_for('main.index'))

# 备忘录管理路由

@main.route('/list/<int:list_id>', methods=['GET', 'POST'])
@login_required
def view_list(list_id):
    lst = List.query.get_or_404(list_id)
    if lst.owner != current_user and lst not in current_user.shared_lists:
        abort(403)
    memos = Memo.query.filter_by(list_id=lst.id).order_by(Memo.timestamp.desc()).all()
    form = MemoForm()
    empty_form = EmptyForm()
    return render_template('list.html', list=lst, memos=memos, form=form, empty_form=empty_form)


@main.route('/list/<int:list_id>/create_memo', methods=['POST'])
@login_required
def create_memo(list_id):
    lst = List.query.get_or_404(list_id)
    if lst.owner != current_user and lst not in current_user.shared_lists:
        abort(403)
    form = MemoForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        memo = Memo(title=title, content=content, list=lst)
        db.session.add(memo)
        db.session.commit()
        flash('备忘录创建成功')
        return redirect(url_for('main.view_list', list_id=list_id))
    else:
        # 如果验证失败，可以将错误信息显示在模板中
        flash('备忘录创建失败：' + '; '.join([f"{field}: {error[0]}" for field, error in form.errors.items()]))
        return redirect(url_for('main.view_list', list_id=list_id))
@main.route('/memo/<int:memo_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_memo(memo_id):
    memo = Memo.query.get_or_404(memo_id)
    lst = memo.list
    if lst.owner != current_user and lst not in current_user.shared_lists:
        abort(403)
    form = MemoForm(obj=memo)
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        if not title:
            flash('备忘录标题不能为空')
            return redirect(url_for('main.edit_memo', memo_id=memo_id))
        memo.title = title
        memo.content = content
        db.session.commit()
        flash('备忘录已更新')
        return redirect(url_for('main.view_list', list_id=lst.id))
    return render_template('memo_edit.html', form=form, memo=memo)
# app/routes.py
from .forms import EmptyForm  # 导入 EmptyForm

@main.route('/memo/<int:memo_id>')
@login_required
def view_memo(memo_id):
    memo = Memo.query.get_or_404(memo_id)
    lst = memo.list
    if lst.owner != current_user and lst not in current_user.shared_lists:
        abort(403)
    form = EmptyForm()
    return render_template('memo_view.html', memo=memo, form=form)


@main.route('/memo/<int:memo_id>/delete', methods=['POST'])
@login_required
def delete_memo(memo_id):
    memo = Memo.query.get_or_404(memo_id)
    lst = memo.list
    if lst.owner != current_user and lst not in current_user.shared_lists:
        abort(403)
    db.session.delete(memo)
    db.session.commit()
    flash('备忘录已删除')
    return redirect(url_for('main.view_list', list_id=lst.id))

# 共享列表路由
@main.route('/share_list/<int:list_id>', methods=['POST'])
@login_required
def share_list(list_id):
    lst = List.query.get_or_404(list_id)
    if lst.owner != current_user:
        abort(403)
    if not lst.is_shared:
        lst.is_shared = True
        lst.generate_share_link()
        db.session.commit()

    # 修改分享链接
    base_url = 'https://zjx-kimi.github.io/memorandum/shared/'
    share_url = f"{base_url}{lst.share_link}"
    
    flash(f'分享链接已生成: {share_url}')
    return redirect(url_for('main.view_list', list_id=list_id))



@main.route('/shared/<share_link>')
@login_required
def join_shared_list(share_link):
    lst = List.query.filter_by(share_link=share_link, is_shared=True).first_or_404()
    if lst.owner == current_user or lst in current_user.shared_lists:
        flash('你已经加入该共享列表')
        return redirect(url_for('main.view_list', list_id=lst.id))
    current_user.shared_lists.append(lst)
    db.session.commit()
    flash('成功加入共享列表')
    return redirect(url_for('main.view_list', list_id=lst.id))
