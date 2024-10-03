# run.py
from app import create_app, db
from app.models import User, List, Memo

app = create_app()

# 在应用程序上下文中创建数据库表
with app.app_context():
    db.create_all()

# 使得 Flask shell 可以访问模型
@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'List': List, 'Memo': Memo}

if __name__ == '__main__':
    app.run(debug=True)
