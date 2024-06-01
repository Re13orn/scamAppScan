from flask import render_template
from . import main_bp


# 主页，要判断登录状态
@main_bp.route('/')
def index():
    return render_template('index.html')