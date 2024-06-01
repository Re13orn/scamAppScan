from flask import Flask
from config import Config
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix


"""
应用工厂
"""

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # 初始化 CSRF 保护
    csrf = CSRFProtect(app)

    @app.after_request
    def set_security_headers(response):
        response.headers["X-FRAME-OPTIONS"] = "SAMEORIGIN"
        return response

    """
    注册蓝图
    """

    from .blueprints.main import main_bp as main_blueprint
    app.register_blueprint(main_blueprint)

    from .blueprints.api import api_bp as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    # csrf.exempt(apis_blueprint)  # 对 apis 蓝图禁用CSRF保护

    # 配置 ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    return app