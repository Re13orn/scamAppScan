from flask import Flask
from utils.config import Config
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

"""
应用工厂
"""

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config['MAX_CONTENT_LENGTH'] = 300 * 1024 * 1024  # 限制为300MB

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

    csrf.exempt(api_blueprint)  # 对 apis 蓝图禁用CSRF保护

    # 配置 ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    return app