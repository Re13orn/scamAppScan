from flask import Blueprint, request, abort, current_app

api_bp = Blueprint('api', __name__, url_prefix='/api')
from . import views


# @api_bp.before_request
# def verify_token():
#     # 从请求头获取token
#     token = request.headers.get('Token')
#     # 检查token是否存在且是否匹配预设的值
#     if not token or token != current_app.config['API_TOKEN']:
#         # 如果不匹配，返回401未授权状态
#         abort(401, description="Invalid or missing token")