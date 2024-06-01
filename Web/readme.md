# asset scan 安装手册

开发环境使用的是 Python 3.9.13
pip 更新源用的是 https://pypi.tuna.tsinghua.edu.cn/simple

### 配置虚拟环境

```shell
# 配置虚拟环境
python3 -m venv .venv
# 激活虚拟环境
source .venv/bin/activate
# 查看 python 是否已经更换
which python3

# 退出虚拟环境可以使用如下命令：
deactivate
```

### 安装第三方模块
```shell
python3 -m pip install -r requirement.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

```

### 启动
```shell
# 调试模式
.venv/bin/flask run -p 8000 -h 0.0.0.0 --debug

# 可以使用 gunicorn 启动
# -w WORKERS, --workers=WORKERS 设置工作进程数。建议服务器每一个核心可以设置2-4个。
# -b BIND, --bind=BIND 设定服务需要绑定的端口。建议使用HOST:PORT。
# 指定进程和端口号： -w: 表示进程（worker）。 -b：表示绑定ip地址和端口号（bind）。 -D: 后台运行
python3 -m gunicorn --preload -w 4 -b 127.0.0.1:8000 -D --access-logfile access.log --error-logfile error.log run:app

python3 -m gunicorn --preload -w 4 -b 0.0.0.0:8000 -D --access-logfile access.log --error-logfile error.log run:app
```
