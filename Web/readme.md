# ScamAppScan Web

ScamAppScan 的Web服务。前端采用MobSF的上传模版，后端采用Flask。可以点击或者拖拽APK 文件到服务端进行分析。

![Example](../docs/web_example_1.jpg)

## 安装第三方模块
```shell
python3 -m pip install -r requirement.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### 启动
```shell
# 调试模式
.venv/bin/flask run -p 8000 -h 0.0.0.0 --debug

# 生产模式
nohup flask run -p 80 -h 0.0.0.0 &
```
**结果展示**

![Example](../docs/web_example_2.jpg)