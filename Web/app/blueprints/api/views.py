import os
import json
import hashlib
from . import api_bp
from loguru import logger
from app.utils.apkAnalyzer import APKAnalyzer
from app.utils.apkShellDetector import APKShellDetector
from app.utils.scamAppScanConfig import *
from flask import request, jsonify, current_app
from werkzeug.utils import secure_filename

from concurrent.futures import ThreadPoolExecutor
# 线程池所能同时进行的最大数量
pool_executor = ThreadPoolExecutor(max_workers=200)

# 初始化日志配置
logger.remove()
logger.add(lambda msg: print(msg), level=LOG_LEVEL)


def allowed_file(filename):
    """
    判断上传文件是否是.apk文件
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'apk'}

def compute_hash(file_path):
    """
    哈希计算
    """
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


@api_bp.route('/upload', methods=['POST'])
def upload():
    """
    APK 上传处理函数，上传后保存并重命名为“文件哈希+'.apk'”。
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part', 'status_code': 400}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file', 'status_code': 400}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not supported', 'status_code': 400}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER_APK'], filename)

    try:
        file.save(file_path)
        file_hash = compute_hash(file_path)
        file_hash_path = os.path.join(current_app.config['UPLOAD_FOLDER_APK'], file_hash + ".apk")
        os.rename(file_path, file_hash_path)
        return jsonify({
            "analyzer": "api/submitrunscan",
            "status": "success",
            "status_code":200,
            "hash": file_hash,
            "scan_type": "apk",
            "file_name": filename
        }), 200
    except Exception as e:
        return jsonify({'error': str(e), 'status_code': 500}), 500


@api_bp.route('/submitrunscan/<string:apk_hash_filename>/', methods=['GET'])
def submitrunscan(apk_hash_filename):
    """
    提交分析APK请求函数，采用线程实现异步执行。
    """
    UPLOAD_PATH = os.path.join(current_app.config['UPLOAD_FOLDER'])
    combined_patterns = {**PATH_PATTERNS, **DOMAIN_PATTERNS}
    # 交给线程去处理耗时任务
    pool_executor.submit(runApkAnalysis,apk_hash_filename,UPLOAD_PATH,combined_patterns,True)

    return jsonify({
                "status_code":200,
                "message":"Analysis started! Please wait or check recent scans after sometime.",
                "hash":apk_hash_filename
            }), 200

def runApkAnalysis(apk_hash_filename,UPLOAD_PATH,combined_patterns,flag=True):
    """
    APK 分析函数
    flag 用于判断是否是刷新分析，默认True
    """
    print("查看是否历史分析...")
    
    json_filename_path = os.path.join(UPLOAD_PATH,"json",apk_hash_filename+".json")
    if flag and os.path.exists(json_filename_path):
        print(f"Json 数据已存在：{json_filename_path}")
    else:
        print("新APK, 开始分析...")
        apk_file = os.path.join(UPLOAD_PATH, "apk", apk_hash_filename+".apk")
        try:
            shellDetect = APKShellDetector(apk_file, SHELLFEATURE)
            shell = shellDetect.detect() or "unknown"
        except:
            shell = "unknown"
        isScamApp = "unknow"
        all_results = []
        status_code = 400

        try:
            analyzer = APKAnalyzer(apk_file, TEMP_DIRECTORY)
            results = analyzer.analyze_apk(combined_patterns)
            
            history = history_apk_hash_compare(apk_hash_filename)

            if results:
                status_code = 200
                if results[0].get("match_rule"):
                    isScamApp = "true"
                    result_json = json.dumps(results,indent=4)
                    print(G,result_json,W)
                    all_results.extend(results)
                else:
                    result_json = json.dumps(results, indent=4)
                    print(G, result_json, W)
                    all_results.extend(results)
                    print(R, f"[-] 可以进行分析但是未发现信息: {analyzer.apk_name}", W)
            else:
                status_code = 400
                
        except Exception as e:
            status_code = 500
            logger.error(f"runApkAnalysis error:{e}")

        json_content = {
                        "status_code": status_code,
                        "isScamApp" : isScamApp,
                        "result" : json.dumps(all_results, indent=4),
                        "history" : history,
                        "shell" : shell
                    }
        with open(json_filename_path, "w+", encoding="utf-8") as f:
            json.dump(json_content,f,ensure_ascii=False,indent=4)

        print(f"Json 数据保存到{json_filename_path}")

def history_apk_hash_compare(apk_hash):
    """
    有些APK无法分析，但是确认是恶意程序，因此从配置文件中读取并匹配
    """
    history = []
    for hash, domain in HASH_PATTERNS.items():
        if apk_hash == hash:
            history.append((hash,domain))
            print(O, f"[*] 经过历史恶意APK库Hash匹配: {apk_hash} 命中，恶意域名为: {domain}，哈希为: {hash}", W)
    return history


@api_bp.route('/getscanresult/<string:apk_hash_filename>/', methods=['GET'])
def getscanresult(apk_hash_filename):
    """
    获取分析报告，前端在提交分析请求后会每隔3秒请求一次
    """
    json_result_path = os.path.join(current_app.config['UPLOAD_FOLDER_JSON'],apk_hash_filename + ".json")

    if os.path.exists(json_result_path):
        # 打开文件进行读取
        with open(json_result_path, 'r', encoding='utf-8') as f:
            # 使用 json.load() 方法从文件中读取数据
            data = json.load(f)
        return data
    else:
        state_code = 404
        message = "Analyzing, please wait."

        return jsonify({
                    "status_code": state_code,
                    "message": message,
                }), 200

@api_bp.route('/refreshresult/', methods=['GET'])
def refreshresult():
    """
    刷新JSON文件，用于在更新规则后，将状态`"isScamApp": "unknow"`重新分析
    """
    UPLOAD_PATH = os.path.join(current_app.config['UPLOAD_FOLDER'])
    UPLOAD_FOLDER_JSON = os.path.join(current_app.config['UPLOAD_FOLDER_JSON'])
    json_files = [os.path.join(UPLOAD_FOLDER_JSON, f) for f in os.listdir(UPLOAD_FOLDER_JSON) if f.endswith('.json')]
    print(json_files)

    apk_hash_filename_list = []
    # 遍历列表中的每个JSON文件
    for json_file in json_files:
        # 读取 JSON 文件内容
        with open(json_file,'r',encoding='utf-8') as file:
            data = json.load(file)
        
        # 检查 'isScamApp' 字段是否为 'unknow'
        if data.get('isScamApp','').lower() == 'unknow':
            # 从文件路径中提取文件名（不含扩展名）
            apk_hash_filename = os.path.splitext(os.path.basename(json_file))[0]
            apk_hash_filename_list.append(apk_hash_filename)
        
    if apk_hash_filename_list:
        for apk_hash_filename_ in apk_hash_filename_list:
            combined_patterns = {**PATH_PATTERNS, **DOMAIN_PATTERNS}
            # 交给线程去处理耗时任务
            pool_executor.submit(runApkAnalysis,apk_hash_filename_,UPLOAD_PATH,combined_patterns,False)


    # # 交给线程去处理耗时任务
    # pool_executor.submit(runApkAnalysis,UPLOAD_PATH,combined_patterns)

    return jsonify({
                "status_code":200,
                "message":"Analysis started! Please wait or check recent scans after sometime.",
            }), 200


