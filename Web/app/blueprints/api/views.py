from . import api_bp
import hashlib
from flask import Flask, request, jsonify, current_app
from werkzeug.utils import secure_filename

import os
import time
import json
from app.utils.config import *
from loguru import logger
from app.utils.apkAnalyzer import APKAnalyzer
from app.utils.apkShellDetector import APKShellDetector
from app.utils.reportGenerator import ReportGenerator


# 初始化日志配置
logger.remove()
logger.add(lambda msg: print(msg), level=LOG_LEVEL)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'apk'}

def compute_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()



@api_bp.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part', 'status_code': 400}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file', 'status_code': 400}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not supported', 'status_code': 400}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

    try:
        file.save(file_path)
        file_hash = compute_hash(file_path)
        file_hash_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_hash + ".apk")
        os.rename(file_path, file_hash_path)
        return jsonify({
            "analyzer": "api/runscan",
            "status": "success",
            "status_code":200,
            "hash": file_hash,
            "scan_type": "apk",
            "file_name": filename
        }), 200
    except Exception as e:
        return jsonify({'error': str(e), 'status_code': 500}), 500


@api_bp.route('/runscan/<string:apk_hash_filename>/', methods=['GET'])
def runscan(apk_hash_filename):
    combined_patterns = {**PATH_PATTERNS, **DOMAIN_PATTERNS}
    all_results = []
    apk_file = os.path.join(current_app.config['UPLOAD_FOLDER'], apk_hash_filename+".apk")

    try:
        print(G1, f"[+] 开始分析: {os.path.basename(apk_file)}", W)
        analyzer = APKAnalyzer(apk_file, TEMP_DIRECTORY)
        results = analyzer.analyze_apk(combined_patterns)
        isScamApp = "unknow"
        history = []
        shell = ""

        if results:
            if results[0].get("match_rule"):
                isScamApp = "true"
                result_json = json.dumps(results, indent=4)
                print(G, result_json, W)
                all_results.extend(results)
            else:
                isScamApp = "false"
                result_json = json.dumps(results, indent=4)
                print(G, result_json, W)
                all_results.extend(results)
                print(R, f"[-] 可以进行分析但是未发现信息: {analyzer.apk_name}", W)
                apk_hash = analyzer.calculate_hash()
                for hash, domain in HASH_PATTERNS.items():
                    if apk_hash == hash:
                        history.append((hash,domain))
                        print(O, f"[*] 经过历史恶意APK库Hash匹配: {analyzer.apk_name} 命中，恶意域名为: {domain}，哈希为: {hash}", W)

                shellDetect = APKShellDetector(apk_file, SHELLFEATURE)
                shell = shellDetect.detect() 
        else:
            print(R, f"[-] 无法分析且未发现信息: {analyzer.apk_name}", W)
            apk_hash = analyzer.calculate_hash()
            for hash, domain in HASH_PATTERNS.items():
                if apk_hash == hash:
                    history.append((hash,domain))
                    print(O, f"[*] 经过历史恶意APK库Hash匹配: {analyzer.apk_name} 命中，恶意域名为: {domain}，哈希为: {hash}", W)
            
            shellDetect = APKShellDetector(apk_file, SHELLFEATURE)
            shell = shellDetect.detect()
            if shell == "":
                    shell = "unknown"


        if all_results:
            if all_results[0].get("match_rule"):
                return jsonify({
                    "status_code":200,
                    "isScamApp" : isScamApp,
                    "result" : json.dumps(all_results, indent=4),
                    "history" : history,
                    "shell" : shell
                }), 200
            else:
                
                return jsonify({
                "status_code":400,
                "isScamApp" : "unknow",
                "result" : json.dumps(all_results, indent=4),
                "history" : history,
                "shell" : shell
            }), 200
        else:
            return jsonify({
                "status_code":400,
                "isScamApp" : isScamApp,
                "result" : json.dumps(all_results, indent=4),
                "history" : history,
                "shell" : shell
            }), 200

    except Exception as e:
        shellDetect = APKShellDetector(apk_file, SHELLFEATURE)
        shell = shellDetect.detect()
        if shell == "":
            shell = "unknown"
        return jsonify({'error': str(e), 
                        "isScamApp" :"unknown",
                        "shell" : shell,
                        'status_code': 500
                        }), 500


# def tmp():
#     combined_patterns = {**PATH_PATTERNS, **DOMAIN_PATTERNS}
#     all_results = []
#     apk_file = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

#     analyzer = APKAnalyzer(apk_file)
#     results = analyzer.analyze_apk(combined_patterns)
#     if results:
#         result_json = json.dumps(results, indent=4)
#         print(G, result_json, W)
#         all_results.extend(results)
#     else:
#         print(R, f"[-] 未发现信息: {analyzer.apk_name}", W)
#         apk_hash = analyzer.calculate_hash()
#         for hash, domain in HASH_PATTERNS.items():
#             if apk_hash == hash:
#                 print(O, f"[*] 经过历史恶意APK库Hash匹配: {analyzer.apk_name} 命中，恶意域名为: {domain}，哈希为: {hash}", W)
        
#         shellDetect = APKShellDetector(apk_file, SHELLFEATURE)
#         shellDetect.detect()

#     if all_results:
#         os.makedirs(REPORT_DIR, exist_ok=True)
#         filename = os.path.join(REPORT_DIR, time.strftime("%Y%m%d_%H%M%S") + "_results.csv")
#         report_generator = ReportGenerator(all_results, filename)
#         report_generator.export_to_csv()