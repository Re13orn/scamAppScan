import os
import time
import json
from loguru import logger
from utils.config import *
from utils.apkAnalyzer import APKAnalyzer
from utils.apkShellDetector import APKShellDetector
from utils.reportGenerator import ReportGenerator


# 初始化日志配置
logger.remove()
logger.add(lambda msg: print(msg), level=LOG_LEVEL)

def main():
    """
    主函数：分析所有 APK 文件并导出结果。
    """
    all_results = []
    apk_files = [os.path.join(APK_DIRECTORY, f) for f in os.listdir(APK_DIRECTORY) if f.endswith('.apk')]
    for apk_file in apk_files:
        apk_name = os.path.basename(apk_file)
        print(G1, f"[+] 开始分析: {apk_name}", W)
        # analyzer 实例一个 APKAnalyzer
        analyzer = APKAnalyzer(apk_file)
        # analyze_apk 默认分析方案，采用
        results = analyzer.analyze_apk()
        if results:
            result_json = json.dumps(results, indent=4)
            print(G, result_json, W)
            all_results.extend(results)
        else:
            # analyze_apk 分析失败，则采用 analyze_apk_by_apktool 方案
            print(G1, f"[+] androguard 分析失败，开始采用 aapt 和 apktool 进行分析", W)
            results = analyzer.analyze_apk_by_apktool()
            if results:
                result_json = json.dumps(results, indent=4)
                print(G, result_json, W)
                all_results.extend(results)
            else:
                # 最后确实都没有分析出来，分析加固信息
                print(R, f"[-] 未发现信息: {analyzer.apk_name}", W)
                shellDetect = APKShellDetector(apk_file,SHELLFEATURE)
                shellDetect.detect()
                
                # 匹配看是否历史手动分析过
                apk_hash = analyzer.calculate_hash()
                for hash, domain in HASH_PATTERNS.items():
                    if apk_hash == hash:
                        print(O, f"[*] 经过历史恶意APK库Hash匹配: {analyzer.apk_name} 命中，恶意域名为: {domain}，哈希为: {hash}", W)

    # 保存最后的结果导出 csv 报告文件
    if all_results:
        os.makedirs(REPORT_DIR, exist_ok=True)
        filename = os.path.join(REPORT_DIR, f"{time.strftime('%Y%m%d_%H%M%S')}_results.csv")
        report_generator = ReportGenerator(all_results, filename)
        report_generator.export_to_csv()

if __name__ == "__main__":
    main()