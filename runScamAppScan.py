import os
import time
import json
from config import *
from loguru import logger
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
    combined_patterns = {**PATH_PATTERNS, **DOMAIN_PATTERNS}
    all_results = []
    apk_files = [os.path.join(APK_DIRECTORY, f) for f in os.listdir(APK_DIRECTORY) if f.endswith('.apk')]
    for apk_file in apk_files:
        analyzer = APKAnalyzer(apk_file)
        results = analyzer.analyze_apk(combined_patterns)
        if results:
            result_json = json.dumps(results, indent=4)
            print(G, result_json, W)
            all_results.extend(results)
        else:
            print(R, f"[-] 未发现信息: {analyzer.apk_name}", W)
            apk_hash = analyzer.calculate_hash()
            for hash, domain in HASH_PATTERNS.items():
                if apk_hash == hash:
                    print(O, f"[*] 经过历史恶意APK库Hash匹配: {analyzer.apk_name} 命中，恶意域名为: {domain}，哈希为: {hash}", W)
            
            shellDetect = APKShellDetector(apk_file)
            shellDetect.detect()

    if all_results:
        os.makedirs(REPORT_DIR, exist_ok=True)
        filename = os.path.join(REPORT_DIR, time.strftime("%Y%m%d_%H%M%S") + "_results.csv")
        report_generator = ReportGenerator(all_results, filename)
        report_generator.export_to_csv()

if __name__ == "__main__":
    main()