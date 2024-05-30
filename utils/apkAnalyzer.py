import os
import shutil
import zipfile
import hashlib
from androguard.misc import AnalyzeAPK
from loguru import logger
from config import *


class APKAnalyzer:
    """
    APK 文件分析器类，负责APK文件的解析和信息抽取。
    """

    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)
        self.apk_info = {}
        self.extract_to = TEMP_DIRECTORY

    def get_application_name(self, apk):
        """
        获取并返回 APK 的应用名称。
        """
        return apk.get_app_name()

    def extract_bundle_file(self):
        """
        从 APK 中提取 assets/index.android.bundle 文件。
        """
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                bundle_file = 'assets/index.android.bundle'
                if bundle_file in zip_ref.namelist():
                    zip_ref.extract(bundle_file, self.extract_to)
                    return os.path.join(self.extract_to, bundle_file)
        except zipfile.BadZipFile:
            logger.error(f"Failed to open {self.apk_path}.")

    def analyze_content(self, content, patterns):
        """
        分析 APK 内容，匹配定义的规则，并尝试处理可能的越界问题。
        """
        matches = []
        for pattern, accuracy in patterns.items():
            start = 0
            while True:
                start = content.find(pattern, start)
                if start == -1:
                    break
                context_start = max(0, start - CONTEXT_RANGE)
                context_end = min(len(content), start + len(pattern) + CONTEXT_RANGE)
                limited_context = content[context_start:context_end]
                matches.append({
                    "match_rule": pattern,
                    "match_value": limited_context,
                    "accuracy": accuracy
                })
                start += len(pattern)
        return matches

    def analyze_apk(self, patterns):
        """
        分析指定的 APK 文件，并妥善处理所有异常。
        """

        print(G1, f"[+] 开始分析: {self.apk_name}", W)
        results = []
        apk_hash = self.calculate_hash()
        try:
            apk, dex_list, analysis = AnalyzeAPK(self.apk_path)
            app_name = self.get_application_name(apk)
            package_name = apk.get_package()
            # 获取版本代码和版本名称
            version_code = apk.get_androidversion_code()
            appversion = apk.get_androidversion_name()

            self.apk_info = {
                "apk_name": self.apk_name,
                "app_version": appversion,
                "hash": apk_hash,
                "Package_name": package_name,
                "app_name": app_name
            }

            for idx, dex in enumerate(dex_list, start=1):
                try:
                    dex_strings = '\n'.join(dex.get_strings())
                    matches = self.analyze_content(dex_strings, patterns)
                    results.extend([{**match, **self.apk_info} for match in matches])
                except Exception as e:
                    logger.error(f"Error analyzing DEX {idx}: {str(e)}")

            bundle_path = self.extract_bundle_file()
            if bundle_path:
                with open(bundle_path, 'r', encoding='utf-8') as file:
                    bundle_content = file.read()
                    matches = self.analyze_content(bundle_content, patterns)
                    for match in matches:
                        match.update(self.apk_info)
                        results.append(match)
        except Exception as e:
            logger.error(f"Failed to analyze {self.apk_name}: {str(e)}")
        finally:
            shutil.rmtree(self.extract_to, ignore_errors=True)
            return results

    def calculate_hash(self):
        """
        计算 APK 文件的 MD5 哈希值。
        """
        hash_md5 = hashlib.md5()
        with open(self.apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
