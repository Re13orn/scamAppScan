import os
import shutil
import zipfile
import hashlib
from androguard.misc import AnalyzeAPK
from loguru import logger


class APKAnalyzer:
    """
    APK 文件分析类，负责APK文件的解析和信息抽取。
    """

    def __init__(self, apk_path, tmp_dictory):
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)
        self.apk_info = {}
        self.extract_to = tmp_dictory # 临时文件目录

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

    def analyze_content(self, content, patterns, context_range):
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
                context_start = max(0, start - context_range)
                context_end = min(len(content), start + len(pattern) + context_range)
                limited_context = content[context_start:context_end]
                matches.append({
                    "match_rule": pattern,
                    "match_value": limited_context,
                    "accuracy": accuracy
                })
                start += len(pattern)
        return matches

    def analyze_apk(self, patterns,context_range):
        """
        分析指定的 APK 文件，并处理异常。
        """
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
                    matches = self.analyze_content(dex_strings, patterns, context_range)
                    results.extend([{**match, **self.apk_info} for match in matches])
                except Exception as e:
                    logger.error(f"Error analyzing DEX {idx}: {str(e)}")

            bundle_path = self.extract_bundle_file()
            if bundle_path:
                with open(bundle_path, 'r', encoding='utf-8') as file:
                    bundle_content = file.read()
                    matches = self.analyze_content(bundle_content, patterns,context_range)
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

# 使用示例
if __name__ == "__main__":
    from loguru import logger
    logger.remove() # androguard 库调试日志太多，所以移除原来的日志等级，重新设定日志输出等级
    logger.add(lambda msg: print(msg), level="ERROR")

    PATH_PATTERNS = { # 恶意路径指纹规则，完整可从配置文件 config.py 导入
    "aid=10&wt=1&os=1&key=": 100,
    "ciyu.php?ciyu=": 100,
    "getkey?e=": 100,
    "getmnemonic?type=": 100,
    "c=9&app=1&client=2&o=": 100,
    "ciyu=": 100
    #...
    }
    DOMAIN_PATTERNS = { # 恶意域名指纹规则，完整可从配置文件 config.py 导入
    "tokengoodns.com":100,
    "intoken.tw":100,
    "imtoke.net":100,
    "geqianff386.xyz":100,
    "qianff364.xyz":100,
    "geqianxz383.xyz":100,
    "qianxz364.xyz":100,
    "geqianxz385.xyz":100,
    "qianxz361.xyz":100
    #...
    }

    CONTEXT_RANGE = 100 # 匹配上下文100个字符，config.py 已设定

    TEMP_DIRECTORY = os.path.join(os.path.dirname(__file__), "temp_extracted") # 设定临时文件存储目录，config.py 已设定
    combined_patterns = {**PATH_PATTERNS, **DOMAIN_PATTERNS} # 合并所有规则
    
    # 传入APK路径
    analyzer = APKAnalyzer("test.apk", TEMP_DIRECTORY)
    # 获取结果
    results = analyzer.analyze_apk(combined_patterns, CONTEXT_RANGE)
    import json
    if results:
            result_json = json.dumps(results, indent=4)
            print(result_json)
    else:
        print("Not found.")
    
    """
    若匹配到，结果示例：
    [
        {
            "match_rule": "aid=10&wt=1&os=1&key=",
            "match_value": "tpResponseCode\nhttpStream\nhttpUrl\nhttponly\nhttps\nhttps:\nhttps://\nhttps://api.funnel.rocks/api/trust?aid=10&wt=1&os=1&key=\nhu\nhub\nhub is required\nhughes\nhyatt\nhybridSignTest\nhypot\nhyundai\ni\ni386\ni686\niArgs\niClassToInstanti",
            "accuracy": 100,
            "apk_name": "test.apk",
            "app_version": "24.9.11",
            "hash": "d4489ba7cd892142a098b6be04c7907c",
            "Package_name": "im.token.app",
            "app_name": "imToken"
        }
    ]
    """