import os
import re
import shutil
import zipfile
import hashlib
import subprocess
from config import *
from tqdm import tqdm
from queue import Queue
from pathlib import Path
from loguru import logger
from androguard.misc import AnalyzeAPK
from concurrent.futures import ThreadPoolExecutor, as_completed


class APKAnalyzer:
    """
    APK 文件分析类，负责APK文件的解析和信息抽取。
    """

    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)
        self.apk_info = {}
        self.extract_to = TEMP_DIRECTORY # 临时文件目录
        self.patterns = {**PATH_PATTERNS, **DOMAIN_PATTERNS}
        self.context_range = CONTEXT_RANGE
        self.aapt = AAPT
        self.apktool = APKTOOL

    def analyze_apk(self):
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
                    matches = self.analyze_content(dex_strings)
                    results.extend([{**match, **self.apk_info} for match in matches])
                except Exception as e:
                    logger.error(f"Error analyzing DEX {idx}: {str(e)}")

            bundle_path = self.extract_bundle_file()
            if bundle_path:
                with open(bundle_path, 'r', encoding='utf-8') as file:
                    bundle_content = file.read()
                    matches = self.analyze_content(bundle_content)
                    for match in matches:
                        match.update(self.apk_info)
                        results.append(match)
        except Exception as e:
            logger.error(f"Failed to analyze {self.apk_name}: {str(e)}")
        finally:
            shutil.rmtree(self.extract_to, ignore_errors=True)
            return results
    
    def analyze_apk_by_apktool(self):
        """
        备用方案，当androguard库分析失败，采用 apktool工具反编译APK文件，需要环境有java的环境。
        """
        results = []
        cmd = ["java", "-jar", self.apktool, "d", "-f", self.apk_path, "-o", self.extract_to]
        try:
            self.apk_info = self.extract_apk_info_by_aapt()
            cmd_result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if cmd_result.returncode != 0:
                    raise RuntimeError(f"apktool failed to unpack APK: {cmd_result.stderr}")
            else:
                file_queue = Queue()
                # 将临时目录的文件名写入到队列中
                file_paths = (str(file_path) for file_path in Path(self.extract_to).rglob('*') if file_path.is_file())
                for file_path in file_paths:
                    file_queue.put(file_path)
                total_files = file_queue.qsize()
                with tqdm(total=total_files,desc="Scanning files",unit="file") as pbar:
                    with ThreadPoolExecutor(max_workers=20) as executor:
                        futures = []
                        while not file_queue.empty():
                            file_path = file_queue.get()
                            futures.append(executor.submit(self.scan_file, file_path))

                        for future in as_completed(futures):
                            matches = future.result()
                            if matches:
                                results.extend([{**match, **self.apk_info} for match in matches])
                            pbar.update(1)
        except Exception as e:
            logger.error(f"Failed to analyze {self.apk_name}: {str(e)} with apktools")
        finally:
            shutil.rmtree(self.extract_to, ignore_errors=True)
            return results

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
    
    def extract_apk_info_by_aapt(self):
        """
        备用方案，当androguard库分析失败，采用 aapt 解析apk的基本信息
        """

        cmd = [self.aapt, "dump", "badging", self.apk_path]

        # 使用正则表达式匹配应用程序标签、版本号和包名
        RLABEL = re.compile(r"application-label:'([^']+)'")
        VERSION = re.compile(r"versionName='([^']+)'")
        PACKAGE = re.compile(r"package: name='([^']+)'")
        
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            application_label = re.search(r"application-label:'([^']+)'", output).group(1) if re.search(r"application-label:'([^']+)'", output) else ""
            version = re.search(r"versionName='([^']+)'", output).group(1) if re.search(r"versionName='([^']+)'", output) else ""
            package_name = re.search(r"package: name='([^']+)'", output).group(1) if re.search(r"package: name='([^']+)'", output) else ""

            apk_info = {
                "apk_name": self.apk_name,
                "app_version": version,
                "hash": self.calculate_hash(),
                "Package_name": package_name,
                "app_name": application_label
            }
            return apk_info

        except subprocess.CalledProcessError as e:
            logger.error(f"error executing aapt: {e.output}")
            return {}

    def analyze_content(self, content):
        """
        分析 APK 内容，匹配定义的规则，并尝试处理可能的越界问题。
        """
        matches = []
        for pattern, accuracy in self.patterns.items():
            start = 0
            while True:
                start = content.find(pattern, start)
                if start == -1:
                    break
                context_start = max(0, start - self.context_range)
                context_end = min(len(content), start + len(pattern) + self.context_range)
                limited_context = content[context_start:context_end]
                matches.append({
                    "match_rule": pattern,
                    "match_value": limited_context,
                    "accuracy": accuracy
                })
                start += len(pattern)
        return matches
        
    def scan_file(self, file_path):
        matches = []
        with open(file_path,'r',encoding='utf-8',errors='ignore') as file:
            file_content = file.read()
            matches = self.analyze_content(file_content)
        return matches 

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
        # 考虑备用方案
        results = analyzer.analyze_apk_by_apktool(combined_patterns, CONTEXT_RANGE)
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