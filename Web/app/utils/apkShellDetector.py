import zipfile
import os
# from flask import current_app


class APKShellDetector:
    # 加固特征库
    # shell_features = SHELLFEATURE
    # shell_features = current_app.config['SHELLFEATURE']

    def __init__(self, apk_path, shell_features):
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)
        self.shell_features = shell_features

    def read_zip_files(self):
        """打开APK文件并读取其内容列表"""
        with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
            return zip_ref.namelist()

    def match_shell(self, name_list):
        """匹配APK文件中的文件名与加固特征库"""
        flags = set()
        for file_name in name_list:
            for shell, desc in self.shell_features.items():
                if shell in file_name:
                    flags.add(desc)
        return list(flags)

    def detect(self):
        shell = "unknow"
        """检测APK是否使用了加固技术，并打印结果"""
        name_list = self.read_zip_files()
        flags = self.match_shell(name_list)
        if flags:
            shell = ', '.join(flags)
            print(f"[*] 经过加壳特征库匹配，{self.apk_name} 加壳方案为: {shell}.")
        return shell

# 使用示例
if __name__ == '__main__':
    detector = APKShellDetector("FDFA25B954480A44D2632B0AA2FD2A2F.apk")
    detector.detect()
