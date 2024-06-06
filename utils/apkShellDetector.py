import os
import zipfile

class APKShellDetector:
    """
    APK 加壳加固分析类，负责分析APK采用哪种加固方案
    """

    def __init__(self, apk_path, shell_feature):
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)
        self.shell_features = shell_feature

    def read_zip_files(self):
        """
        打开APK文件并读取其内容列表
        """
        with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
            return zip_ref.namelist()

    def match_shell(self, name_list):
        """
        匹配APK文件中的文件名与加固特征库
        """
        flags = set()
        for file_name in name_list:
            for shell, desc in self.shell_features.items():
                if shell in file_name:
                    flags.add(desc)
        return list(flags)

    def detect(self):
        """
        检测APK是否使用了加固技术，并打印结果
        """
        shell = "unknow"
        name_list = self.read_zip_files()
        flags = self.match_shell(name_list)
        if flags:
            shell = ', '.join(flags)
            print('\033[0;33m', f"[*] 经过加壳特征库匹配，{self.apk_name} 加壳方案为: {shell}.", '\033[0m')
        return shell

# 使用示例
if __name__ == '__main__':

    # 加固特征库，完整内容可从配置文件 config.py 导入
    SHELLFEATURE = {
    "libchaosvmp.so": "娜迦",
    "libddog.so": "娜迦",
    "libfdog.so": "娜迦",
    "libjiagu.so": "360 加固",
    "libexec.so": "爱加密"
    # ...
    }
    detector = APKShellDetector("test.apk", SHELLFEATURE)
    detector.detect()