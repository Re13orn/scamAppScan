import os
import csv


class ReportGenerator:
    """
    报告生成器类，负责导出分析结果到 CSV 文件。
    """

    def __init__(self, results, filename='results.csv'):
        self.results = results
        self.filename = filename

    def export_to_csv(self):
        """
        导出分析结果到 CSV 文件。
        """
        fieldnames = ['apk_name', 'hash', 'Package_name', 'app_name', 'match_rule', 'app_version', 'match_rule', 'match_value', 'accuracy']
        with open(self.filename, 'w+', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for result in self.results:
                writer.writerow(result)
        print('\033[0;33m', f"[*] Scan finished, Results exported to {self.filename}", '\033[0m')

# 使用示例
if __name__ == '__main__':
    import time
    result = [
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
    # 报告存放目录，config.py 已设定
    REPORT_DIR = os.path.join(os.path.dirname(__file__), "reporttmp")
    os.makedirs(REPORT_DIR, exist_ok=True)

    filename = os.path.join(REPORT_DIR, time.strftime("%Y%m%d_%H%M%S") + "_results.csv")
    report_generator = ReportGenerator(result, filename)
    report_generator.export_to_csv()