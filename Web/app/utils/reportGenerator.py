import csv
import json


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
        print(f"[*] Scan finished, Results exported to {self.filename}")

    def export_to_json(self):
        """
        导出分析结果到 JSON 文件。
        """
        with open(self.filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(self.results, jsonfile, indent=4, ensure_ascii=False)
        print(f"[*] Scan finished, Results exported to {self.filename}")