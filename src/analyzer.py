import re
import json
import logging
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SyslogAnalyzer:
    def __init__(self):
        self.events_by_severity = defaultdict(set)
        self.all_ips = set()

    def categorize_message(self, message: str) -> str:
        """Определяет уровень опасности на основе ключевых слов"""
        msg_lower = message.lower()
        if "failed" in msg_lower or "invalid" in msg_lower:
            return "критический"
        elif "sudo" in msg_lower or "root" in msg_lower:
            return "высокий"
        elif "accepted" in msg_lower or "session opened" in msg_lower:
            return "информационный"
        return "средний"

    def parse_line(self, line: str) -> dict:
        """Разбирает строку регуляркой на составные части"""
        pattern = r"(?P<timestamp>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>[\w\d\[\]]+):\s+(?P<message>.*)"
        match = re.search(pattern, line)
        if match:
            return match.groupdict()
        return {}

    def process_file(self, file_path: str):
        """Читает файл построчно через yield"""
        logging.info(f"Начало обработки лога: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                data = self.parse_line(line.strip())
                if data:
                    msg = data['message']
                    severity = self.categorize_message(msg)
                    self.events_by_severity[severity].add(msg)
                    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', msg)
                    self.all_ips.update(ips)

                    yield data

    def save_json_report(self, output_path: str):
        """Сохраняет результаты анализа в JSON файл"""
        report = {
            "summary": {
                severity: len(messages) for severity, messages in self.events_by_severity.items()
            },
            "suspicious_ips": list(self.all_ips)
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        logging.info(f"Отчет успешно сохранен в {output_path}")




analyzer = SyslogAnalyzer()

count = 0
for event in analyzer.process_file('data/syslog.log'):
    print(f"Успешно распарсено: {event['timestamp']} -> {event['process']}")
    count += 1
    if count >= 5:
        break

analyzer.save_json_report("data/report.json")