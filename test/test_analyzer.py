import pytest
from src.analyzer import SyslogAnalyzer

@pytest.fixture
def analyzer():
    """Фикстура, которая создает чистый объект анализатора перед каждым тестом"""
    return SyslogAnalyzer()


def test_categorize_message_critical(analyzer):
    """Проверяем, что сообщения со словом 'failed' падают в критические"""
    msg = "sshd[1234]: Failed password for invalid user admin"
    assert analyzer.categorize_message(msg) == "критический"


def test_categorize_message_high(analyzer):
    """Проверяем, что юзер sudo поднимает уровень до высокого"""
    msg = "mishk : TTY=pts/0 ; PWD=/home/mishk ; USER=root ; COMMAND=/bin/su"
    assert analyzer.categorize_message(msg) == "высокий"


def test_parse_line_valid(analyzer):
    """Проверяем, разбирает ли регулярка стандартную строку лога"""
    line = "Jun 17 09:39:45 Mickle375 sshd[5269]: Accepted password for mishk"
    parsed = analyzer.parse_line(line)

    assert parsed != {}
    assert parsed["host"] == "Mickle375"
    assert parsed["process"] == "sshd[5269]"
    assert "Accepted password" in parsed["message"]


def test_ip_extraction(analyzer):
    """Проверяем, вытаскиваются ли IP-адреса из текста лога"""
    line = "Jun 17 09:39:45 Mickle375 sshd[5269]: Connection from 192.168.1.50"
    data = analyzer.parse_line(line)
    assert data != {}
    import re
    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data['message'])
    assert "192.168.1.50" in ips