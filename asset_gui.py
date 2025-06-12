import os
import sys
import re
import ipaddress
from urllib.parse import urlparse
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFileDialog, QTextEdit, QCheckBox,
    QLineEdit, QTabWidget, QTextBrowser
)
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt

def is_ip_address(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except:
        return False

def expand_spec(spec: str) -> set[str]:
    ips = set()
    spec = spec.replace('，', ',')
    parts = re.split(r'[\s,]+', spec.strip())
    for part in parts:
        if not part:
            continue
        if '/' in part:
            try:
                net = ipaddress.IPv4Network(part, strict=False)
                ips.update(str(ip) for ip in net)
            except:
                pass
        elif '-' in part:
            try:
                start, end = part.split('-', 1)
                # 形如 192.168.1.10-20
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', start) and re.match(r'^\d+$', end):
                    prefix, start_oct = start.rsplit('.', 1)
                    for i in range(int(start_oct), int(end) + 1):
                        ips.add(f"{prefix}.{i}")
                else:
                    start_ip = ipaddress.IPv4Address(start)
                    end_ip = ipaddress.IPv4Address(end)
                    for ip_int in range(int(start_ip), int(end_ip) + 1):
                        ips.add(str(ipaddress.IPv4Address(ip_int)))
            except:
                pass
        else:
            try:
                ips.add(str(ipaddress.IPv4Address(part)))
            except:
                pass
    return ips

def extract_main_domain(host: str) -> str:
    """
    去掉端口和路径后，如果是 IP 直接返回；
    否则只保留第一个点之后的所有内容。
    """
    host = host.split(':', 1)[0].split('/', 1)[0]
    if is_ip_address(host):
        return host
    if '.' in host:
        # 去掉最左侧的子域名，保留第一个点之后的部分
        return host.split('.', 1)[1]
    return host

def extract_assets(lines: list[str]):
    ip_set = set()
    domain_set = set()
    subdomain_set = set()
    url_set = set()

    for line in lines:
        line = line.strip().replace('，', ',')
        if not line or line.startswith('#'):
            continue

        # 纯 IP/CIDR/范围/逗号
        if re.match(r'^\d+\.\d+\.\d+\.\d+(\/\d{1,2})?$', line) or '-' in line or ',' in line:
            ip_set.update(expand_spec(line))
            continue

        # 确保有协议，便于 parsing
        if not line.startswith(('http://', 'https://')):
            line = 'http://' + line

        try:
            parsed = urlparse(line)
            host = parsed.hostname or ''
            url_set.add(line)
            if is_ip_address(host):
                ip_set.add(host)
            else:
                main_domain = extract_main_domain(host)
                domain_set.add(main_domain)
                if host != main_domain:
                    subdomain_set.add(host)
        except Exception as e:
            print(f"[!] 无法解析: {line} - {e}")

    return sorted(ip_set), sorted(domain_set), sorted(subdomain_set), sorted(url_set)

class AssetSplitterGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("资产分练工具 V1.0")
        self.resize(1000, 700)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        big_font = QFont("Microsoft YaHei", 13)
        code_font = QFont("Consolas", 12)
        self.setFont(big_font)
        self.setWindowIcon(QIcon.fromTheme("folder"))

        # 文件选择
        file_layout = QHBoxLayout()
        file_label = QLabel("选择资产文件:")
        self.file_path = QLineEdit("未选择文件")
        self.file_path.setMinimumWidth(400)
        browse_button = QPushButton("选择文件")
        browse_button.setFixedWidth(120)
        browse_button.clicked.connect(self.load_file)
        for w in (file_label, self.file_path, browse_button):
            w.setFont(big_font)
        file_layout.addWidget(file_label)
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(browse_button)
        layout.addLayout(file_layout)

        # 手动输入
        manual_label = QLabel("手动输入资产（每行一个 IP/URL）:")
        manual_label.setFont(big_font)
        self.manual_input = QTextEdit()
        self.manual_input.setFont(code_font)
        self.manual_input.setPlaceholderText("请输入资产（每行一个 IP/URL）")
        self.manual_input.setMinimumHeight(130)
        layout.addWidget(manual_label)
        layout.addWidget(self.manual_input)

        # 提取项
        check_layout = QHBoxLayout()
        check_label = QLabel("提取项:")
        self.chk_ip = QCheckBox("提取 IP")
        self.chk_url = QCheckBox("提取 URL")
        self.chk_domain = QCheckBox("主域名")
        self.chk_subdomain = QCheckBox("子域名")
        for chk in (self.chk_ip, self.chk_url, self.chk_domain, self.chk_subdomain):
            chk.setFont(big_font)
        self.chk_ip.setChecked(True)
        self.chk_url.setChecked(True)
        self.chk_domain.setChecked(True)
        self.chk_subdomain.setChecked(True)
        check_layout.addWidget(check_label)
        check_layout.addWidget(self.chk_ip)
        check_layout.addWidget(self.chk_url)
        check_layout.addWidget(self.chk_domain)
        check_layout.addWidget(self.chk_subdomain)
        layout.addLayout(check_layout)

        # 输出目录
        output_layout = QHBoxLayout()
        self.output_path = QLineEdit()
        self.output_path.setPlaceholderText("请选择输出目录")
        self.output_path.setMinimumWidth(400)
        choose_output = QPushButton("输出路径")
        choose_output.setFixedWidth(120)
        choose_output.clicked.connect(self.set_output_folder)
        for w in (self.output_path, choose_output):
            w.setFont(big_font)
        output_layout.addWidget(self.output_path)
        output_layout.addWidget(choose_output)
        layout.addLayout(output_layout)

        # 按钮
        btn_layout = QHBoxLayout()
        run_btn = QPushButton("开始分练")
        reset_btn = QPushButton("重置")
        run_btn.setFixedWidth(140)
        reset_btn.setFixedWidth(100)
        run_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        reset_btn.setStyleSheet("background-color: #f44336; color: white;")
        run_btn.clicked.connect(self.run_analysis)
        reset_btn.clicked.connect(self.reset_all)
        for w in (run_btn, reset_btn):
            w.setFont(big_font)
        btn_layout.addWidget(run_btn)
        btn_layout.addWidget(reset_btn)
        layout.addLayout(btn_layout)

        # 结果标签页
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Microsoft YaHei", 12))
        self.ip_tab = QTextBrowser()
        self.url_tab = QTextBrowser()
        self.domain_tab = QTextBrowser()
        self.sub_tab = QTextBrowser()
        for tab in (self.ip_tab, self.url_tab, self.domain_tab, self.sub_tab):
            tab.setFont(code_font)
        self.tabs.addTab(self.ip_tab, "IP 结果")
        self.tabs.addTab(self.url_tab, "URL 结果")
        self.tabs.addTab(self.domain_tab, "主域名")
        self.tabs.addTab(self.sub_tab, "子域名")
        layout.addWidget(self.tabs)

        self.setLayout(layout)

    def load_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "选择资产文件", "", "Text Files (*.txt);;CSV Files (*.csv)")
        if file:
            self.file_path.setText(file)
            with open(file, 'r', encoding='utf-8') as f:
                self.manual_input.setPlainText(f.read())

    def set_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "选择输出目录")
        if folder:
            self.output_path.setText(folder)

    def run_analysis(self):
        lines = self.manual_input.toPlainText().splitlines()
        ips, domains, subdomains, urls = extract_assets(lines)

        # 清空并更新
        for tab in (self.ip_tab, self.url_tab, self.domain_tab, self.sub_tab):
            tab.setUpdatesEnabled(False)
            tab.clear()

        if self.chk_ip.isChecked():
            self.ip_tab.setPlainText('\n'.join(ips))
        if self.chk_url.isChecked():
            self.url_tab.setPlainText('\n'.join(urls))
        if self.chk_domain.isChecked():
            self.domain_tab.setPlainText('\n'.join(domains))
        if self.chk_subdomain.isChecked():
            self.sub_tab.setPlainText('\n'.join(subdomains))

        for tab in (self.ip_tab, self.url_tab, self.domain_tab, self.sub_tab):
            tab.setUpdatesEnabled(True)

        # 写文件
        out_dir = self.output_path.text().strip()
        if out_dir:
            out_file = os.path.join(out_dir, "分练结果.txt")
            with open(out_file, 'w', encoding='utf-8') as f:
                if self.chk_ip.isChecked():
                    f.write("【IP】\n" + '\n'.join(ips) + "\n\n")
                if self.chk_domain.isChecked():
                    f.write("【主域名】\n" + '\n'.join(domains) + "\n\n")
                if self.chk_subdomain.isChecked():
                    f.write("【子域名】\n" + '\n'.join(subdomains) + "\n\n")
                if self.chk_url.isChecked():
                    f.write("【URL】\n" + '\n'.join(urls) + "\n")

    def reset_all(self):
        self.manual_input.clear()
        self.output_path.clear()
        self.ip_tab.clear()
        self.url_tab.clear()
        self.domain_tab.clear()
        self.sub_tab.clear()
        self.file_path.setText("未选择文件")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = AssetSplitterGUI()
    gui.show()
    sys.exit(app.exec())
