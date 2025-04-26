import sys
import base64
import hashlib
import zlib
import re
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QLabel,
                             QLineEdit, QTextEdit, QPushButton, QVBoxLayout,
                             QHBoxLayout, QFrame, QMessageBox, QStatusBar)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor


class CompactDecryptApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.setupStyles()

    def initUI(self):
        # 主窗口设置
        self.setWindowTitle('weevely流量解码_By_An0ma1')
        self.setWindowIcon(QIcon('lock.png'))
        self.resize(800, 600)

        # 中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 15, 20, 15)
        main_layout.setSpacing(15)

        # 输入区域
        input_group = QWidget()
        input_layout = QVBoxLayout(input_group)
        input_layout.setContentsMargins(0, 0, 0, 0)

        # 密码输入
        password_layout = QHBoxLayout()
        password_label = QLabel("🔑 密码：")
        self.password_input = QLineEdit()
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        input_layout.addLayout(password_layout)

        # 加密内容输入
        body_label = QLabel("📜 加密内容：")
        self.body_edit = QTextEdit()
        self.body_edit.setMaximumHeight(120)  # 限制输入框高度
        input_layout.addWidget(body_label)
        input_layout.addWidget(self.body_edit)

        main_layout.addWidget(input_group)

        # 操作按钮
        self.decrypt_btn = QPushButton("🔓 执行解密")
        main_layout.addWidget(self.decrypt_btn, alignment=Qt.AlignCenter)

        # 分割线
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(separator)

        # 结果输出
        result_label = QLabel("📤 解密结果：")
        self.result_edit = QTextEdit()
        self.result_edit.setMinimumHeight(300)  # 设置最小高度
        self.result_edit.setReadOnly(True)
        main_layout.addWidget(result_label)
        main_layout.addWidget(self.result_edit)

        # 状态栏
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # 连接信号
        self.decrypt_btn.clicked.connect(self.decrypt)

    def setupStyles(self):
        # 统一字体
        app_font = QFont("微软雅黑", 10)
        self.setFont(app_font)

        # 颜色方案
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(245, 247, 250))
        palette.setColor(QPalette.Base, QColor(255, 255, 255))
        palette.setColor(QPalette.Button, QColor(74, 144, 226))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        self.setPalette(palette)

        # 控件样式
        self.setStyleSheet("""
            QLabel {
                color: #2d3e50;
                font-weight: 500;
            }

            QLineEdit {
                border: 2px solid #dfe5ec;
                border-radius: 5px;
                padding: 8px;
                font-size: 13px;
            }

            QTextEdit {
                border: 2px solid #dfe5ec;
                border-radius: 5px;
                padding: 10px;
                font-size: 13px;
            }

            QPushButton {
                background-color: #4a90e2;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 12px 24px;
                font-size: 14px;
                min-width: 120px;
            }

            QPushButton:hover {
                background-color: #3a80d2;
            }

            QPushButton:pressed {
                background-color: #2a70c2;
            }
        """)

    def decrypt(self):
        try:
            self.status_bar.showMessage("正在处理...")
            QApplication.processEvents()

            password = self.password_input.text()
            body = self.body_edit.toPlainText()

            if not password or not body:
                raise ValueError("密码和内容不能为空")

            # 执行解密流程
            passwordhash = hashlib.md5(password.encode()).hexdigest().lower()
            key = passwordhash[:8]
            header = passwordhash[8:20]
            footer = passwordhash[20:32]

            safe_kh = re.escape(header)
            safe_kf = re.escape(footer)
            pattern = f"{safe_kh}(.+?){safe_kf}"

            match = re.search(pattern, body, flags=re.DOTALL)
            if not match:
                raise ValueError("未找到有效加密内容")

            encode_data = match.group(1)
            base64_data = self.fix_base64_padding(encode_data)
            decoded_data = base64.b64decode(base64_data)
            xor_data = self.xor(decoded_data, key.encode())
            uncompressed_data = self.gzuncompress(xor_data)

            # 尝试解码
            final = self.try_decode(uncompressed_data)

            self.result_edit.setPlainText(final)
            self.status_bar.showMessage("解密成功", 3000)

        except Exception as e:
            self.result_edit.clear()
            QMessageBox.critical(self, "错误", f"解密失败：{str(e)}")
            self.status_bar.showMessage("解密失败", 3000)

    def try_decode(self, data):
        encodings = ['utf-8', 'gbk', 'latin-1']
        for enc in encodings:
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        return data.decode('utf-8', errors='replace')

    @staticmethod
    def fix_base64_padding(encoded_str):
        padding = 4 - (len(encoded_str) % 4)
        return encoded_str + ("=" * padding if padding != 4 else "")

    @staticmethod
    def gzuncompress(data):
        try:
            return zlib.decompress(data, wbits=zlib.MAX_WBITS | 32)
        except zlib.error as e:
            raise ValueError("解压失败，数据可能损坏") from e

    @staticmethod
    def xor(t, k):
        c = len(k)
        l = len(t)
        o = bytearray()
        i = 0
        while i < l:
            j = 0
            while j < c and i < l:
                o.append(t[i] ^ k[j])
                j += 1
                i += 1
        return bytes(o)


if __name__ == '__main__':
    # 高DPI支持
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)

    app = QApplication(sys.argv)
    window = CompactDecryptApp()
    window.show()
    sys.exit(app.exec_())