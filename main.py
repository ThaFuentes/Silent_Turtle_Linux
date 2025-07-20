#main.py
#!/usr/bin/env python3
# main.py

import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QStackedWidget, QLabel, QGraphicsDropShadowEffect
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import (
    QColor, QFont, QPalette, QLinearGradient, QBrush, QPixmap
)

from capture import CaptureWidget
from cracker import CrackerWidget
from cloneap import CloneAPWidget
from ollama import OllamaChatWidget


class TitleLabel(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont("Orbitron", 32, QFont.Bold))
        self.setStyleSheet("color: #00ff80;")
        self.setAlignment(Qt.AlignCenter)


class GlowingButton(QPushButton):
    def __init__(self, label, parent=None):
        super().__init__(label.upper(), parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setFont(QFont("Consolas", 14, QFont.Bold))
        self.setStyleSheet("""
            QPushButton {
                color: #00ff80;
                background-color: #001100;
                border: 2px solid #00ff80;
                border-radius: 6px;
                padding: 10px 24px;
                letter-spacing: 1.2px;
            }
            QPushButton:hover {
                background-color: #003322;
            }
            QPushButton:pressed {
                background-color: #005544;
            }
        """)
        glow = QGraphicsDropShadowEffect(self)
        glow.setBlurRadius(30)
        glow.setColor(QColor(0, 255, 128, 200))
        glow.setOffset(0)
        self.setGraphicsEffect(glow)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Silent Turtle - Wi-Fi Toolkit")
        self.resize(900, 650)
        self._apply_background()
        self._init_ui()

    def _apply_background(self):
        grad = QLinearGradient(0, 0, 0, self.height())
        grad.setColorAt(0.0, QColor("#000900"))
        grad.setColorAt(1.0, QColor("#001100"))
        pal = QPalette()
        pal.setBrush(QPalette.Window, QBrush(grad))
        self.setPalette(pal)

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        layout = QHBoxLayout(central)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(16)

        # --- Left nav panel ---
        nav = QVBoxLayout()
        nav.setSpacing(22)

        # Title & logo
        self.title_label = TitleLabel("SILENT TURTLE")
        nav.addWidget(self.title_label)

        logo = QLabel()
        pix = QPixmap("assets/silent_turtle_logo.png")
        if not pix.isNull():
            logo.setPixmap(
                pix.scaled(260, 260, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            )
        nav.addWidget(logo, alignment=Qt.AlignCenter)

        nav.addStretch()

        # Nav buttons in correct order
        self.capture_btn = GlowingButton("Capture")
        self.cracker_btn = GlowingButton("Cracker")
        self.cloneap_btn = GlowingButton("Clone AP")
        self.ollama_btn = GlowingButton("Ollama Chat")

        for btn in (
            self.capture_btn,
            self.cracker_btn,
            self.cloneap_btn,
            self.ollama_btn
        ):
            nav.addWidget(btn)

        nav.addStretch()
        layout.addLayout(nav, 1)

        # --- Main content stack ---
        self.stack = QStackedWidget()
        self.capture_widget    = CaptureWidget()
        self.cracker_widget    = CrackerWidget()
        self.cloneap_widget    = CloneAPWidget()
        self.ollama_chat_widget= OllamaChatWidget()

        page_css = """
            background-color: #001100;
            color: #00ff80;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        """
        for w in (
            self.capture_widget,
            self.cracker_widget,
            self.cloneap_widget,
            self.ollama_chat_widget
        ):
            w.setStyleSheet(page_css)
            self.stack.addWidget(w)

        # Hook up nav buttons
        self.capture_btn.clicked.connect(lambda: self.stack.setCurrentWidget(self.capture_widget))
        self.cracker_btn.clicked.connect(lambda: self.stack.setCurrentWidget(self.cracker_widget))
        self.cloneap_btn.clicked.connect(lambda: self.stack.setCurrentWidget(self.cloneap_widget))
        self.ollama_btn.clicked.connect(lambda: self.stack.setCurrentWidget(self.ollama_chat_widget))

        # Default page
        self.stack.setCurrentWidget(self.capture_widget)

        layout.addWidget(self.stack, 6)

def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Consolas", 12))
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
