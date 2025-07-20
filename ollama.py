# ollama.py

import os
import pty
import select
import subprocess
import logging
import re
import sys
import errno
import json

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QScrollArea,
    QLabel, QPushButton, QLineEdit, QFileDialog, QMessageBox
)

SETTINGS_FILE = "settings.json"

# ——— Logging Configuration ———
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler("ollama_chat.log", encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(handler)

ANSI_ESCAPE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


class OllamaWorker(QThread):
    new_response = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, model="dolphin-llama3:8b", system_prompt="", parent=None):
        super().__init__(parent)
        self.model = model
        self.system_prompt = system_prompt.strip()
        self._running = True
        self._proc = None
        self._master_fd = None

    def run(self):
        try:
            master_fd, slave_fd = pty.openpty()
            self._master_fd = master_fd

            logger.debug(f"Starting Ollama: ollama run {self.model}")
            self._proc = subprocess.Popen(
                ["ollama", "run", self.model],
                stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                close_fds=True
            )
            os.close(slave_fd)

            # send system prompt once
            if self.system_prompt:
                os.write(master_fd, (self.system_prompt + "\n").encode())

            buffer = ""
            prompt_token = ">>> "

            # wait for first prompt
            while self._running:
                r, _, _ = select.select([master_fd], [], [], 0.1)
                if master_fd in r:
                    try:
                        data = os.read(master_fd, 1024).decode(errors="ignore")
                    except OSError as e:
                        if e.errno == errno.EIO:
                            return
                        else:
                            raise
                    buffer += data
                    if prompt_token in buffer:
                        _, buffer = buffer.split(prompt_token, 1)
                        break
                if self._proc.poll() is not None:
                    return

            # main loop
            while self._running and self._proc.poll() is None:
                r, _, _ = select.select([master_fd], [], [], 0.1)
                if master_fd in r:
                    try:
                        data = os.read(master_fd, 1024).decode(errors="ignore")
                    except OSError as e:
                        if e.errno == errno.EIO:
                            break
                        else:
                            raise
                    buffer += data

                    while prompt_token in buffer:
                        raw, buffer = buffer.split(prompt_token, 1)
                        text = ANSI_ESCAPE.sub("", raw)
                        # strip help banner
                        idx = text.find("Send a message")
                        if idx != -1:
                            end = text.find(")", idx)
                            text = text[end+1:] if end != -1 else text
                        # drop fragments
                        if "... " in text:
                            text = text.split("... ")[-1]
                        clean = text.strip()
                        if clean:
                            self.new_response.emit(clean)

            # leftover
            leftover = ANSI_ESCAPE.sub("", buffer).strip()
            if leftover:
                self.new_response.emit(leftover)

        except Exception as e:
            logger.exception("Worker exception")
            self.error_occurred.emit(str(e))
        finally:
            if self._master_fd:
                try: os.close(self._master_fd)
                except OSError: pass

    def send_message(self, message: str):
        if self._master_fd:
            try:
                os.write(self._master_fd, (message + "\n").encode())
            except OSError as e:
                if e.errno != errno.EIO:
                    self.error_occurred.emit(str(e))

    def stop(self):
        self._running = False
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                pass
        if self._master_fd:
            try: os.close(self._master_fd)
            except OSError: pass


class OllamaChatWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.last_user_message = ""
        self._load_settings()
        self._init_ui()

    def _load_settings(self):
        # Load or default
        if os.path.isfile(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r") as f:
                    s = json.load(f)
            except Exception:
                s = {}
        else:
            s = {}
        self.model = s.get("model", "dolphin-llama3:8b")
        self.system_prompt = s.get("system_prompt", "")
        self.bot_name = s.get("bot_name", "Ollama")

    def _save_settings(self):
        s = {
            "model": self.model_input.text().strip() or "dolphin-llama3:8b",
            "system_prompt": self.prompt_input.text().strip(),
            "bot_name": self.name_input.text().strip() or "Ollama"
        }
        with open(SETTINGS_FILE, "w") as f:
            json.dump(s, f, indent=2)

    def _init_ui(self):
        self.setWindowTitle("Ollama Chat")
        root = QVBoxLayout(self)
        root.setContentsMargins(15, 15, 15, 15)
        root.setSpacing(10)

        # Settings row
        row = QHBoxLayout()
        row.addWidget(QLabel("Model:"))
        self.model_input = QLineEdit(self.model)
        row.addWidget(self.model_input, 1)

        row.addWidget(QLabel("System Prompt:"))
        self.prompt_input = QLineEdit(self.system_prompt)
        row.addWidget(self.prompt_input, 2)

        row.addWidget(QLabel("Bot Name:"))
        self.name_input = QLineEdit(self.bot_name)
        row.addWidget(self.name_input, 1)

        self.apply_btn = QPushButton("Start Chat")
        row.addWidget(self.apply_btn)
        root.addLayout(row)

        # Scrollable chat area
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.container = QWidget()
        self.msg_layout = QVBoxLayout(self.container)
        self.msg_layout.addStretch()
        self.scroll.setWidget(self.container)
        root.addWidget(self.scroll, 1)

        # Input
        inp_row = QHBoxLayout()
        self.input_line = QLineEdit()
        self.input_line.setPlaceholderText("Type your message…")
        self.input_line.setEnabled(False)
        inp_row.addWidget(self.input_line, 1)

        self.send_btn = QPushButton("Send")
        self.send_btn.setEnabled(False)
        inp_row.addWidget(self.send_btn)
        root.addLayout(inp_row)

        # Signals
        self.apply_btn.clicked.connect(self._start_or_restart)
        self.send_btn.clicked.connect(self._on_send)
        self.input_line.returnPressed.connect(self._on_send)

        self.resize(900, 650)

    def _start_or_restart(self):
        # stop old
        if self.worker:
            self.worker.stop()
            self.worker.wait()

        # save settings
        self._save_settings()
        self.model = self.model_input.text().strip() or "dolphin-llama3:8b"
        self.system_prompt = self.prompt_input.text().strip()
        self.bot_name = self.name_input.text().strip() or "Ollama"

        # clear messages
        for i in reversed(range(self.msg_layout.count())):
            w = self.msg_layout.itemAt(i).widget()
            if w:
                w.deleteLater()
        self.msg_layout.addStretch()

        # start worker
        self.worker = OllamaWorker(model=self.model, system_prompt=self.system_prompt)
        self.worker.new_response.connect(self._on_response)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.start()

        # enable
        self.input_line.setEnabled(True)
        self.send_btn.setEnabled(True)
        self.apply_btn.setText("Restart Chat")

        # info line
        self._add_system_label(
            f"Chat started with <b>{self.model}</b> as “{self.bot_name}”"
            + (f"<br>System prompt: {self.system_prompt}" if self.system_prompt else "")
        )

    def _add_system_label(self, html):
        lbl = QLabel(html)
        lbl.setStyleSheet("color:#888;")
        lbl.setWordWrap(True)
        self.msg_layout.insertWidget(self.msg_layout.count()-1, lbl)
        self._scroll_to_bottom()

    def _add_message(self, author: str, text: str, user_msg: str = None):
        row = QHBoxLayout()
        author_lbl = QLabel(f"<b>{author}:</b>")
        author_lbl.setTextFormat(Qt.RichText)
        if author == "You":
            author_lbl.setStyleSheet("color:#00ff33;")
        else:
            author_lbl.setStyleSheet("color:#33ff33;")
        row.addWidget(author_lbl)

        text_lbl = QLabel(text)
        text_lbl.setWordWrap(True)
        text_lbl.setTextFormat(Qt.RichText)
        row.addWidget(text_lbl, 1)

        if author == self.bot_name and user_msg is not None:
            btn = QPushButton("Reload")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _, w=row, um=user_msg: self._reload_response(w, um))
            row.addWidget(btn)

        widget = QWidget()
        widget.setLayout(row)
        self.msg_layout.insertWidget(self.msg_layout.count()-1, widget)
        self._scroll_to_bottom()

    def _on_send(self):
        msg = self.input_line.text().strip()
        if not msg:
            return
        self.last_user_message = msg
        self._add_message("You", msg)
        self.input_line.clear()
        if self.worker:
            self.worker.send_message(msg)

    def _on_response(self, text: str):
        # attach with the user message that triggered it
        self._add_message(self.bot_name, text, user_msg=self.last_user_message)

    def _reload_response(self, layout: QHBoxLayout, user_msg: str):
        # remove old widget
        widget = layout.parentWidget()
        widget.deleteLater()
        # resend
        if self.worker:
            self.worker.send_message(user_msg)

    def _on_error(self, error: str):
        QMessageBox.warning(self, "Ollama Error", error)

    def _scroll_to_bottom(self):
        sb = self.scroll.verticalScrollBar()
        sb.setValue(sb.maximum())

    def closeEvent(self, event):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = OllamaChatWidget()
    win.show()
    sys.exit(app.exec_())
