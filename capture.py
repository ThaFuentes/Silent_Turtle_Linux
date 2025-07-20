#!/usr/bin/env python3
import sys
from PyQt5.QtWidgets import QApplication
from ui_capture import CaptureWidget  # Your full UI and logic here
import os

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = CaptureWidget()
    w.show()
    sys.exit(app.exec_())
