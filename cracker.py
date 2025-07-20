#cracker.py
#!/usr/bin/env python3
import sys
from PyQt5.QtWidgets import QApplication
from ui import CrackerWidget  # UI module we'll create

def main():
    app = QApplication(sys.argv)
    window = CrackerWidget()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
