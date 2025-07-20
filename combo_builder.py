#!/usr/bin/env python3
# combo_builder.py
import os
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QCheckBox, QSpinBox, QPushButton, QMessageBox,
    QTableWidget, QTableWidgetItem, QLineEdit, QFileDialog,
    QComboBox, QWidget, QHeaderView, QSizePolicy
)
from PyQt5.QtCore import Qt, pyqtSignal


class ComboBuilderWindow(QDialog):
    confirmed = pyqtSignal(list, dict)  # (pattern, cfg)

    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Combo Pattern Builder")
        self.resize(820, 480)
        self.settings = settings
        # Load last-used file paths
        self.last_paths = {
            'name': settings.value('names_path', ''),
            'adj':  settings.value('adj_path', ''),
            'noun': settings.value('noun_path', '')
        }
        self.fields = [
            {"label": "Names (file)",          "token": "name",       "kind": "file"},
            {"label": "Adjectives (file)",     "token": "adj",        "kind": "file"},
            {"label": "Nouns (file)",          "token": "noun",       "kind": "file"},
            {"label": "Month Numbers (01..12)","token": "month_num",  "kind": "none"},
            {"label": "Month Abbrs (Jan..Dec)","token": "month_abbr", "kind": "none"},
            {"label": "Month Names (Full)",    "token": "month_name","kind": "none"},
            {"label": "Days (01..31)",         "token": "day",        "kind": "none"},
            {"label": "Years (range)",         "token": "year",       "kind": "range-year"},
            {"label": "Digits (range)",        "token": "digit",      "kind": "range-digit"},
            {"label": "Symbols (set)",         "token": "symbol",     "kind": "static"},
            {"label": "Static Text",           "token": "static",     "kind": "static"},
        ]
        self._build_ui()

    def _build_ui(self):
        vbox = QVBoxLayout(self)
        self.table = QTableWidget(len(self.fields), 4, self)
        self.table.setHorizontalHeaderLabels(["Use", "Order", "Field", "Config"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setMinimumHeight(400)
        self.table.setMinimumWidth(800)
        self.table.setColumnWidth(0, 70)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 270)
        self.table.setColumnWidth(3, 390)
        self.table.verticalHeader().setDefaultSectionSize(40)

        for i, f in enumerate(self.fields):
            # Checkbox with blue outline
            chk = QCheckBox()
            chk.setStyleSheet("""
                QCheckBox::indicator {
                    border: 3px solid #2196F3;
                    width: 24px; height: 24px;
                    border-radius: 4px;
                    background: #222;
                    margin: 3px;
                }
                QCheckBox::indicator:checked {
                    background: #2196F3;
                    border: 3px solid #42A5F5;
                }
            """)
            self.table.setCellWidget(i, 0, chk)

            # Order spinbox
            sp = QSpinBox()
            sp.setRange(1, len(self.fields))
            sp.setDisabled(True)
            sp.setMinimumWidth(48)
            sp.setMaximumWidth(72)
            sp.setStyleSheet("font-size:17px;")
            self.table.setCellWidget(i, 1, sp)

            # Field label
            item = QTableWidgetItem(f["label"])
            font = item.font(); font.setPointSize(font.pointSize() + 2)
            item.setFont(font)
            self.table.setItem(i, 2, item)

            # Config widget
            kind = f["kind"]
            if kind == "file":
                le = QLineEdit()
                # Set last-used path
                last = self.last_paths.get(f["token"], '')
                if last:
                    le.setText(last)
                le.setMinimumWidth(180)
                le.setStyleSheet("font-size:15px;")
                btn = QPushButton("…")
                btn.setMaximumWidth(34)
                def choose_file(_=None, row=i, le=le, tok=f["token"]):
                    path, _ = QFileDialog.getOpenFileName(
                        self, f"Choose {self.fields[row]['label']}",
                        os.path.expanduser("~"), "Text Files (*.txt)"
                    )
                    if path:
                        le.setText(path)
                btn.clicked.connect(choose_file)
                cont = QWidget(); h = QHBoxLayout(cont)
                h.setContentsMargins(0,0,0,0); h.setSpacing(7)
                h.addWidget(le); h.addWidget(btn)
                cont.setMinimumWidth(230)
                self.table.setCellWidget(i, 3, cont)
            elif kind == "range-year":
                wid = QLineEdit("1970-2025"); wid.setMinimumWidth(110)
                self.table.setCellWidget(i, 3, wid)
            elif kind == "range-digit":
                wid = QLineEdit("1-4"); wid.setMinimumWidth(90)
                self.table.setCellWidget(i, 3, wid)
            elif kind == "static":
                wid = QLineEdit(); wid.setMinimumWidth(120)
                self.table.setCellWidget(i, 3, wid)
            else:
                self.table.setCellWidget(i, 3, QWidget())

            # Checkbox toggles order box
            def toggle_spin(state, row=i):
                spn = self.table.cellWidget(row, 1)
                if state == Qt.Checked:
                    spn.setDisabled(False)
                else:
                    spn.setValue(spn.minimum())
                    spn.setDisabled(True)
            chk.stateChanged.connect(toggle_spin)

        vbox.addWidget(self.table)

        # OK / Cancel
        h = QHBoxLayout()
        ok     = QPushButton("OK");     ok.setMinimumWidth(120); ok.setStyleSheet("font-size:16px"); ok.clicked.connect(self._on_ok)
        cancel = QPushButton("Cancel"); cancel.setMinimumWidth(120); cancel.setStyleSheet("font-size:16px"); cancel.clicked.connect(self.reject)
        h.addStretch(); h.addWidget(ok); h.addWidget(cancel)
        vbox.addLayout(h)

    def _on_ok(self):
        pattern = []
        cfg     = {}
        orders  = set()
        # Loop rows to collect selections
        for i, f in enumerate(self.fields):
            chk = self.table.cellWidget(i, 0)
            spn = self.table.cellWidget(i, 1)
            if not chk.isChecked():
                continue
            order = spn.value()
            if order in orders:
                QMessageBox.warning(self, "Order Error",
                    f"Duplicate order {order} for: {f['label']}")
                return
            orders.add(order)
            pattern.append((order, f["token"]))

            # Gather config
            kind = f["kind"]
            w = self.table.cellWidget(i, 3)
            if kind == "file":
                le = w.layout().itemAt(0).widget()
                path = le.text().strip()
                cfg[f["token"]] = {"file": path}
                # Save for next time
                key = 'names_path' if f["token"]=='name' else ('adj_path' if f["token"]=='adj' else 'noun_path')
                self.settings.setValue(key, path)

            elif kind == "range-year":
                txt = w.text()
                lo, hi = map(int, txt.split("-"))
                cfg[f["token"]] = {"min": lo, "max": hi}

            elif kind == "range-digit":
                txt = w.text()
                lo, hi = map(int, txt.split("-"))
                cfg[f["token"]] = {"min": lo, "max": hi}

            elif kind == "static":
                cfg[f["token"]] = {"text": w.text()}

        if not pattern:
            QMessageBox.warning(self, "Empty", "Check at least one row.")
            return

        pattern = [tok for _, tok in sorted(pattern)]
        self.confirmed.emit(pattern, cfg)
        self.accept()
