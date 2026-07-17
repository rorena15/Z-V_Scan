# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[Phase 3] 도움말 페이지: 좌측 카테고리 목록 + 우측 상세 설명.
내용은 help_texts.py의 HELP_TEXTS를 그대로 재사용해 툴팁과 중복 작성하지 않는다.
"""
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QTextEdit, QPushButton, QLabel
)

from gui.help_texts import HELP_TEXTS

# 좌측 목록에 표시할 순서와, 각 항목이 HELP_TEXTS의 어떤 키(들)를 참조하는지
CATEGORY_ORDER = [
    ("discovery", ["discovery"]),
    ("audit", ["audit"]),
    ("expert_mode", ["expert_mode"]),
    ("ot_demo_mode", ["ot_demo_mode"]),
    ("import_assets", ["import_assets"]),
    ("waiver", ["waiver"]),
    ("report", ["report"]),
    ("settings", ["settings"]),
    ("known_hosts", ["known_hosts"]),
    ("license", ["license"]),
]


class HelpDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("도움말")
        self.resize(820, 560)

        layout = QHBoxLayout(self)

        self.category_list = QListWidget()
        self.category_list.setFixedWidth(200)
        for key, _ in CATEGORY_ORDER:
            self.category_list.addItem(HELP_TEXTS[key]["title"])
        self.category_list.currentRowChanged.connect(self._show_category)
        layout.addWidget(self.category_list)

        right = QVBoxLayout()
        self.title_label = QLabel("")
        self.title_label.setStyleSheet("font-size: 14pt; font-weight: bold;")
        right.addWidget(self.title_label)

        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        right.addWidget(self.detail_view)

        btn_close = QPushButton("닫기")
        btn_close.clicked.connect(self.accept)
        right.addWidget(btn_close)

        layout.addLayout(right, 1)

        self.category_list.setCurrentRow(0)

    def _show_category(self, row):
        if row < 0 or row >= len(CATEGORY_ORDER):
            return
        key, _ = CATEGORY_ORDER[row]
        entry = HELP_TEXTS[key]
        self.title_label.setText(entry["title"])
        self.detail_view.setPlainText(entry["detail"])
