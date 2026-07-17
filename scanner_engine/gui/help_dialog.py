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

[가독성 개선] 예전엔 setPlainText()로 그냥 통짜 텍스트를 넣어서, "■ 소제목"이나
"· 목록" 같은 구분 기호가 있어도 시각적으로는 전부 똑같은 굵기/줄간격의 텍스트
덩어리로 보였다. HELP_TEXTS의 원문은 그대로 두고(내용 재작성 없음), 여기서만
그 표기 규칙(■=소제목, ★=강조 경고, ·=목록)을 읽어서 실제 제목 크기/색/볼드,
목록 들여쓰기, 문단 줄간격이 있는 HTML로 변환해 보여주는 방식으로 바꿨다.
"""
import html as html_lib
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QTextEdit, QPushButton, QLabel, QFrame
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


def _format_detail_html(text):
    """HELP_TEXTS의 원문(줄바꿈으로 수동 개행된 일반 텍스트)을 읽기 좋은 HTML로 변환.
    ■ 로 시작하는 줄 -> 소제목(굵게, 강조색, 위 여백)
    ★ 로 시작하는 줄 -> 경고 콜아웃(배경색 강조 박스)
    · 로 시작하는 줄(연속) -> 글머리 목록(<ul>)
    그 외 일반 줄(연속) -> 하나의 문단으로 합쳐서 자연스럽게 줄바꿈되도록 함
    (원문이 40자 안팎에서 수동으로 줄바꿈돼 있던 것을 그대로 <br>로 살리면
    창 너비에 안 맞아 오히려 더 부자연스러워지므로, 문단 단위로 다시 합친다)
    """
    blocks = text.split('\n\n')
    out = []
    for block in blocks:
        lines = block.split('\n')
        i = 0
        n = len(lines)
        while i < n:
            stripped = lines[i].strip()
            if not stripped:
                i += 1
                continue
            if stripped.startswith('■'):
                out.append(
                    '<div style="margin:18px 0 6px 0; font-size:13pt; font-weight:700; '
                    f'color:#3B82F6;">{html_lib.escape(stripped)}</div>'
                )
                i += 1
            elif stripped.startswith('★'):
                out.append(
                    '<div style="margin:10px 0; padding:10px 14px; border-left:4px solid #E5484D; '
                    f'background:rgba(229,72,77,0.12); font-weight:600;">{html_lib.escape(stripped)}</div>'
                )
                i += 1
            elif stripped.startswith('·'):
                items = []
                while i < n and lines[i].strip().startswith('·'):
                    item_text = lines[i].strip().lstrip('·').strip()
                    items.append(f'<li style="margin-bottom:4px;">{html_lib.escape(item_text)}</li>')
                    i += 1
                out.append(f'<ul style="margin:2px 0 12px 0; padding-left:24px;">{"".join(items)}</ul>')
            else:
                para_lines = []
                while i < n and lines[i].strip() and not lines[i].strip().startswith(('■', '★', '·')):
                    para_lines.append(lines[i].strip())
                    i += 1
                joined = html_lib.escape(' '.join(para_lines))
                out.append(f'<p style="margin:0 0 12px 0; line-height:1.6;">{joined}</p>')
    return ''.join(out)


class HelpDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("도움말")
        self.resize(920, 640)

        layout = QHBoxLayout(self)

        self.category_list = QListWidget()
        self.category_list.setFixedWidth(210)
        self.category_list.setStyleSheet("QListWidget { font-size: 10.5pt; } QListWidget::item { padding: 8px 6px; }")
        for key, _ in CATEGORY_ORDER:
            self.category_list.addItem(HELP_TEXTS[key]["title"])
        self.category_list.currentRowChanged.connect(self._show_category)
        layout.addWidget(self.category_list)

        divider = QFrame()
        divider.setFrameShape(QFrame.VLine)
        divider.setStyleSheet("color: #888;")
        layout.addWidget(divider)

        right = QVBoxLayout()
        right.setContentsMargins(14, 4, 4, 4)
        self.title_label = QLabel("")
        self.title_label.setStyleSheet("font-size: 16pt; font-weight: 700; padding-bottom: 8px;")
        right.addWidget(self.title_label)

        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setStyleSheet(
            "QTextEdit { font-size: 11pt; font-family: 'Malgun Gothic', 'Segoe UI', sans-serif; "
            "line-height: 160%; border: none; }"
        )
        right.addWidget(self.detail_view)

        btn_close = QPushButton("닫기")
        btn_close.setFixedWidth(100)
        right.addWidget(btn_close, 0)
        btn_close.clicked.connect(self.accept)

        layout.addLayout(right, 1)

        self.category_list.setCurrentRow(0)

    def _show_category(self, row):
        if row < 0 or row >= len(CATEGORY_ORDER):
            return
        key, _ = CATEGORY_ORDER[row]
        entry = HELP_TEXTS[key]
        self.title_label.setText(entry["title"])
        self.detail_view.setHtml(_format_detail_html(entry["detail"]))
