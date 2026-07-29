# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[Phase 3] 전문가 모드: 룰 카테고리/개별 코드 단위로 "이번 스캔 범위"에 포함할지 뺄지 고른다.
점검 명령어·중요도는 KISA 신뢰성을 위해 읽기 전용으로만 보여주고 절대 수정하지 않는다.

주의: 이것은 스캔 "범위" 선택이지 Waiver(예외처리)가 아니다.
- 여기서 제외한 항목은 점검 자체가 실행되지 않으며, 판정 결과도 생기지 않는다.
- 이미 점검된 결과를 감사 추적성 있게 예외 처리(사유·승인자 필수, 리포트에 "예외처리됨"으로
  표시)하는 것은 별개 기능인 Waiver Manager(gui/waiver_dialog.py, TBL_SCAN_RESULT 기반)가
  담당한다. 두 기능을 섞지 않는다.
"""
import os
import sys
import json

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QSplitter, QTreeWidget, QTreeWidgetItem,
    QListWidget, QListWidgetItem, QPushButton, QLineEdit, QTextEdit, QLabel,
    QMessageBox, QCheckBox, QWidget, QFrame
)
from PySide6.QtCore import Qt

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.expert_profile import load_profile, save_profile
from gui.dashboard_widgets import COLORS

RULESETS = [
    ("linux_rules.json", "UNIX/Linux"),
    ("windows_rules.json", "Windows Server"),
    ("pc_rules.json", "PC (워크스테이션)"),
    ("mysql_rules.json", "MySQL"),
    ("postgresql_rules.json", "PostgreSQL"),
    ("web_rules.json", "WAS (Apache/Nginx)"),
]


class ExpertModeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("전문가 모드 - 점검 범위 선택")
        self.resize(1100, 720)

        self.profile = load_profile()  # {ruleset_filename: [excluded_code, ...]}

        self._rule_lookup = {}   # (filename, code) -> rule dict
        self._leaf_lookup = {}   # (filename, code) -> QTreeWidgetItem
        self._all_items = []     # (filename, code, QTreeWidgetItem)
        self._current_key = None
        self._suspend_signals = False

        layout = QVBoxLayout(self)

        info = QLabel(
            "체크 해제한 항목은 이번 진단 범위에서 아예 제외되어 실행되지 않고, 판정 결과 자체가 생기지 않습니다.\n"
            "이미 점검된 결과를 감사 추적성 있게 예외 처리하려면 '예외처리 관리(Waiver)'를 사용하세요.\n"
            "점검 명령어·중요도는 KISA 신뢰성을 위해 읽기 전용이며 여기서 수정할 수 없습니다."
        )
        info.setStyleSheet(f"color: {COLORS['text_secondary']};")
        info.setWordWrap(True)
        layout.addWidget(info)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setSizes([550, 450])
        layout.addWidget(splitter, 1)

        self.scope_banner = QLabel()
        self.scope_banner.setStyleSheet(
            f"color: {COLORS['warning_text']}; padding: 6px; background: {COLORS['warning_bg']}; border-radius: 4px;"
        )
        layout.addWidget(self.scope_banner)

        btn_layout = QHBoxLayout()
        btn_select_all = QPushButton("전체 선택")
        btn_select_all.clicked.connect(lambda: self._set_all_checked(True))
        btn_deselect_all = QPushButton("전체 해제")
        btn_deselect_all.clicked.connect(lambda: self._set_all_checked(False))
        btn_layout.addWidget(btn_select_all)
        btn_layout.addWidget(btn_deselect_all)
        btn_layout.addStretch()

        btn_save = QPushButton("저장")
        btn_save.clicked.connect(self._save_and_close)
        btn_cancel = QPushButton("취소")
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_save)
        btn_layout.addWidget(btn_cancel)

        layout.addLayout(btn_layout)

        self._load_rules()
        self._refresh_excluded_list()
        self._refresh_scope_banner()

    # ------------------------------------------------------------------
    # 좌측: 카테고리 트리 + 제외 항목 미니 목록
    # ------------------------------------------------------------------
    def _build_left_panel(self):
        panel = QWidget()
        v = QVBoxLayout(panel)
        v.setContentsMargins(0, 0, 0, 0)

        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("검색:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("코드 또는 항목명으로 필터...")
        self.search_input.textChanged.connect(self._apply_filter)
        search_layout.addWidget(self.search_input)
        v.addLayout(search_layout)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["항목", "코드", "중요도"])
        self.tree.setColumnWidth(0, 320)
        self.tree.setColumnWidth(1, 90)
        self.tree.itemChanged.connect(self._on_item_changed)
        self.tree.currentItemChanged.connect(self._on_selection_changed)
        v.addWidget(self.tree, 3)

        v.addWidget(QLabel("이번 스캔 범위에서 제외된 항목"))
        self.excluded_list = QListWidget()
        self.excluded_list.setMaximumHeight(140)
        self.excluded_list.itemClicked.connect(self._on_excluded_list_clicked)
        v.addWidget(self.excluded_list, 1)

        return panel

    # ------------------------------------------------------------------
    # 우측: 선택한 룰의 상세 정보 (읽기 전용) + 포함/제외 체크박스
    # ------------------------------------------------------------------
    def _build_right_panel(self):
        panel = QWidget()
        v = QVBoxLayout(panel)
        v.setContentsMargins(10, 0, 0, 0)

        self.detail_title = QLabel("좌측에서 항목을 선택하세요")
        self.detail_title.setStyleSheet(f"font-size: 12pt; font-weight: bold; color: {COLORS['text']};")
        self.detail_title.setWordWrap(True)
        v.addWidget(self.detail_title)

        self.detail_meta = QLabel("")
        self.detail_meta.setStyleSheet(f"color: {COLORS['text_secondary']};")
        v.addWidget(self.detail_meta)

        v.addWidget(QLabel("점검 명령어 (읽기 전용):"))
        self.detail_command = QTextEdit()
        self.detail_command.setReadOnly(True)
        self.detail_command.setStyleSheet(
            f"background-color: {COLORS['surface_1']}; color: {COLORS['text']}; "
            f"font-family: Consolas, monospace; border: 1px solid {COLORS['border']};"
        )
        self.detail_command.setMaximumHeight(160)
        v.addWidget(self.detail_command, 1)

        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet(f"color: {COLORS['border']}; background-color: {COLORS['border']}; max-height: 1px;")
        v.addWidget(divider)

        self.chk_include = QCheckBox("이번 진단 범위에 포함")
        self.chk_include.setToolTip("체크 해제 시 이 항목은 이번 스캔에서 아예 실행되지 않습니다 (판정 결과 없음).")
        self.chk_include.toggled.connect(self._on_include_toggled)
        v.addWidget(self.chk_include)

        v.addStretch()
        self._set_right_panel_enabled(False)
        return panel

    def _set_right_panel_enabled(self, enabled):
        self.chk_include.setEnabled(enabled)

    # ------------------------------------------------------------------
    def _rules_dir(self):
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        rules_dir = os.path.join(base_dir, 'rules')
        if hasattr(sys, '_MEIPASS') and not os.path.isdir(rules_dir):
            rules_dir = os.path.join(sys._MEIPASS, 'rules')
        return rules_dir

    def _load_rules(self):
        rules_dir = self._rules_dir()
        self._suspend_signals = True

        for filename, ruleset_label in RULESETS:
            path = os.path.join(rules_dir, filename)
            if not os.path.exists(path):
                continue
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
            except Exception:
                continue

            excluded = set(self.profile.get(filename, []))

            root = QTreeWidgetItem(self.tree, [ruleset_label])
            root.setFlags(root.flags() | Qt.ItemIsAutoTristate | Qt.ItemIsUserCheckable)
            root.setData(0, Qt.UserRole, ("ruleset", filename))
            font = root.font(0)
            font.setBold(True)
            root.setFont(0, font)

            by_category = {}
            order = []
            for rule in rules:
                cat = rule.get('category', '기타')
                if cat not in by_category:
                    by_category[cat] = []
                    order.append(cat)
                by_category[cat].append(rule)

            for cat in order:
                cat_node = QTreeWidgetItem(root, [cat])
                cat_node.setFlags(cat_node.flags() | Qt.ItemIsAutoTristate | Qt.ItemIsUserCheckable)
                cat_node.setData(0, Qt.UserRole, ("category", filename))

                for rule in by_category[cat]:
                    code = rule.get('code', '')
                    name = rule.get('name', '')
                    importance = rule.get('importance', '중')

                    leaf = QTreeWidgetItem(cat_node, [name, code, importance])
                    leaf.setFlags(leaf.flags() | Qt.ItemIsUserCheckable)
                    leaf.setCheckState(0, Qt.Unchecked if code in excluded else Qt.Checked)
                    leaf.setData(0, Qt.UserRole, ("leaf", filename, code))
                    self._all_items.append((filename, code, leaf))
                    self._rule_lookup[(filename, code)] = rule
                    self._leaf_lookup[(filename, code)] = leaf

            self.tree.addTopLevelItem(root)

        self.tree.expandToDepth(0)
        self._suspend_signals = False
        self._update_all_counts()

    # ------------------------------------------------------------------
    # 카운트 뱃지 ("66/67") 갱신
    # ------------------------------------------------------------------
    def _update_all_counts(self):
        for i in range(self.tree.topLevelItemCount()):
            root = self.tree.topLevelItem(i)
            self._update_node_count(root)

    def _update_node_count(self, node):
        total = 0
        checked = 0
        for i in range(node.childCount()):
            child = node.child(i)
            kind = child.data(0, Qt.UserRole)[0]
            if kind == "leaf":
                total += 1
                if child.checkState(0) == Qt.Checked:
                    checked += 1
            else:
                c, t = self._update_node_count(child)
                total += t
                checked += c

        base_label = node.text(0).split(" (")[0]
        node.setText(0, f"{base_label} ({checked}/{total})")
        return checked, total

    # ------------------------------------------------------------------
    def _on_item_changed(self, item, column):
        if self._suspend_signals or column != 0:
            return
        self._suspend_signals = True
        self._update_all_counts()
        self._suspend_signals = False
        self._refresh_excluded_list()
        self._refresh_scope_banner()

        kind_data = item.data(0, Qt.UserRole)
        if kind_data and kind_data[0] == "leaf":
            filename, code = kind_data[1], kind_data[2]
            if self._current_key == (filename, code):
                is_checked = item.checkState(0) == Qt.Checked
                self.chk_include.blockSignals(True)
                self.chk_include.setChecked(is_checked)
                self.chk_include.blockSignals(False)

    def _on_selection_changed(self, current, previous):
        if current is None:
            self._current_key = None
            self._set_right_panel_enabled(False)
            return

        kind_data = current.data(0, Qt.UserRole)
        if not kind_data or kind_data[0] != "leaf":
            self._current_key = None
            self._set_right_panel_enabled(False)
            self.detail_title.setText("카테고리 또는 룰셋 전체를 선택했습니다. 개별 항목을 선택하면 상세 정보가 표시됩니다.")
            self.detail_meta.setText("")
            self.detail_command.setPlainText("")
            return

        filename, code = kind_data[1], kind_data[2]
        self._current_key = (filename, code)
        rule = self._rule_lookup.get((filename, code), {})
        self._set_right_panel_enabled(True)

        self.detail_title.setText(f"[{code}] {rule.get('name', '')}")
        self.detail_meta.setText(f"중요도: {rule.get('importance', '중')}   |   카테고리: {rule.get('category', '기타')}")
        self.detail_command.setPlainText(rule.get('command', '') or "(명령어 없음)")

        leaf = self._leaf_lookup.get((filename, code))
        is_checked = leaf is not None and leaf.checkState(0) == Qt.Checked
        self.chk_include.blockSignals(True)
        self.chk_include.setChecked(is_checked)
        self.chk_include.blockSignals(False)

    def _on_include_toggled(self, checked):
        if self._current_key is None:
            return
        leaf = self._leaf_lookup.get(self._current_key)
        if leaf is not None:
            leaf.setCheckState(0, Qt.Checked if checked else Qt.Unchecked)

    # ------------------------------------------------------------------
    def _refresh_excluded_list(self):
        self.excluded_list.clear()
        for filename, code, item in self._all_items:
            if item.checkState(0) == Qt.Unchecked:
                rule = self._rule_lookup.get((filename, code), {})
                label = f"[{code}] {rule.get('name', '')}"
                list_item = QListWidgetItem(label)
                list_item.setData(Qt.UserRole, (filename, code))
                self.excluded_list.addItem(list_item)

    def _on_excluded_list_clicked(self, list_item):
        filename, code = list_item.data(Qt.UserRole)
        leaf = self._leaf_lookup.get((filename, code))
        if leaf is not None:
            self.tree.setCurrentItem(leaf)

    def _refresh_scope_banner(self):
        total = len(self._all_items)
        excluded = sum(1 for _, _, item in self._all_items if item.checkState(0) == Qt.Unchecked)
        if excluded == 0:
            self.scope_banner.setText(f"현재 전체 {total}개 항목이 모두 이번 진단 범위에 포함됩니다.")
        else:
            self.scope_banner.setText(
                f"전체 {total}개 항목 중 {excluded}개가 이번 스캔 범위에서 제외되어 있습니다 (판정 결과가 아예 생기지 않음)."
            )

    # ------------------------------------------------------------------
    def _set_all_checked(self, checked):
        state = Qt.Checked if checked else Qt.Unchecked
        self._suspend_signals = True
        for _, _, item in self._all_items:
            if not item.isHidden():
                item.setCheckState(0, state)
        self._suspend_signals = False
        self._update_all_counts()
        self._refresh_excluded_list()
        self._refresh_scope_banner()
        if self._current_key is not None:
            leaf = self._leaf_lookup.get(self._current_key)
            if leaf is not None:
                is_checked = leaf.checkState(0) == Qt.Checked
                self.chk_include.blockSignals(True)
                self.chk_include.setChecked(is_checked)
                self.chk_include.blockSignals(False)

    def _apply_filter(self, text):
        text = text.strip().lower()
        for filename, code, item in self._all_items:
            name = item.text(0)
            visible = (not text) or (text in code.lower()) or (text in name.lower())
            item.setHidden(not visible)

    def _save_and_close(self):
        new_profile = {}
        for filename, code, item in self._all_items:
            if item.checkState(0) == Qt.Unchecked:
                new_profile.setdefault(filename, []).append(code)

        if save_profile(new_profile):
            total_excluded = sum(len(v) for v in new_profile.values())
            QMessageBox.information(self, "저장 완료", f"전문가 모드 설정이 저장되었습니다.\n(제외된 항목: {total_excluded}개)")
            self.accept()
        else:
            QMessageBox.critical(self, "Error", "설정 저장에 실패했습니다.")
