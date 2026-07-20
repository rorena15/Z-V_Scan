# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[교차검증 모드] 외부 컨설턴트가 산출한 TXT 결과 파일을 오프라인으로 불러와
Z-VulnScan 판정 로직으로 재판정/대조한다.

이 다이얼로그는 DB(TBL_SCAN_RESULT)에 전혀 접근하지 않는다 - __init__이 db 인자를
받지 않는 것으로 그 사실을 시그니처 레벨에서 강제한다. 결과는 이 창 안에서만
표시되고, "엑셀로 내보내기"를 눌러야만 독립 파일로 저장된다.
"""
import os
import sys

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QFileDialog, QMessageBox
)
from PySide6.QtGui import QColor

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from core.crosscheck_engine import run_cross_check  # noqa: E402
from output.crosscheck_report import CrossCheckReportGenerator  # noqa: E402


class CrossCheckDialog(QDialog):
    CLASS_LABEL = {
        "MATCH": "일치", "MISMATCH": "불일치",
        "MISSING_IN_RULESET": "룰셋에 코드 없음",
        "AMBIGUOUS_RULESET": "룰셋 판별 불가",
        "PARSE_ERROR": "파싱 실패",
    }
    CLASS_COLOR = {
        "MATCH": "#DCEFE0", "MISMATCH": "#FBD9D9",
        "MISSING_IN_RULESET": "#F6DFA6", "AMBIGUOUS_RULESET": "#F6DFA6",
        "PARSE_ERROR": "#EDEDEC",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("교차검증 (오프라인 TXT 재판정)")
        self.resize(1100, 650)

        self._selected_files = []
        self._last_result = None

        layout = QVBoxLayout(self)

        intro = QLabel(
            "컨설턴트가 산출한 TXT 결과 파일(Z-VulnScan 리포트 포맷과 동일)을 선택해 "
            "판정 로직으로 재판정하고 원 판정과 대조합니다. 네트워크 접속이나 실제 "
            "스캔은 수행하지 않으며, DB에도 저장하지 않습니다."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        file_row = QHBoxLayout()
        btn_add_files = QPushButton("TXT 파일 선택...")
        btn_add_files.clicked.connect(self._pick_files)
        btn_add_folder = QPushButton("폴더 선택...")
        btn_add_folder.clicked.connect(self._pick_folder)
        btn_clear = QPushButton("목록 비우기")
        btn_clear.clicked.connect(self._clear_files)
        file_row.addWidget(btn_add_files)
        file_row.addWidget(btn_add_folder)
        file_row.addWidget(btn_clear)
        file_row.addStretch()
        layout.addLayout(file_row)

        self.file_list = QListWidget()
        self.file_list.setMaximumHeight(100)
        layout.addWidget(self.file_list)

        run_row = QHBoxLayout()
        self.btn_run = QPushButton("교차검증 실행")
        self.btn_run.clicked.connect(self._run_cross_check)
        run_row.addWidget(self.btn_run)
        self.summary_label = QLabel("")
        run_row.addWidget(self.summary_label)
        run_row.addStretch()
        layout.addLayout(run_row)

        self.warning_label = QLabel("")
        self.warning_label.setStyleSheet("background-color: #F6DFA6; color: #8A5A00; padding: 6px; border-radius: 4px;")
        self.warning_label.setWordWrap(True)
        self.warning_label.setVisible(False)
        layout.addWidget(self.warning_label)

        self.table = QTableWidget()
        headers = ["Host", "IP", "Code", "Name", "컨설턴트 판정", "재판정", "구분", "비고"]
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        layout.addWidget(self.table, 1)

        bottom_row = QHBoxLayout()
        bottom_row.addStretch()
        self.btn_export = QPushButton("엑셀로 내보내기")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self._export_excel)
        bottom_row.addWidget(self.btn_export)
        btn_close = QPushButton("닫기")
        btn_close.clicked.connect(self.reject)
        bottom_row.addWidget(btn_close)
        layout.addLayout(bottom_row)

    # ------------------------------------------------------------------
    def _pick_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "컨설턴트 결과 TXT 선택", "", "Text files (*.txt)")
        for f in files:
            if f not in self._selected_files:
                self._selected_files.append(f)
        self._refresh_file_list()

    def _pick_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "컨설턴트 결과 폴더 선택")
        if not folder:
            return
        for name in sorted(os.listdir(folder)):
            if name.lower().endswith(".txt"):
                path = os.path.join(folder, name)
                if path not in self._selected_files:
                    self._selected_files.append(path)
        self._refresh_file_list()

    def _clear_files(self):
        self._selected_files = []
        self._refresh_file_list()

    def _refresh_file_list(self):
        self.file_list.clear()
        for f in self._selected_files:
            self.file_list.addItem(f)

    # ------------------------------------------------------------------
    def _run_cross_check(self):
        if not self._selected_files:
            QMessageBox.warning(self, "파일 없음", "먼저 TXT 파일 또는 폴더를 선택하세요.")
            return

        result = run_cross_check(self._selected_files)
        self._last_result = result

        self.warning_label.setVisible(False)
        notes = []
        parse_errors = result.get("parse_errors", [])
        failed_files = result.get("failed_files", [])
        if parse_errors:
            notes.append(f"{len(parse_errors)}개 항목 파싱 실패 - 수동 확인 필요")
        if failed_files:
            notes.append(f"{len(failed_files)}개 파일을 읽지 못했습니다: {', '.join(os.path.basename(p) for p in failed_files)}")
        if notes:
            self.warning_label.setText(" / ".join(notes))
            self.warning_label.setVisible(True)

        self._populate_table(result.get("diff_entries", []))

        s = result.get("summary", {})
        self.summary_label.setText(
            f"총 {s.get('total', 0)} / 일치 {s.get('match', 0)} / 불일치 {s.get('mismatch', 0)} / "
            f"판별불가 {s.get('ambiguous', 0)} / 룰셋에 없음 {s.get('missing_in_ruleset', 0)} / "
            f"파싱실패 {s.get('parse_error', 0)} / 근사치 {s.get('approx_count', 0)} / "
            f"누락코드 {s.get('missing_codes', 0)}"
        )
        self.btn_export.setEnabled(bool(result.get("diff_entries")))

    def _populate_table(self, diff_entries):
        self.table.setRowCount(0)
        for entry in diff_entries:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [
                entry.get("host"), entry.get("ip"), entry.get("code"), entry.get("name"),
                entry.get("consultant_result"), entry.get("rejudged_result"),
                self.CLASS_LABEL.get(entry.get("classification"), entry.get("classification")),
                entry.get("approx_note") or entry.get("detail_note") or "",
            ]
            color = QColor(self.CLASS_COLOR.get(entry.get("classification"), "#FFFFFF"))
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value) if value is not None else "")
                item.setBackground(color)
                self.table.setItem(row, col, item)

    # ------------------------------------------------------------------
    def _export_excel(self):
        if not self._last_result:
            return
        try:
            path = CrossCheckReportGenerator(self._last_result).generate()
        except Exception as e:
            QMessageBox.critical(self, "내보내기 실패", f"엑셀 생성 중 오류가 발생했습니다:\n{e}")
            return
        QMessageBox.information(self, "완료", f"교차검증 결과를 저장했습니다:\n{path}")
