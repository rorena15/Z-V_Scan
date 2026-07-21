# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[교차검증 모드] 외부 컨설턴트가 산출한 TXT 결과 파일을 불러와 Z-VulnScan과 대조한다.

두 가지 대조 방식을 지원한다:
- 재판정(오프라인, 기본값): 컨설턴트 증적을 Z-VulnScan 룰 키워드로 다시 판정한다.
  DB(TBL_SCAN_RESULT)에 전혀 접근하지 않는다. 다만 서로 다른 스크립트가 만든 증적
  문장이 우리 룰의 safe_keyword("OK" 등)와 우연히 일치할 수 없어 실측상 신뢰도가
  낮다는 게 확인됐다 - 예: safe_keyword가 "OK"인 룰은 컨설턴트의 한국어 서술형
  증적에 "OK"가 나올 리 없어 거의 항상 취약으로 오판정된다.
- DB 직접대조: 재판정을 하지 않고, Z-VulnScan이 같은 호스트를 실제로 스캔해 DB에
  이미 저장해 둔 최종 판정값을 코드 단위로 직접 비교한다. 키워드 매칭 문제 자체를
  우회하므로 더 신뢰할 수 있지만, Z-VulnScan이 그 호스트를 실제로 스캔한 이력이
  있어야만 쓸 수 있고 DB에 접근한다(main_window.py가 self.db를 넘겨준 경우에만
  이 모드를 켤 수 있다).
"""
import os
import sys

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QFileDialog, QMessageBox, QRadioButton, QButtonGroup
)
from PySide6.QtGui import QColor

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from core.crosscheck_engine import run_cross_check, run_cross_check_db  # noqa: E402
from output.crosscheck_report import CrossCheckReportGenerator  # noqa: E402


class CrossCheckDialog(QDialog):
    CLASS_LABEL = {
        "MATCH": "일치", "MISMATCH": "불일치",
        "MISSING_IN_RULESET": "룰셋에 코드 없음",
        "AMBIGUOUS_RULESET": "룰셋 판별 불가",
        "PARSE_ERROR": "파싱 실패",
        "NO_KISA_CODE": "KISA 코드 없음",
        "NO_CONSULTANT_RESULT": "컨설턴트 결과 없음",
        "CONSULTANT_UNCERTAIN": "컨설턴트도 확인 필요",
        "MANUAL_VERIFICATION_NEEDED": "수동 검증 필요(세부기준형)",
        "DB_NO_ASSET": "Z-VulnScan 스캔 자산 없음",
        "DB_NO_SCAN_RESULT": "Z-VulnScan 스캔 이력 없음",
    }
    CLASS_COLOR = {
        "MATCH": "#DCEFE0", "MISMATCH": "#FBD9D9",
        "MISSING_IN_RULESET": "#F6DFA6", "AMBIGUOUS_RULESET": "#F6DFA6",
        "PARSE_ERROR": "#EDEDEC",
        "NO_KISA_CODE": "#EDEDEC", "NO_CONSULTANT_RESULT": "#EDEDEC",
        "CONSULTANT_UNCERTAIN": "#F6DFA6",
        "MANUAL_VERIFICATION_NEEDED": "#F6DFA6",
        "DB_NO_ASSET": "#EDEDEC", "DB_NO_SCAN_RESULT": "#EDEDEC",
    }

    def __init__(self, parent=None, db=None):
        super().__init__(parent)
        self.setWindowTitle("교차검증 (컨설턴트 TXT 대조)")
        self.resize(1100, 680)

        self.db = db
        self._selected_files = []
        self._last_result = None

        layout = QVBoxLayout(self)

        intro = QLabel(
            "컨설턴트가 산출한 TXT 결과 파일을 선택해 Z-VulnScan과 대조합니다. Z-VulnScan "
            "자체 리포트 포맷과 실제 KISA 대조검증 스크립트 포맷을 모두 자동 인식합니다."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("대조 방식:"))
        self.rb_rejudge = QRadioButton("재판정(오프라인, DB 미사용)")
        self.rb_rejudge.setToolTip(
            "컨설턴트 증적을 Z-VulnScan 룰 키워드로 재판정합니다. DB에 접근하지 않지만,\n"
            "서로 다른 스크립트의 증적 문장은 우리 키워드와 우연히 일치하기 어려워 신뢰도가 낮습니다."
        )
        self.rb_dbcompare = QRadioButton("DB 직접대조 (Z-VulnScan 실제 스캔 결과와 비교, 추천)")
        self.rb_dbcompare.setToolTip(
            "재판정 없이, Z-VulnScan이 같은 호스트를 실제로 스캔해 DB에 저장한 최종 판정값과\n"
            "코드 단위로 직접 비교합니다. 재판정보다 훨씬 신뢰할 수 있지만 Z-VulnScan이 그 호스트를\n"
            "실제로 스캔한 이력이 있어야 하며, DB에 접근합니다."
        )
        self.rb_dbcompare.setEnabled(self.db is not None)
        if self.db is None:
            self.rb_dbcompare.setToolTip("이 창이 DB 연결 없이 열려서 사용할 수 없습니다.")
        # [신뢰도] 실측상 재판정 모드는 DB 직접대조보다 일치율이 크게 낮다(서로 다른 스크립트의
        # 증적 문장이 우리 키워드와 우연히 일치하기 어려움) - DB를 쓸 수 있으면 그쪽을 기본값으로
        # 켜서, 사용자가 굳이 재판정을 고르지 않는 한 더 신뢰할 수 있는 결과를 먼저 보게 한다.
        if self.db is not None:
            self.rb_dbcompare.setChecked(True)
        else:
            self.rb_rejudge.setChecked(True)
        self.mode_group = QButtonGroup(self)
        self.mode_group.addButton(self.rb_rejudge)
        self.mode_group.addButton(self.rb_dbcompare)
        mode_row.addWidget(self.rb_rejudge)
        mode_row.addWidget(self.rb_dbcompare)
        mode_row.addStretch()
        layout.addLayout(mode_row)

        self.mode_caveat_label = QLabel()
        self.mode_caveat_label.setStyleSheet(
            "background-color: #F6DFA6; color: #8A5A00; padding: 6px; border-radius: 4px;"
        )
        self.mode_caveat_label.setWordWrap(True)
        layout.addWidget(self.mode_caveat_label)
        self.rb_rejudge.toggled.connect(self._update_mode_caveat)
        self._update_mode_caveat()

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
        headers = ["Host", "IP", "Code", "Name", "컨설턴트 판정", "Z-VulnScan 판정", "구분", "비고"]
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
    def _update_mode_caveat(self):
        """[신뢰도 고지] 재판정 모드를 선택한 동안은 항상 보이는 경고를 띄운다 - 마우스를
        올려야만 보이는 툴팁만으로는 실측 신뢰도 차이(재판정 vs DB 직접대조)가 잘 전달되지
        않는다는 게 실제로 확인됐다."""
        if self.rb_rejudge.isChecked():
            self.mode_caveat_label.setText(
                "⚠ 재판정 모드는 서로 다른 스크립트의 증적 문장이 Z-VulnScan 룰 키워드와 우연히 "
                "일치하기 어려워 실측상 일치율이 낮습니다. Z-VulnScan이 이 호스트를 실제로 스캔한 "
                "이력이 있다면 \"DB 직접대조\" 모드가 훨씬 정확합니다."
            )
            self.mode_caveat_label.setVisible(True)
        else:
            self.mode_caveat_label.setVisible(False)

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

        if self.rb_dbcompare.isChecked():
            if self.db is None:
                QMessageBox.warning(self, "DB 없음", "DB 직접대조 모드를 쓸 수 없는 창입니다.")
                return
            result = run_cross_check_db(self._selected_files, self.db)
        else:
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
        if self.rb_dbcompare.isChecked():
            self.summary_label.setText(
                f"[DB 직접대조] 총 {s.get('total', 0)} / 일치 {s.get('match', 0)} / 불일치 {s.get('mismatch', 0)} / "
                f"KISA코드없음 {s.get('no_kisa_code', 0)} / 파싱실패 {s.get('parse_error', 0)} / "
                f"컨설턴트결과없음 {s.get('no_consultant_result', 0)} / 컨설턴트도확인필요 {s.get('consultant_uncertain', 0)} / "
                f"자산없음 {s.get('db_no_asset', 0)} / DB스캔이력없음 {s.get('db_no_scan_result', 0)}"
            )
        else:
            self.summary_label.setText(
                f"[재판정] 총 {s.get('total', 0)} / 일치 {s.get('match', 0)} / 불일치 {s.get('mismatch', 0)} / "
                f"판별불가 {s.get('ambiguous', 0)} / 룰셋에 없음 {s.get('missing_in_ruleset', 0)} / "
                f"파싱실패 {s.get('parse_error', 0)} / 근사치 {s.get('approx_count', 0)} / "
                f"누락코드 {s.get('missing_codes', 0)} / KISA코드없음 {s.get('no_kisa_code', 0)} / "
                f"컨설턴트결과없음 {s.get('no_consultant_result', 0)} / 컨설턴트도확인필요 {s.get('consultant_uncertain', 0)} / "
                f"수동검증필요(세부기준형) {s.get('manual_verification_needed', 0)}"
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
