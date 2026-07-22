# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[PC 진단 도구] WinRM이 안 되는 업무용 PC를 위해, ① 로컬 실행용 PowerShell 스크립트를
생성해 저장하고, ② 그 스크립트가 만든 TXT 결과를 불러와 정식 스캔 이력 DB에 반영한다.

교차검증(crosscheck_dialog.py)과 달리 "독립 대조"가 목적이 아니라 Z-VulnScan 자신의
대체 스캔 경로이므로, 여기서 가져온 결과는 TBL_SCAN_RESULT에 그대로 쓰인다.
"""
import os
import sys

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QListWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QFileDialog, QMessageBox
)
from PySide6.QtGui import QColor

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from core.pc_toolkit import generate_pc_script, generate_pc_launcher_bat  # noqa: E402
from core.crosscheck_engine import import_pc_results  # noqa: E402
from utils.app_settings import get_report_output_dir  # noqa: E402


class PCToolkitDialog(QDialog):
    def __init__(self, parent=None, db=None):
        super().__init__(parent)
        self.setWindowTitle("PC 진단 도구 (로컬 스크립트)")
        self.resize(1000, 640)

        self.db = db
        self._selected_files = []

        layout = QVBoxLayout(self)

        intro = QLabel(
            "업무용 PC는 WinRM 원격 접속이 기본적으로 막혀 있어 일반 스캔으로 점검할 수 없는 "
            "경우가 많습니다. 아래에서 로컬 실행용 진단 스크립트를 생성해 대상 PC에서 실행한 뒤, "
            "그 결과 TXT 파일을 불러오면 pc_rules.json과 동일한 판정 로직으로 채점되어 정식 "
            "스캔 이력에 반영됩니다."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        # ---- ① 스크립트 생성 ----
        gen_box = QVBoxLayout()
        gen_row = QHBoxLayout()
        btn_generate = QPushButton("① 진단 스크립트 생성 및 저장...")
        btn_generate.clicked.connect(self._generate_script)
        gen_row.addWidget(btn_generate)
        gen_row.addStretch()
        gen_box.addLayout(gen_row)
        gen_hint = QLabel(
            "생성된 .bat 파일을 대상 PC로 옮겨 더블클릭하세요(관리자 권한 승인 창이 자동으로 "
            "뜹니다). 판정 없이 원본 명령 출력만 수집하므로 실행 자체는 안전합니다."
        )
        gen_hint.setWordWrap(True)
        gen_hint.setStyleSheet("color: #666666;")
        gen_box.addWidget(gen_hint)
        layout.addLayout(gen_box)

        # ---- ② 결과 가져오기 ----
        file_row = QHBoxLayout()
        btn_pick = QPushButton("② 결과 TXT 선택...")
        btn_pick.clicked.connect(self._pick_files)
        btn_clear = QPushButton("목록 비우기")
        btn_clear.clicked.connect(self._clear_files)
        file_row.addWidget(btn_pick)
        file_row.addWidget(btn_clear)
        file_row.addStretch()
        layout.addLayout(file_row)

        self.file_list = QListWidget()
        self.file_list.setMaximumHeight(90)
        layout.addWidget(self.file_list)

        run_row = QHBoxLayout()
        self.btn_import = QPushButton("가져오기 및 DB 반영")
        self.btn_import.clicked.connect(self._run_import)
        run_row.addWidget(self.btn_import)
        self.summary_label = QLabel("")
        run_row.addWidget(self.summary_label)
        run_row.addStretch()
        layout.addLayout(run_row)

        self.warning_label = QLabel("")
        self.warning_label.setStyleSheet(
            "background-color: #F6DFA6; color: #8A5A00; padding: 6px; border-radius: 4px;"
        )
        self.warning_label.setWordWrap(True)
        self.warning_label.setVisible(False)
        layout.addWidget(self.warning_label)

        self.table = QTableWidget()
        headers = ["Host", "IP", "Code", "Name", "판정", "DB 반영", "비고"]
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        layout.addWidget(self.table, 1)

        bottom_row = QHBoxLayout()
        bottom_row.addStretch()
        btn_close = QPushButton("닫기")
        btn_close.clicked.connect(self.accept)
        bottom_row.addWidget(btn_close)
        layout.addLayout(bottom_row)

    # ------------------------------------------------------------------
    def _generate_script(self):
        try:
            script_text = generate_pc_script()
        except Exception as e:
            QMessageBox.critical(self, "생성 실패", f"진단 스크립트 생성 중 오류가 발생했습니다:\n{e}")
            return

        default_dir = get_report_output_dir()
        default_path = os.path.join(default_dir, "Z-VulnScan_PC_Check.ps1")
        path, _ = QFileDialog.getSaveFileName(
            self, "진단 스크립트 저장", default_path, "PowerShell script (*.ps1)"
        )
        if not path:
            return

        ps1_name = os.path.basename(path)
        bat_path = os.path.splitext(path)[0] + ".bat"
        try:
            with open(path, 'w', encoding='utf-8-sig') as f:
                f.write(script_text)
            # [주의] .bat은 cmd.exe가 읽는다 - UTF-8 BOM이 섞이면 @echo off 첫 줄이 깨질 수
            # 있고, 본문(ASCII)에 이어 파일명(한글일 수 있음)도 그대로 들어가므로, 대상 PC의
            # 기본 코드페이지(현장 PC 대부분 한국어 Windows, cp949)로 저장해 둘 다 안전하게 한다.
            with open(bat_path, 'w', encoding='cp949', newline='') as f:
                f.write(generate_pc_launcher_bat(ps1_name))
        except Exception as e:
            QMessageBox.critical(self, "저장 실패", f"스크립트 파일 저장 중 오류가 발생했습니다:\n{e}")
            return
        QMessageBox.information(
            self, "완료",
            f"진단 스크립트를 저장했습니다:\n{path}\n{bat_path}\n\n"
            f"대상 PC로 두 파일을 함께 옮겨 {os.path.basename(bat_path)}를 더블클릭하세요 "
            "(관리자 권한 승인 창이 자동으로 뜹니다). 완료되면 같은 폴더에 생성되는 "
            "[PC]로 시작하는 .txt 파일을 아래 ②에서 불러오세요."
        )

    # ------------------------------------------------------------------
    def _pick_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "PC 진단 결과 TXT 선택", "", "Text files (*.txt)")
        for f in files:
            if f not in self._selected_files:
                self._selected_files.append(f)
        self._refresh_file_list()

    def _clear_files(self):
        self._selected_files = []
        self._refresh_file_list()

    def _refresh_file_list(self):
        self.file_list.clear()
        for f in self._selected_files:
            self.file_list.addItem(f)

    # ------------------------------------------------------------------
    def _run_import(self):
        if not self._selected_files:
            QMessageBox.warning(self, "파일 없음", "먼저 결과 TXT 파일을 선택하세요.")
            return
        if self.db is None:
            QMessageBox.warning(self, "DB 없음", "DB 연결 없이는 결과를 반영할 수 없습니다.")
            return

        result = import_pc_results(self._selected_files, self.db)

        self.warning_label.setVisible(False)
        notes = []
        parse_errors = result.get("parse_errors", [])
        failed_files = result.get("failed_files", [])
        if parse_errors:
            notes.append(f"{len(parse_errors)}개 항목 파싱 실패")
        if failed_files:
            notes.append(f"{len(failed_files)}개 파일을 읽지 못했습니다: {', '.join(os.path.basename(p) for p in failed_files)}")
        if notes:
            self.warning_label.setText(" / ".join(notes))
            self.warning_label.setVisible(True)

        self._populate_table(result.get("imported_entries", []))

        s = result.get("summary", {})
        self.summary_label.setText(
            f"총 {s.get('total', 0)} / DB 반영 {s.get('imported', 0)} / "
            f"건너뜀 {s.get('skipped', 0)} / 수동확인·해당없음 {s.get('manual_or_na', 0)}"
        )

        if s.get('imported'):
            QMessageBox.information(
                self, "완료",
                f"{s.get('imported', 0)}건을 스캔 이력 DB에 반영했습니다. "
                "대시보드/리포트에서 확인할 수 있습니다."
            )

    def _populate_table(self, entries):
        self.table.setRowCount(0)
        for entry in entries:
            row = self.table.rowCount()
            self.table.insertRow(row)
            imported = entry.get("imported")
            values = [
                entry.get("host"), entry.get("ip"), entry.get("code"), entry.get("name"),
                entry.get("status") or "-", "O" if imported else "-", entry.get("note") or "",
            ]
            color = QColor("#DCEFE0" if imported else "#EDEDEC")
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value) if value is not None else "")
                item.setBackground(color)
                self.table.setItem(row, col, item)
