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

[2026-09 UI 개선] 예전엔 QDialog(모달 팝업)이었는데, "새 창을 띄우지 않았으면
좋겠다"는 사용자 요청으로 QWidget 기반 페이지로 바꿔 main_window.py의
QStackedWidget에 다른 탭들과 나란히 임베드한다(_build_pc_toolkit_page() 참고).
QDialog 의존은 원래 "닫기" 버튼의 self.accept() 하나뿐이라 그 버튼만 제거하면
나머지 로직(파일 목록/스크립트 생성/가져오기/테이블)은 그대로 재사용된다.
"""
import os
import sys

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QListWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QFileDialog, QMessageBox, QGroupBox, QLineEdit, QCheckBox
)
from PySide6.QtGui import QColor

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from core.pc_toolkit import generate_pc_script_bat  # noqa: E402
from core.crosscheck_engine import import_pc_results  # noqa: E402
from utils.app_settings import (  # noqa: E402
    get_pc_check_output_dir, load_settings, save_settings, get_base_dir,
)
from utils.expert_profile import get_excluded_codes  # noqa: E402


class PCToolkitPage(QWidget):
    def __init__(self, parent=None, db=None, on_imported=None):
        super().__init__(parent)

        self.db = db
        self._selected_files = []
        # [모달->페이지 전환] 예전엔 dlg.exec() 리턴 뒤(다이얼로그 닫힐 때) 딱 한 번
        # main_window.refresh_dashboard()를 불렀는데, 페이지에는 "닫힘" 시점이 없으니
        # DB에 실제로 반영된 직후(_run_import 성공 시) 바로 호출하도록 콜백을 받는다.
        self._on_imported = on_imported

        layout = QVBoxLayout(self)

        intro = QLabel(
            "업무용 PC는 WinRM 원격 접속이 기본적으로 막혀 있어 일반 스캔으로 점검할 수 없는 "
            "경우가 많습니다. 아래에서 로컬 실행용 진단 스크립트를 생성해 대상 PC에서 실행한 뒤, "
            "그 결과 TXT 파일을 불러오면 pc_rules.json과 동일한 판정 로직으로 채점되어 정식 "
            "스캔 이력에 반영됩니다."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        # ---- 출력 설정 ----
        out_box = QGroupBox("출력 설정")
        out_layout = QVBoxLayout(out_box)

        saved = load_settings()

        dir_row = QHBoxLayout()
        dir_row.addWidget(QLabel("출력 경로:"))
        self.pc_check_dir_input = QLineEdit(saved.get("pc_check_output_dir", ""))
        self.pc_check_dir_input.setPlaceholderText(f"비워두면 기본 경로 사용: {get_pc_check_output_dir()}")
        dir_row.addWidget(self.pc_check_dir_input, 1)
        btn_browse_dir = QPushButton("찾아보기...")
        btn_browse_dir.clicked.connect(self._browse_output_dir)
        dir_row.addWidget(btn_browse_dir)
        out_layout.addLayout(dir_row)

        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("스크립트 파일명:"))
        self.pc_check_filename_input = QLineEdit(saved.get("pc_check_script_filename", "Z-VulnScan_PC_Check.bat"))
        name_row.addWidget(self.pc_check_filename_input, 1)
        out_layout.addLayout(name_row)
        name_hint = QLabel(
            "생성되는 진단 스크립트(.bat) 파일명만 바꿉니다. 스크립트가 만드는 결과 TXT 파일명은 "
            "([PC]호스트명_OS_IP.txt) 교차검증 파서가 host/IP를 그 구조에서 읽어내므로 고정입니다."
        )
        name_hint.setWordWrap(True)
        name_hint.setStyleSheet("color: #666666;")
        out_layout.addWidget(name_hint)

        layout.addWidget(out_box)

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

        # [PC 진단 - 세세한 설정, 2026-09] Expert Mode(자산 탭 Expert 버튼/설정 >
        # 룰셋 탭)에서 이미 사전 배제해둔 PC-xx 코드가 있으면, 로컬 스크립트도
        # 그 항목은 아예 빼고 생성할 수 있게 - 라이브 스캔과 동일한 범위로 맞추기 위함.
        self.chk_apply_expert_exclude = QCheckBox("Expert Mode 제외 항목은 스크립트에서도 제외")
        self.chk_apply_expert_exclude.setChecked(True)
        self.chk_apply_expert_exclude.setToolTip(
            "자산 탭 'Expert' 또는 설정 > 룰셋 탭에서 pc_rules.json 항목 중 사전 배제한 "
            "코드가 있으면, 여기서 생성하는 로컬 스크립트에서도 그 항목을 뺍니다."
        )
        gen_box.addWidget(self.chk_apply_expert_exclude)

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

    # ------------------------------------------------------------------
    def _browse_output_dir(self):
        path = QFileDialog.getExistingDirectory(
            self, "PC 진단 출력 폴더 선택", self.pc_check_dir_input.text() or get_base_dir()
        )
        if path:
            self.pc_check_dir_input.setText(path)

    def _save_output_settings(self):
        settings = load_settings()
        settings["pc_check_output_dir"] = self.pc_check_dir_input.text().strip()
        filename = self.pc_check_filename_input.text().strip() or "Z-VulnScan_PC_Check.bat"
        settings["pc_check_script_filename"] = filename
        save_settings(settings)
        return filename

    # ------------------------------------------------------------------
    def _generate_script(self):
        try:
            excluded = get_excluded_codes("pc_rules.json") if self.chk_apply_expert_exclude.isChecked() else None
            script_text = generate_pc_script_bat(excluded_codes=excluded)
        except Exception as e:
            QMessageBox.critical(self, "생성 실패", f"진단 스크립트 생성 중 오류가 발생했습니다:\n{e}")
            return

        filename = self._save_output_settings()
        default_dir = get_pc_check_output_dir()
        default_path = os.path.join(default_dir, filename)
        path, _ = QFileDialog.getSaveFileName(
            self, "진단 스크립트 저장", default_path, "Batch script (*.bat)"
        )
        if not path:
            return

        try:
            # [주의] generate_pc_script_bat()이 반환하는 문자열은 이미 "\r\n".join()으로
            # CRLF를 직접 넣어뒀다 - 여기서 newline='\r\n'을 또 쓰면 파이썬이 그 안의
            # '\n'을 다시 치환해 '\r\r\n'으로 이중 손상된다(실측 확인됨). newline=''로
            # 번역을 끄고 문자열을 있는 그대로 써야 한다. 인코딩은 pc_toolkit.
            # generate_pc_script_bat()의 자기-재실행(ReadAllText)이 cp949로 읽으므로
            # 반드시 cp949로 맞춘다.
            with open(path, 'w', encoding='cp949', newline='') as f:
                f.write(script_text)
        except Exception as e:
            QMessageBox.critical(self, "저장 실패", f"스크립트 파일 저장 중 오류가 발생했습니다:\n{e}")
            return
        QMessageBox.information(
            self, "완료",
            f"진단 스크립트를 저장했습니다:\n{path}\n\n"
            f"대상 PC로 이 파일 하나만 옮겨 더블클릭하세요 "
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
            if self._on_imported:
                self._on_imported()

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
