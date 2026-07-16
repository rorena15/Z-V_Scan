# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[Phase 3] 설정 페이지: 로그/이력 보관 기간 · 테마 · 리포트 출력 경로 · 룰셋/전문가 프로필 ·
기본 계정/자격증명 관리를 5개 탭으로 구성한다.
"""
import os
import sys

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget,
    QLabel, QLineEdit, QPushButton, QComboBox, QSpinBox,
    QMessageBox, QFileDialog, QGroupBox, QCheckBox, QListWidget
)

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.app_settings import load_settings, save_settings, get_base_dir
from utils.secure_storage import SecureStorage
from core.ssh_inspector import SSHInspector


class SettingsDialog(QDialog):
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("설정")
        self.resize(560, 460)

        self.settings = load_settings()

        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.tabs.addTab(self._build_log_tab(), "로그/이력 보관")
        self.tabs.addTab(self._build_theme_tab(), "테마·UI")
        self.tabs.addTab(self._build_report_tab(), "리포트 출력")
        self.tabs.addTab(self._build_ruleset_tab(), "룰셋/전문가 프로필")
        self.tabs.addTab(self._build_credential_tab(), "기본 계정/자격증명")
        self.tabs.addTab(self._build_known_hosts_tab(), "호스트 키(known_hosts)")

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_save = QPushButton("저장")
        btn_save.clicked.connect(self._save_and_close)
        btn_close = QPushButton("닫기")
        btn_close.clicked.connect(self.reject)
        btn_layout.addWidget(btn_save)
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)

    # ------------------------------------------------------------------
    # 탭 1: 로그/이력 보관 기간
    # ------------------------------------------------------------------
    def _build_log_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)

        box = QGroupBox("스캔 이력 보관 기간")
        box_layout = QVBoxLayout(box)
        box_layout.addWidget(QLabel(
            "설정한 일수보다 오래된 스캔 이력(TBL_SCAN_RESULT)을 정리할 수 있습니다.\n"
            "리포트는 항상 최신 회차만 표시하므로, 오래된 이력을 지워도 최근 결과에는 영향이 없습니다."
        ))

        row = QHBoxLayout()
        row.addWidget(QLabel("보관 기간 (일):"))
        self.spin_retention = QSpinBox()
        self.spin_retention.setRange(1, 3650)
        self.spin_retention.setValue(int(self.settings.get("log_retention_days", 90)))
        row.addWidget(self.spin_retention)
        box_layout.addLayout(row)

        btn_purge = QPushButton("지금 오래된 이력 정리 실행")
        btn_purge.clicked.connect(self._run_purge_now)
        box_layout.addWidget(btn_purge)

        v.addWidget(box)
        v.addStretch()
        return w

    def _run_purge_now(self):
        days = self.spin_retention.value()
        reply = QMessageBox.question(
            self, "이력 정리 확인",
            f"{days}일보다 오래된 스캔 이력을 삭제합니다.\n계속하시겠습니까?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        deleted = self.db.purge_old_results(days)
        if deleted >= 0:
            QMessageBox.information(self, "완료", f"{deleted}건의 오래된 이력을 정리했습니다.")
        else:
            QMessageBox.critical(self, "Error", "이력 정리 중 오류가 발생했습니다.")

    # ------------------------------------------------------------------
    # 탭 2: 테마 · UI
    # ------------------------------------------------------------------
    def _build_theme_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)

        box = QGroupBox("테마")
        box_layout = QVBoxLayout(box)
        row = QHBoxLayout()
        row.addWidget(QLabel("테마 선택:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["dark (다크)", "light (라이트)"])
        self.theme_combo.setCurrentIndex(1 if self.settings.get("theme") == "light" else 0)
        row.addWidget(self.theme_combo)
        box_layout.addLayout(row)
        box_layout.addWidget(QLabel("저장 후 프로그램을 재시작하면 적용됩니다."))
        v.addWidget(box)

        log_box = QGroupBox("System Log")
        log_box_layout = QVBoxLayout(log_box)
        self.chk_show_log_panel = QCheckBox("시스템 로그 패널 표시")
        self.chk_show_log_panel.setChecked(bool(self.settings.get("show_log_panel", False)))
        log_box_layout.addWidget(self.chk_show_log_panel)
        log_box_layout.addWidget(QLabel(
            "체크하면 메인 화면 하단에 실시간 로그 패널이 나타납니다.\n"
            "평소에는 꺼두고, 진행 상황을 자세히 확인해야 할 때만 켜는 것을 권장합니다."
        ))
        v.addWidget(log_box)

        v.addStretch()
        return w

    # ------------------------------------------------------------------
    # 탭 3: 리포트 출력 경로 · 형식
    # ------------------------------------------------------------------
    def _build_report_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)

        box = QGroupBox("리포트 출력 경로")
        box_layout = QVBoxLayout(box)
        row = QHBoxLayout()
        self.report_path_input = QLineEdit(self.settings.get("report_output_dir", ""))
        self.report_path_input.setPlaceholderText(f"비워두면 기본 경로 사용: {os.path.join(get_base_dir(), 'reports')}")
        row.addWidget(self.report_path_input)
        btn_browse = QPushButton("찾아보기...")
        btn_browse.clicked.connect(self._browse_report_dir)
        row.addWidget(btn_browse)
        box_layout.addLayout(row)
        v.addWidget(box)
        v.addStretch()
        return w

    def _browse_report_dir(self):
        path = QFileDialog.getExistingDirectory(self, "리포트 출력 폴더 선택", self.report_path_input.text() or get_base_dir())
        if path:
            self.report_path_input.setText(path)

    # ------------------------------------------------------------------
    # 탭 4: 룰셋/전문가 프로필 관리
    # ------------------------------------------------------------------
    def _build_ruleset_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)

        box = QGroupBox("전문가 모드 프로필")
        box_layout = QVBoxLayout(box)
        box_layout.addWidget(QLabel(
            "룰 카테고리/개별 코드 단위 include-exclude 설정은 '전문가 모드' 창에서 관리합니다.\n"
            "(점검 명령어·중요도는 KISA 신뢰성을 위해 어디서도 수정할 수 없습니다)"
        ))
        btn_open_expert = QPushButton("전문가 모드 열기")
        btn_open_expert.clicked.connect(self._open_expert_mode)
        box_layout.addWidget(btn_open_expert)
        v.addWidget(box)
        v.addStretch()
        return w

    def _open_expert_mode(self):
        from gui.expert_mode_dialog import ExpertModeDialog
        dlg = ExpertModeDialog(self)
        dlg.exec()

    # ------------------------------------------------------------------
    # 탭 5: 기본 계정/자격증명 관리
    # ------------------------------------------------------------------
    def _build_credential_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)

        box1 = QGroupBox("기본 사용자명")
        box1_layout = QVBoxLayout(box1)
        box1_layout.addWidget(QLabel("스캔 화면의 User 입력란에 자동으로 채워질 기본 계정명입니다."))
        self.default_user_input = QLineEdit(self.settings.get("default_username", ""))
        box1_layout.addWidget(self.default_user_input)
        v.addWidget(box1)

        box2 = QGroupBox("저장된 자격증명 삭제")
        box2_layout = QVBoxLayout(box2)
        box2_layout.addWidget(QLabel(
            "OS 자격증명 관리자(Windows Credential Manager 등)에 저장된 특정 대상의\n"
            "SSH/WinRM/DB 비밀번호를 삭제합니다."
        ))
        row = QHBoxLayout()
        self.cred_ip_input = QLineEdit()
        self.cred_ip_input.setPlaceholderText("대상 IP")
        self.cred_user_input = QLineEdit()
        self.cred_user_input.setPlaceholderText("사용자명")
        row.addWidget(self.cred_ip_input)
        row.addWidget(self.cred_user_input)
        box2_layout.addLayout(row)
        btn_delete_cred = QPushButton("자격증명 삭제")
        btn_delete_cred.clicked.connect(self._delete_credential)
        box2_layout.addWidget(btn_delete_cred)
        v.addWidget(box2)

        v.addStretch()
        return w

    def _delete_credential(self):
        ip = self.cred_ip_input.text().strip()
        user = self.cred_user_input.text().strip()
        if not ip or not user:
            QMessageBox.warning(self, "입력 필요", "IP와 사용자명을 모두 입력하세요.")
            return
        SecureStorage.delete_credential(ip, user)
        QMessageBox.information(self, "완료", f"{ip} ({user}) 자격증명을 삭제했습니다.\n(저장돼 있지 않았다면 아무 변화 없음)")

    # ------------------------------------------------------------------
    # 탭 6: 호스트 키(known_hosts) 관리
    # ------------------------------------------------------------------
    def _build_known_hosts_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)

        box = QGroupBox("등록된 SSH 호스트 키")
        box_layout = QVBoxLayout(box)
        box_layout.addWidget(QLabel(
            "SSH로 접속한 서버의 호스트 키를 최초 접속 시 저장해두고, 다음부터 같은 IP에서\n"
            "다른 키가 나오면 접속을 거부합니다(MITM 탐지). 서버를 정상적으로 재설치해서\n"
            "호스트 키가 바뀐 경우에는 아래에서 해당 IP를 삭제해야 다시 접속할 수 있습니다."
        ))

        self.known_hosts_list = QListWidget()
        box_layout.addWidget(self.known_hosts_list)

        row = QHBoxLayout()
        btn_refresh = QPushButton("새로고침")
        btn_refresh.clicked.connect(self._refresh_known_hosts)
        btn_remove = QPushButton("선택 항목 삭제")
        btn_remove.clicked.connect(self._remove_selected_known_host)
        btn_clear = QPushButton("전체 초기화")
        btn_clear.clicked.connect(self._clear_all_known_hosts)
        row.addWidget(btn_refresh)
        row.addWidget(btn_remove)
        row.addWidget(btn_clear)
        box_layout.addLayout(row)

        v.addWidget(box)
        v.addStretch()

        self._refresh_known_hosts()
        return w

    def _refresh_known_hosts(self):
        self.known_hosts_list.clear()
        entries = SSHInspector.list_known_hosts()
        if not entries:
            self.known_hosts_list.addItem("(등록된 호스트 키 없음)")
            self.known_hosts_list.setEnabled(False)
            return
        self.known_hosts_list.setEnabled(True)
        for hostname, key_types in entries:
            self.known_hosts_list.addItem(f"{hostname}  [{', '.join(key_types)}]")

    def _remove_selected_known_host(self):
        item = self.known_hosts_list.currentItem()
        if not item or not self.known_hosts_list.isEnabled():
            QMessageBox.warning(self, "선택 필요", "삭제할 항목을 목록에서 선택하세요.")
            return
        hostname = item.text().split("  [")[0]
        reply = QMessageBox.question(
            self, "삭제 확인",
            f"{hostname}의 저장된 호스트 키를 삭제합니다.\n"
            "이후 이 IP로 접속하면 새 호스트 키를 다시 최초 등록합니다.\n계속하시겠습니까?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        if SSHInspector.remove_known_host(hostname):
            QMessageBox.information(self, "완료", f"{hostname} 호스트 키를 삭제했습니다.")
        else:
            QMessageBox.critical(self, "Error", "호스트 키 삭제 중 오류가 발생했습니다.")
        self._refresh_known_hosts()

    def _clear_all_known_hosts(self):
        reply = QMessageBox.question(
            self, "전체 초기화 확인",
            "등록된 모든 SSH 호스트 키를 삭제합니다.\n"
            "이후 모든 대상이 '최초 접속'으로 취급되어 호스트 키를 새로 등록합니다.\n계속하시겠습니까?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        if SSHInspector.clear_known_hosts():
            QMessageBox.information(self, "완료", "모든 호스트 키를 초기화했습니다.")
        else:
            QMessageBox.critical(self, "Error", "호스트 키 초기화 중 오류가 발생했습니다.")
        self._refresh_known_hosts()

    # ------------------------------------------------------------------
    def _save_and_close(self):
        self.settings["log_retention_days"] = self.spin_retention.value()
        self.settings["theme"] = "light" if self.theme_combo.currentIndex() == 1 else "dark"
        self.settings["show_log_panel"] = self.chk_show_log_panel.isChecked()
        self.settings["report_output_dir"] = self.report_path_input.text().strip()
        self.settings["default_username"] = self.default_user_input.text().strip()

        if save_settings(self.settings):
            QMessageBox.information(self, "저장 완료", "설정이 저장되었습니다.\n(테마는 재시작 후 적용됩니다)")
            self.accept()
        else:
            QMessageBox.critical(self, "Error", "설정 저장에 실패했습니다.")
