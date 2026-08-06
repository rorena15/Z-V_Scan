# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[Phase 3] 설정 페이지: 로그/이력 보관 기간 · 테마 · 리포트 출력 경로 · 룰셋/전문가 프로필 ·
기본 계정/자격증명 · 호스트 키 · 라이선스 정보를 좌측 사이드바 메뉴 + 우측 상세 화면으로 구성한다.
"""
import os
import sys

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QWidget,
    QLabel, QLineEdit, QPushButton, QComboBox, QSpinBox,
    QMessageBox, QFileDialog, QGroupBox, QCheckBox, QListWidget,
    QStackedWidget
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
        self.resize(760, 500)

        self.settings = load_settings()

        root_layout = QVBoxLayout(self)

        body_layout = QHBoxLayout()
        root_layout.addLayout(body_layout, 1)

        # 좌측 사이드바 메뉴
        self.nav_list = QListWidget()
        self.nav_list.setFixedWidth(170)
        self.nav_list.currentRowChanged.connect(self._on_nav_changed)
        body_layout.addWidget(self.nav_list)

        # 우측 상세 화면
        self.pages = QStackedWidget()
        body_layout.addWidget(self.pages, 1)

        pages = [
            ("로그/이력 보관", self._build_log_tab()),
            ("테마·UI", self._build_theme_tab()),
            ("리포트 출력", self._build_report_tab()),
            ("룰셋/전문가 프로필", self._build_ruleset_tab()),
            ("기본 계정/자격증명", self._build_credential_tab()),
            ("호스트 키(known_hosts)", self._build_known_hosts_tab()),
            ("라이선스", self._build_license_tab()),
        ]
        for label, page in pages:
            self.nav_list.addItem(label)
            self.pages.addWidget(page)
        self.nav_list.setCurrentRow(0)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_save = QPushButton("저장")
        btn_save.clicked.connect(self._save_and_close)
        btn_close = QPushButton("닫기")
        btn_close.clicked.connect(self.reject)
        btn_layout.addWidget(btn_save)
        btn_layout.addWidget(btn_close)
        root_layout.addLayout(btn_layout)

    def _on_nav_changed(self, row):
        if row >= 0:
            self.pages.setCurrentIndex(row)

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

        version_box = QGroupBox("룰셋 버전 (KISA 가이드 개정 대응)")
        version_box_layout = QVBoxLayout(version_box)
        version_box_layout.addWidget(QLabel(self._build_ruleset_version_text()))
        v.addWidget(version_box)

        update_box = QGroupBox("룰셋 자동 업데이트")
        update_box_layout = QVBoxLayout(update_box)
        update_box_layout.addWidget(QLabel(
            "GitHub Releases에서 서명된 룰셋 업데이트를 확인합니다. 서명 검증에 실패하면\n"
            "어떤 파일도 반영하지 않습니다. 기본값은 꺼짐입니다 - 인터넷이 없거나 외부\n"
            "접속이 통제된 환경(OT/에어갭 등)에서는 켜지 않는 걸 권장합니다."
        ))
        self.chk_ruleset_auto_update = QCheckBox("룰셋 자동 업데이트 확인 사용")
        self.chk_ruleset_auto_update.setChecked(bool(self.settings.get("ruleset_auto_update", False)))
        update_box_layout.addWidget(self.chk_ruleset_auto_update)

        btn_check_now = QPushButton("지금 확인")
        btn_check_now.setToolTip("설정 저장 여부와 무관하게 지금 이 자리에서 1회 확인합니다.")
        btn_check_now.clicked.connect(self._check_ruleset_update_now)
        update_box_layout.addWidget(btn_check_now)
        v.addWidget(update_box)

        v.addStretch()
        return w

    def _check_ruleset_update_now(self):
        """[수동 확인] Settings에서 아직 저장 안 했어도, 이 체크박스 현재 상태 기준으로
        1회 즉시 확인한다 - "켜고 저장하고 다시 열어서 눌러야" 하는 번거로움을 피하려고
        app_settings.ruleset_auto_update를 잠깐 체크박스 값으로 덮어썼다가 원복한다."""
        from utils.app_settings import load_settings as _load, save_settings as _save
        from utils import rule_update

        original = _load()
        temp = dict(original)
        temp["ruleset_auto_update"] = self.chk_ruleset_auto_update.isChecked()
        _save(temp)
        try:
            status, detail = rule_update.check_and_apply_update()
        finally:
            _save(original)

        title = {
            "UPDATED": "업데이트 완료", "UP_TO_DATE": "이미 최신",
            "VERIFY_FAILED": "서명 검증 실패", "DISABLED": "비활성화됨",
            "NO_RELEASE_ASSET": "업데이트 없음", "ERROR": "오류",
        }.get(status, status)
        if status == "VERIFY_FAILED":
            QMessageBox.critical(self, title, detail)
        elif status == "ERROR":
            QMessageBox.warning(self, title, detail)
        else:
            QMessageBox.information(self, title, detail)

    @staticmethod
    def _build_ruleset_version_text():
        manifest_path = os.path.join(get_base_dir(), 'rules', 'ruleset_manifest.json')
        if not os.path.exists(manifest_path):
            return "룰셋 버전 정보 파일(ruleset_manifest.json)을 찾을 수 없습니다."
        try:
            import json
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest = json.load(f)
            lines = []
            for filename, info in manifest.get("rulesets", {}).items():
                lines.append(f"{filename}: {info.get('item_count')}개 항목 (갱신일 {info.get('last_updated')})")
            return "\n".join(lines) if lines else "룰셋 버전 정보가 비어 있습니다."
        except Exception:
            return "룰셋 버전 정보를 읽는 중 오류가 발생했습니다."

    def _open_expert_mode(self):
        main_win = self.parent()
        if main_win is not None and hasattr(main_win, 'license_mgr') and not main_win.license_mgr.can_use_expert_mode():
            QMessageBox.warning(self, "License Restricted",
                "전문가 모드는 Enterprise 등급 전용 기능입니다.\n"
                f"(현재 등급: {main_win.license_mgr.effective_tier()})")
            return
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
    # 탭 7: 라이선스 정보
    # ------------------------------------------------------------------
    def _build_license_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)

        box = QGroupBox("현재 라이선스")
        box_layout = QVBoxLayout(box)

        self.lbl_current_tier = QLabel()
        self.lbl_current_tier.setStyleSheet("font-size: 13pt; font-weight: bold;")
        box_layout.addWidget(self.lbl_current_tier)
        self.lbl_expiry = QLabel()
        box_layout.addWidget(self.lbl_expiry)

        # [수정 불가, 입력/삭제만 가능] 기존 키를 고쳐 쓰는 개념이 없다 - 새 키를
        # 입력하면 통째로 교체되고, 삭제하면 키 없는 기본 상태(Enterprise)로 돌아간다.
        btn_row = QHBoxLayout()
        btn_activate = QPushButton("라이선스 키 입력")
        btn_activate.clicked.connect(self._open_license_dialog)
        btn_row.addWidget(btn_activate)
        self.btn_delete_license = QPushButton("라이선스 삭제")
        self.btn_delete_license.clicked.connect(self._delete_license)
        btn_row.addWidget(self.btn_delete_license)
        box_layout.addLayout(btn_row)
        v.addWidget(box)

        features_box = QGroupBox("현재 등급에서 사용 가능한 기능")
        features_layout = QVBoxLayout(features_box)
        self.lbl_current_features = QLabel()
        features_layout.addWidget(self.lbl_current_features)
        v.addWidget(features_box)
        v.addStretch()

        self._refresh_license_page()
        return w

    def _open_license_dialog(self):
        main_win = self.parent()
        if main_win is None or not hasattr(main_win, 'open_license_dialog'):
            return
        main_win.open_license_dialog()
        self._refresh_license_page()

    def _delete_license(self):
        main_win = self.parent()
        license_mgr = getattr(main_win, 'license_mgr', None) if main_win else None
        if not license_mgr or not license_mgr.expiry_date:
            QMessageBox.information(self, "안내", "삭제할 라이선스 키가 등록되어 있지 않습니다.")
            return
        reply = QMessageBox.question(
            self, "라이선스 삭제 확인",
            "등록된 라이선스 키를 삭제합니다.\n삭제 후에는 키가 없는 기본 상태(Enterprise)로 동작합니다.\n계속하시겠습니까?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        from core.license_validator import LicenseValidator
        try:
            if os.path.exists(LicenseValidator.LICENSE_FILE):
                os.remove(LicenseValidator.LICENSE_FILE)
        except OSError:
            QMessageBox.critical(self, "Error", "라이선스 파일 삭제에 실패했습니다.")
            return
        license_mgr.current_tier = license_mgr.TIER_ENTERPRISE
        license_mgr.expiry_date = None
        if hasattr(main_win, 'update_ui_by_license'):
            main_win.update_ui_by_license()
        QMessageBox.information(self, "완료", "라이선스가 삭제되었습니다.")
        self._refresh_license_page()

    def _refresh_license_page(self):
        license_mgr = getattr(self.parent(), 'license_mgr', None)
        if not license_mgr:
            self.lbl_current_tier.setText("현재 등급: -")
            self.lbl_expiry.setText("사용 가능 기간: -")
            self.lbl_current_features.setText("-")
            self.btn_delete_license.setEnabled(False)
            return

        tier = license_mgr.effective_tier()
        self.lbl_current_tier.setText(f"현재 등급: {tier}")
        self.lbl_expiry.setText(f"사용 가능 기간: {self._format_expiry(license_mgr)}")
        self.lbl_current_features.setText(self._build_current_features_text(license_mgr))
        # 실제로 등록된(license.dat 기반) 키가 있을 때만 삭제 가능 - 숨겨진 개발자
        # 미리보기 등급 전환은 파일이 없으므로 삭제 대상이 아니다.
        self.btn_delete_license.setEnabled(bool(license_mgr.expiry_date))

    @staticmethod
    def _build_current_features_text(license_mgr):
        excel = "가능" if license_mgr.can_export_excel() else "불가 (PDF만 가능)"
        evidence = {"full": "전체 항목 제공", "vuln_only": "취약/부분만족 항목만 제공"}[license_mgr.evidence_level()]
        remediation = {"full": "전체 제공", "partial": "중요도 상/중 항목만 제공", "none": "미제공"}[license_mgr.remediation_level()]
        expert = "사용 가능" if license_mgr.can_use_expert_mode() else "사용 불가 (Enterprise 전용)"
        return (
            f"• Excel 리포트: {excel}\n"
            f"• 상세 증적(Evidence): {evidence}\n"
            f"• 조치 방안: {remediation}\n"
            f"• 전문가 모드: {expert}"
        )

    @staticmethod
    def _format_expiry(license_mgr):
        if license_mgr.expiry_date:
            return str(license_mgr.expiry_date)
        if license_mgr.effective_tier() == license_mgr.TIER_ENTERPRISE:
            return "무제한 (라이선스 키 미등록 - 기본 Enterprise 모드)"
        return "무제한 (개발자 미리보기 모드 - 프로그램 재시작 시 초기화됨)"

    # ------------------------------------------------------------------
    def _save_and_close(self):
        self.settings["log_retention_days"] = self.spin_retention.value()
        self.settings["theme"] = "light" if self.theme_combo.currentIndex() == 1 else "dark"
        self.settings["show_log_panel"] = self.chk_show_log_panel.isChecked()
        self.settings["report_output_dir"] = self.report_path_input.text().strip()
        self.settings["default_username"] = self.default_user_input.text().strip()
        self.settings["ruleset_auto_update"] = self.chk_ruleset_auto_update.isChecked()

        if save_settings(self.settings):
            QMessageBox.information(self, "저장 완료", "설정이 저장되었습니다.\n(테마는 재시작 후 적용됩니다)")
            self.accept()
        else:
            QMessageBox.critical(self, "Error", "설정 저장에 실패했습니다.")
