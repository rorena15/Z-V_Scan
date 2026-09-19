# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import re
from datetime import datetime
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QTextEdit, QCheckBox, QPushButton, QMessageBox, QLineEdit, QScrollArea, QWidget, QFrame, QComboBox
)
from PySide6.QtGui import QIcon
from PySide6.QtCore import Qt
from core.license_validator import LicenseValidator
from gui.dashboard_widgets import COLORS
from utils import dashboard_accounts

class LegalDisclaimerDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Legal Disclaimer & Agreement")
        self.setFixedSize(700, 520)
        self.setWindowIcon(QIcon("app_icon.ico"))  # 아이콘 경로 확인
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        # [UI/UX 개선 - "신뢰할 수 있는 작업대"] 이 창은 ScannerApp이 생성되기도
        # 전에 뜨는 독립 창이라 set_dashboard_theme()이 아직 호출되지 않았지만,
        # dashboard_widgets.COLORS는 모듈 로드 시점에 이미 LIGHT_COLORS로 채워져
        # 있어 앱 본체와 같은 라이트 팔레트를 바로 쓸 수 있다 - 예전의 하드코딩된
        # 다크 톤(#1e1e1e) 대신 나머지 화면과 동일한 톤으로 맞춘다.
        self.setStyleSheet(f"""
            QDialog {{ background-color: {COLORS['surface_1']}; color: {COLORS['text']}; }}
            QLabel {{ color: {COLORS['text_secondary']}; font-size: 11pt; border:none; }}
            QTextEdit {{
                background-color: {COLORS['surface_2']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 10px;
                padding: 14px;
            }}
            QCheckBox {{ color: {COLORS['text']}; font-weight: 600; spacing: 8px; border:none; }}
            QPushButton {{
                background-color: {COLORS['muted_bg']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                padding: 9px 18px;
                font-weight: 600;
                border-radius: 8px;
            }}
            QPushButton:hover {{ background-color: {COLORS['border']}; }}
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(26, 22, 26, 22)
        layout.setSpacing(12)

        # 1. 경고 아이콘 및 제목
        title_layout = QHBoxLayout()
        accent_bar = QLabel()
        accent_bar.setFixedSize(4, 22)
        accent_bar.setStyleSheet(f"background-color: {COLORS['danger_text']}; border-radius: 2px;")
        title_layout.addWidget(accent_bar)
        title_label = QLabel("  Security Tool Usage Warning")
        title_label.setStyleSheet(f"font-size: 15pt; font-weight: 700; color: {COLORS['text']}; border:none;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        layout.addLayout(title_layout)

        # 2. 법적 고지문 (스크롤 가능)
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setHtml(f"""
        <h3 style='color: {COLORS["warning_text"]};'>[중요] 사용 전 반드시 읽어주십시오</h3>
        <p>본 소프트웨어 <b>Z-Vuln Scan</b>은 네트워크 보안 진단 및 관리 목적으로 제작된 도구입니다.</p>

        <p><b>1. 사용 권한 및 책임</b><br>
        사용자는 본 도구를 <u>자신이 소유하거나, 정당한 권한을 위임받은 네트워크/자산</u>에 대해서만 사용해야 합니다.<br>
        사전 승인되지 않은 타인의 시스템을 스캔하는 행위는 <b>정보통신망법 등 관련 법령에 의거하여 민/형사상 처벌</b>을 받을 수 있습니다.</p>

        <p><b>2. 면책 조항</b><br>
        개발자는 본 도구의 사용으로 인해 발생하는 시스템 장애, 데이터 손실, 법적 분쟁 등 어떠한 결과에 대해서도 책임을 지지 않습니다.<br>
        모든 사용 결과에 대한 책임은 전적으로 사용자 본인에게 있습니다.</p>

        <p><b>3. 사용 목적 제한</b><br>
        본 도구는 보안 취약점 점검, 교육, 연구 목적으로만 사용되어야 하며, 악의적인 공격이나 불법적인 침투 목적으로 사용할 수 없습니다.</p>

        <p><b>4. 시스템 요구사항 및 환경</b><br>
        본 도구는 패킷 제어를 위해 <b>[관리자 권한]</b>으로 실행되어야 하며, 결과 저장을 위해 <b>[파일 쓰기 권한]</b>이 필수적입니다.<br>
        권한이 제한된 환경(예: 압축 파일 내부 실행, 쓰기 금지된 저장소)에서는 프로그램이 정상 작동하지 않거나 종료될 수 있습니다.</p>
        <p style='color: {COLORS["text_secondary"]};'>위 내용을 충분히 숙지하였으며, 이에 동의하는 경우에만 프로그램을 시작하십시오.</p>
        """)
        layout.addWidget(self.text_area)

        # 3. 동의 체크박스
        self.check_box = QCheckBox("위 법적 고지 내용을 모두 읽었으며, 이에 동의합니다. 미동의시 도구 사용이 불가능합니다")
        self.check_box.stateChanged.connect(self.toggle_button)
        layout.addWidget(self.check_box)

        layout.addSpacing(4)

        # 4. 버튼 영역
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.btn_exit = QPushButton("Decline (Exit)")
        self.btn_exit.clicked.connect(self.reject)

        self.btn_agree = QPushButton("I Agree & Start")
        self.btn_agree.setDisabled(True) # 기본 비활성화
        self.btn_agree.setCursor(Qt.PointingHandCursor)
        self.btn_agree.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                padding: 9px 18px;
                font-weight: 600;
                border-radius: 8px;
            }}
            QPushButton:hover {{ background-color: #2860D6; }}
            QPushButton:disabled {{ background-color: {COLORS['border']}; color: {COLORS['text_muted']}; }}
        """)
        self.btn_agree.clicked.connect(self.accept)

        btn_layout.addWidget(self.btn_exit)
        btn_layout.addWidget(self.btn_agree)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def toggle_button(self, state):
        # 체크박스가 체크(2)되면 버튼 활성화
        self.btn_agree.setEnabled(state == 2)
        
    def accept(self):
        #동의 버튼 클릭 시 호출됨
        try:
            # 로그 파일에 기록 (시간, 사용자명, PC명)
            import getpass
            import platform
            username = getpass.getuser()
            pc_name = platform.node()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            log_msg = f"[{timestamp}] AGREEMENT ACCEPTED | User: {username} | PC: {pc_name} | Version: v3.0\n"

            # [버그 수정] 원래 "audit_agreement.log"라는 상대경로만 써서 실행 시점의
            # 작업 디렉터리(cwd)에 따라 엉뚱한 곳에 생길 수 있었다(바로가기의 "시작
            # 위치"가 다르면 그쪽에 생김) - utils/logger.py와 동일하게 항상 exe/
            # 프로젝트 루트 기준 고정 경로에 쓰도록 맞춘다.
            if getattr(sys, 'frozen', False):
                base_dir = os.path.dirname(sys.executable)
            else:
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            agreement_log_path = os.path.join(base_dir, "audit_agreement.log")

            with open(agreement_log_path, "a", encoding="utf-8") as f:
                f.write(log_msg)
                
        except Exception as e:
            # 로깅 실패가 프로그램 실행을 막지는 않도록 예외 처리
            print(f"[Warning] Failed to write agreement log: {e}")
            
        # 부모 클래스의 accept 호출 (창 닫기 및 결과 반환)
        super().accept()

class LicenseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Product Activation")
        # [UI/UX 개선] 키 입력칸이 길어져도 안 잘리도록 폭을 넓힘(450→560)
        self.setFixedSize(560, 260)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        # [UI/UX 개선 - "신뢰할 수 있는 작업대"] LegalDisclaimerDialog와 동일하게
        # 하드코딩된 다크 톤 대신 나머지 화면과 같은 라이트 팔레트(COLORS)로 통일.
        self.setStyleSheet(f"""
            QDialog {{ background-color: {COLORS['surface_1']}; color: {COLORS['text']}; }}
            QLabel {{ color: {COLORS['text_secondary']}; border:none; }}
            QPushButton {{
                background-color: {COLORS['muted_bg']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                padding: 10px;
                font-weight: 600;
                border-radius: 8px;
            }}
            QPushButton:hover {{ background-color: {COLORS['border']}; }}
        """)

        layout = QVBoxLayout()
        layout.setSpacing(14)
        layout.setContentsMargins(26, 24, 26, 24)

        # [버그 수정] 예전엔 여기 "ZV3-TIER-XXXX-XXXX-XXXX"처럼 실제 키 형식(등급까지
        # 평문 표기)을 그대로 안내했는데, 이제 키 자체가 완전히 난독화돼 있어 그
        # 형식 예시가 더 이상 실제 키와 안 맞는다 - 구간 개수만 알려주는 일반 표기로 수정.
        lbl_info = QLabel("제품 키를 입력하여 잠금을 해제하십시오.\n(Format: XXX-XX-XXXX-XXXX-XXXX)")
        lbl_info.setStyleSheet(f"color: {COLORS['text']}; font-size: 10.5pt; font-weight: 600; border:none;")
        layout.addWidget(lbl_info)

        # [보안/프라이버시 개선] 라이선스 키는 옆에서 봐도 무슨 값인지 알 수 없도록
        # 기본은 비밀번호 마스킹(●●●)으로 표시하고, "표시" 버튼을 눌렀을 때만 이
        # 입력칸 안에서 실제 문자를 확인할 수 있게 한다(다른 화면·로그·메시지박스
        # 어디에도 평문 키를 노출하지 않음 - 확인 가능한 곳은 오직 이 입력칸뿐).
        input_row = QHBoxLayout()
        input_row.setSpacing(8)
        self.input_key = QLineEdit()
        self.input_key.setPlaceholderText("Paste your License Key here...")
        self.input_key.setEchoMode(QLineEdit.Password)
        self.input_key.setMinimumHeight(40)
        self.input_key.setStyleSheet(f"""
            QLineEdit {{
                padding: 10px 12px;
                font-size: 11.5pt;
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                background-color: {COLORS['surface_2']};
                color: {COLORS['text']};
            }}
            QLineEdit:focus {{ border: 1px solid {COLORS['accent']}; }}
        """)
        input_row.addWidget(self.input_key, 1)

        self.btn_toggle_visibility = QPushButton("표시")
        self.btn_toggle_visibility.setCheckable(True)
        self.btn_toggle_visibility.setFixedSize(56, 40)
        self.btn_toggle_visibility.setCursor(Qt.PointingHandCursor)
        self.btn_toggle_visibility.toggled.connect(self._toggle_key_visibility)
        input_row.addWidget(self.btn_toggle_visibility)
        layout.addLayout(input_row)

        layout.addStretch()

        # 버튼 영역
        btn_layout = QHBoxLayout()

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.reject)

        self.btn_activate = QPushButton("Activate License")
        self.btn_activate.setCursor(Qt.PointingHandCursor)
        self.btn_activate.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                padding: 10px;
                font-weight: 600;
                border-radius: 8px;
                border: none;
            }}
            QPushButton:hover {{ background-color: #2860D6; }}
        """)
        self.btn_activate.clicked.connect(self.check_license)

        btn_layout.addWidget(self.btn_cancel)
        btn_layout.addWidget(self.btn_activate)
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        self.verified_tier = None
        self.verified_expiry = None

    def _toggle_key_visibility(self, checked):
        self.input_key.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        self.btn_toggle_visibility.setText("숨김" if checked else "표시")

    def check_license(self):
        key = self.input_key.text().strip()

        is_valid, tier, expiry_date = LicenseValidator.validate_key(key)

        if is_valid:
            if LicenseValidator.save_license(key):
                self.verified_tier = tier
                self.verified_expiry = expiry_date
                QMessageBox.information(self, "Activation Successful",
                                        f"정품 인증이 완료되었습니다.\n\n[Active Tier]: {tier}\n[만료일]: {expiry_date}")
                self.accept()
            else:
                QMessageBox.warning(self, "System Error", "라이선스 파일을 저장할 수 없습니다.\n권한을 확인하세요.")
        else:
            QMessageBox.warning(self, "Invalid Key", "유효하지 않거나 만료된 라이선스 키입니다.\n입력한 내용을 다시 확인해주세요.")


class PortSelectorDialog(QDialog):
    """[UI/UX 개선 - 2026-08-06 신규] Custom 포트 지정을 텍스트 직접입력 대신
    체크박스로 고를 수 있는 화면. core.advanced_scanner.AdvancedScanner.parse_ports()가
    받는 것과 동일한 "80,443,8000-8100" 형식 문자열을 만들어 반환한다 - 파싱 로직은
    바꾸지 않고 입력 UI만 바꾼다."""

    COMMON_PORTS = [
        ("자주 쓰는 원격/시스템", [(21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
                                (53, "DNS"), (135, "RPC"), (139, "NetBIOS"), (445, "SMB"),
                                (3389, "RDP"), (5985, "WinRM")]),
        ("웹", [(80, "HTTP"), (443, "HTTPS"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt")]),
        ("데이터베이스", [(1433, "MSSQL"), (1521, "Oracle"), (3306, "MySQL"),
                       (5432, "PostgreSQL"), (6379, "Redis"), (27017, "MongoDB")]),
    ]

    def __init__(self, current_ports_text="", parent=None):
        super().__init__(parent)
        self.setWindowTitle("스캔 포트 선택")
        self.setFixedSize(520, 480)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setStyleSheet(f"""
            QDialog {{ background-color: {COLORS['surface_1']}; color: {COLORS['text']}; }}
            QLabel {{ color: {COLORS['text_secondary']}; border:none; }}
            QCheckBox {{ color: {COLORS['text']}; border:none; padding: 3px 0; }}
            QLineEdit {{
                background-color: {COLORS['surface_2']}; color: {COLORS['text']};
                border: 1px solid {COLORS['border']}; border-radius: 8px; padding: 8px 10px;
            }}
            QLineEdit:focus {{ border: 1px solid {COLORS['accent']}; }}
            QScrollArea {{ border: none; background: transparent; }}
            QPushButton {{
                background-color: {COLORS['muted_bg']}; color: {COLORS['text']};
                border: 1px solid {COLORS['border']}; padding: 9px 18px;
                font-weight: 600; border-radius: 8px;
            }}
            QPushButton:hover {{ background-color: {COLORS['border']}; }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(10)

        title = QLabel("자주 쓰는 포트를 체크하고, 나머지는 아래에 직접 입력하세요.")
        title.setStyleSheet(f"color: {COLORS['text']}; font-size: 11pt; font-weight: 600; border:none;")
        layout.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setSpacing(12)

        self._checkboxes = {}  # port_num -> QCheckBox
        for section_name, ports in self.COMMON_PORTS:
            section_label = QLabel(section_name)
            section_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 9.5pt; font-weight: 700; border:none;")
            inner_layout.addWidget(section_label)

            grid = QGridLayout()
            grid.setHorizontalSpacing(16)
            grid.setVerticalSpacing(2)
            for i, (port, name) in enumerate(ports):
                cb = QCheckBox(f"{port} ({name})")
                self._checkboxes[port] = cb
                grid.addWidget(cb, i // 3, i % 3)
            inner_layout.addLayout(grid)

            divider = QFrame()
            divider.setFrameShape(QFrame.HLine)
            divider.setStyleSheet(f"color: {COLORS['border']}; background-color: {COLORS['border']}; max-height: 1px; border:none;")
            inner_layout.addWidget(divider)

        inner_layout.addStretch()
        scroll.setWidget(inner)
        layout.addWidget(scroll, 1)

        custom_label = QLabel("추가 포트/범위 (쉼표로 구분, 범위는 -, 예: 8000-8100,9000)")
        custom_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10pt; border:none;")
        layout.addWidget(custom_label)
        self.custom_input = QLineEdit()
        self.custom_input.setPlaceholderText("예: 8000-8100,9000")
        layout.addWidget(self.custom_input)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_ok = QPushButton("적용")
        btn_ok.setCursor(Qt.PointingHandCursor)
        btn_ok.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']}; color: white; border: none;
                padding: 9px 18px; font-weight: 600; border-radius: 8px;
            }}
            QPushButton:hover {{ background-color: #2860D6; }}
        """)
        btn_ok.clicked.connect(self.accept)
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

        self._load_from_text(current_ports_text)

    def _load_from_text(self, text):
        """기존 port_input 값을 파싱해서 체크박스/커스텀 입력칸에 미리 채워둔다 -
        다시 열었을 때 이전 선택이 사라지지 않게."""
        if not text:
            return
        leftovers = []
        for token in text.split(","):
            token = token.strip()
            if not token:
                continue
            if re.match(r'^\d+$', token) and int(token) in self._checkboxes:
                self._checkboxes[int(token)].setChecked(True)
            else:
                leftovers.append(token)
        self.custom_input.setText(",".join(leftovers))

    def get_ports_string(self):
        """체크된 포트 + 커스텀 입력을 하나의 "80,443,8000-8100" 형식 문자열로 합친다."""
        checked = sorted(port for port, cb in self._checkboxes.items() if cb.isChecked())
        parts = [str(p) for p in checked]
        custom = self.custom_input.text().strip()
        if custom:
            parts.extend(t.strip() for t in custom.split(",") if t.strip())
        return ",".join(parts)


class LaunchModeDialog(QDialog):
    """[웹 대시보드 모드] 법적 고지 동의 직후, 매번 "데스크톱 앱으로 열지 / 웹
    대시보드(로컬 전용 서버)로 열지" 묻는다 - 사용자가 매번 물어보는 쪽을 선택함
    (기억해서 건너뛰지 않음). 결과는 self.chosen_mode에 'app' 또는 'web'로 담긴다."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.chosen_mode = None
        self.setWindowTitle("Z-VulnScan 시작 모드 선택")
        self.setFixedSize(460, 260)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setStyleSheet(f"""
            QDialog {{ background-color: {COLORS['surface_1']}; color: {COLORS['text']}; }}
            QLabel {{ color: {COLORS['text_secondary']}; border:none; }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(14)

        title = QLabel("어떻게 시작할까요?")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLORS['text']}; border:none;")
        layout.addWidget(title)

        def make_option(label_text, desc_text, mode):
            btn = QPushButton(label_text)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setMinimumHeight(46)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS['surface_2']}; color: {COLORS['text']};
                    border: 1px solid {COLORS['border']}; border-radius: 10px;
                    font-weight: 700; font-size: 11.5pt; text-align: left; padding-left: 16px;
                }}
                QPushButton:hover {{ border: 1px solid {COLORS['accent']}; background-color: {COLORS['accent_bg']}; }}
            """)
            btn.clicked.connect(lambda: self._choose(mode))
            layout.addWidget(btn)
            desc = QLabel(desc_text)
            desc.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 9.5pt; border:none; padding-left: 4px;")
            desc.setWordWrap(True)
            layout.addWidget(desc)

        make_option("데스크톱 앱으로 시작", "지금까지 쓰던 PySide6 창 - 스캔/설정 등 전체 기능.", 'app')
        make_option("웹 대시보드로 시작 (로컬 전용)", "브라우저로 대시보드만 조회 - 127.0.0.1에서만 접속 가능, 로그인 필요.", 'web')

        layout.addStretch()

    def _choose(self, mode):
        self.chosen_mode = mode
        self.accept()


class DashboardAccountSetupDialog(QDialog):
    """[웹 대시보드 모드] 최초 계정이 하나도 없을 때(dashboard_accounts.has_any_account()
    False) 첫 계정을 만들게 한다 - 이 경우 role 선택 없이 항상 admin으로 만들어진다
    (dashboard_accounts.create_account()가 강제함). settings_dialog.py의 계정 관리
    탭에서 두 번째 이후 계정을 추가할 때도 재사용하며, 이때는 role 선택 콤보를 보여준다."""

    def __init__(self, parent=None, allow_cancel=True, title="웹 대시보드 관리자 계정 생성"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self._is_first_account = not dashboard_accounts.has_any_account()
        self.setFixedSize(400, 340 if not self._is_first_account else 300)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setStyleSheet(f"""
            QDialog {{ background-color: {COLORS['surface_1']}; color: {COLORS['text']}; }}
            QLabel {{ color: {COLORS['text_secondary']}; border:none; }}
            QLineEdit, QComboBox {{
                background-color: {COLORS['surface_2']}; color: {COLORS['text']};
                border: 1px solid {COLORS['border']}; border-radius: 8px; padding: 9px 10px;
            }}
            QLineEdit:focus, QComboBox:focus {{ border: 1px solid {COLORS['accent']}; }}
            QPushButton {{
                background-color: {COLORS['muted_bg']}; color: {COLORS['text']};
                border: 1px solid {COLORS['border']}; padding: 9px 18px;
                font-weight: 600; border-radius: 8px;
            }}
            QPushButton:hover {{ background-color: {COLORS['border']}; }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(10)

        info = QLabel("이 계정으로 웹 대시보드에 로그인합니다.\n최소 8자 이상 비밀번호를 사용하세요.")
        info.setWordWrap(True)
        layout.addWidget(info)

        self.input_username = QLineEdit()
        self.input_username.setPlaceholderText("아이디")
        layout.addWidget(self.input_username)

        self.input_password = QLineEdit()
        self.input_password.setPlaceholderText("비밀번호 (8자 이상)")
        self.input_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.input_password)

        self.input_password_confirm = QLineEdit()
        self.input_password_confirm.setPlaceholderText("비밀번호 확인")
        self.input_password_confirm.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.input_password_confirm)

        # [최초 계정은 항상 admin] 계정이 하나도 없는 상태에서는 role 선택을 아예
        # 보여주지 않는다 - 고를 필요가 없고(무조건 admin), 고를 수 있는 것처럼
        # 보이면 실수로 낮은 권한을 골라 설정/계정 관리에 아무도 못 들어가는
        # 상태로 서버를 시작할 위험이 있다.
        self.role_combo = None
        if not self._is_first_account:
            role_label = QLabel("역할")
            layout.addWidget(role_label)
            self.role_combo = QComboBox()
            for role in dashboard_accounts.ROLES:
                self.role_combo.addItem(dashboard_accounts.ROLE_LABELS[role], role)
            self.role_combo.setCurrentIndex(list(dashboard_accounts.ROLES).index(dashboard_accounts.DEFAULT_ROLE))
            layout.addWidget(self.role_combo)
            role_hint = QLabel("관리자: 전부 가능 · 운영자: 스캔/자산/리포트 · 조회자: 조회만")
            role_hint.setWordWrap(True)
            role_hint.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 9pt; border:none;")
            layout.addWidget(role_hint)

        layout.addStretch()

        btn_row = QHBoxLayout()
        if allow_cancel:
            btn_cancel = QPushButton("취소")
            btn_cancel.clicked.connect(self.reject)
            btn_row.addWidget(btn_cancel)
        btn_row.addStretch()
        btn_create = QPushButton("계정 생성")
        btn_create.setCursor(Qt.PointingHandCursor)
        btn_create.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']}; color: white; border: none;
                padding: 9px 18px; font-weight: 600; border-radius: 8px;
            }}
            QPushButton:hover {{ background-color: #2860D6; }}
        """)
        btn_create.clicked.connect(self._create)
        btn_row.addWidget(btn_create)
        layout.addLayout(btn_row)

        self.created_username = None

    def _create(self):
        username = self.input_username.text().strip()
        password = self.input_password.text()
        confirm = self.input_password_confirm.text()

        if password != confirm:
            QMessageBox.warning(self, "확인 필요", "비밀번호가 서로 일치하지 않습니다.")
            return

        role = self.role_combo.currentData() if self.role_combo else "admin"
        ok, error = dashboard_accounts.create_account(username, password, role=role)
        if not ok:
            QMessageBox.warning(self, "계정 생성 실패", error)
            return

        self.created_username = username
        self.accept()