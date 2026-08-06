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

from datetime import datetime
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QTextEdit, QCheckBox, QPushButton,QMessageBox,QLineEdit
)
from PySide6.QtGui import QIcon
from PySide6.QtCore import Qt
from core.license_validator import LicenseValidator
from gui.dashboard_widgets import COLORS

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
        self.setFixedSize(450, 220)
        self.setStyleSheet("background-color: #252526; color: white;")
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(25, 25, 25, 25)
        
        # 안내 문구
        lbl_info = QLabel("제품 키를 입력하여 잠금을 해제하십시오.\n(Format: ZV3-TIER-XXXX-XXXX-XXXX)")
        lbl_info.setStyleSheet("color: #ccc; font-size: 10pt; font-weight: bold;")
        layout.addWidget(lbl_info)
        
        # 입력창
        self.input_key = QLineEdit()
        self.input_key.setPlaceholderText("Paste your License Key here...")
        self.input_key.setStyleSheet("""
            QLineEdit { 
                padding: 10px; 
                font-size: 11pt; 
                border: 1px solid #007acc; 
                border-radius: 4px;
                background-color: #333;
                color: #fff;
            }
            QLineEdit:focus { border: 1px solid #0098ff; background-color: #3a3a3a; }
        """)
        layout.addWidget(self.input_key)
        
        # 버튼 영역
        btn_layout = QHBoxLayout()
        
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setStyleSheet("""
            QPushButton { background-color: #333; color: #aaa; border: 1px solid #555; padding: 10px; border-radius: 4px; }
            QPushButton:hover { background-color: #444; color: white; }
        """)
        self.btn_cancel.clicked.connect(self.reject)

        self.btn_activate = QPushButton("Activate License")
        self.btn_activate.setCursor(Qt.PointingHandCursor)
        self.btn_activate.setStyleSheet("""
            QPushButton { 
                background-color: #007acc; 
                color: white; 
                padding: 10px; 
                font-weight: bold; 
                border-radius: 4px;
                border: none;
            }
            QPushButton:hover { background-color: #005f9e; }
        """)
        self.btn_activate.clicked.connect(self.check_license)

        btn_layout.addWidget(self.btn_cancel)
        btn_layout.addWidget(self.btn_activate)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
        self.verified_tier = None
        self.verified_expiry = None

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