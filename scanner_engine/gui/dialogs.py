# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import getpass
import platform
import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from datetime import datetime
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QTextEdit, QCheckBox, QPushButton
)
from PySide6.QtGui import QIcon
from PySide6.QtCore import Qt
class LegalDisclaimerDialog(QDialog): 
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Legal Disclaimer & Agreement")
        self.setFixedSize(700, 500)
        self.setWindowIcon(QIcon("app_icon.ico"))  # 아이콘 경로 확인
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        
        # 스타일 적용 (다크 모드 톤)
        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; color: #ffffff; }
            QLabel { color: #cccccc; font-size: 11pt; }
            QTextEdit { 
                background-color: #252526; 
                color: #d4d4d4; 
                border: 1px solid #3e3e3e; 
                padding: 10px;
                font-family: 'Consolas', 'NanumGothic', monospace;
            }
            QCheckBox { color: #ffffff; font-weight: bold; spacing: 8px; }
            QPushButton {
                background-color: #0e639c;
                color: white;
                border: none;
                padding: 8px 16px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:disabled { background-color: #3e3e3e; color: #888888; }
            QPushButton:hover { background-color: #1177bb; }
        """)

        layout = QVBoxLayout()
        
        # 1. 경고 아이콘 및 제목
        title_layout = QHBoxLayout()
        title_label = QLabel("⚠️ Security Tool Usage Warning")
        title_label.setStyleSheet("font-size: 18pt; font-weight: bold; color: #ff5555;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        layout.addLayout(title_layout)

        # 2. 법적 고지문 (스크롤 가능)
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setHtml("""
        <h3 style='color: #ffaa00;'>[중요] 사용 전 반드시 읽어주십시오</h3>
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
        <p style='color: #cccccc;'>위 내용을 충분히 숙지하였으며, 이에 동의하는 경우에만 프로그램을 시작하십시오.</p>
        """)
        layout.addWidget(self.text_area)

        # 3. 동의 체크박스
        self.check_box = QCheckBox("위 법적 고지 내용을 모두 읽었으며, 이에 동의합니다. 미동의시 도구 사용이 불가능합니다")
        self.check_box.stateChanged.connect(self.toggle_button)
        layout.addWidget(self.check_box)

        layout.addSpacing(10)

        # 4. 버튼 영역
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        self.btn_exit = QPushButton("Decline (Exit)")
        self.btn_exit.setStyleSheet("background-color: #555555;")
        self.btn_exit.clicked.connect(self.reject)
        
        self.btn_agree = QPushButton("I Agree & Start")
        self.btn_agree.setDisabled(True) # 기본 비활성화
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
            
            log_msg = f"[{timestamp}] AGREEMENT ACCEPTED | User: {username} | PC: {pc_name} | Version: v2.2.0\n"
            
            # 프로젝트 루트에 로그 저장
            with open("audit_agreement.log", "a", encoding="utf-8") as f:
                f.write(log_msg)
                
        except Exception as e:
            # 로깅 실패가 프로그램 실행을 막지는 않도록 예외 처리
            print(f"[Warning] Failed to write agreement log: {e}")
            
        # 부모 클래스의 accept 호출 (창 닫기 및 결과 반환)
        super().accept()
