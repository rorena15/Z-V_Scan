# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import sys
import os
from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFileDialog, QMessageBox
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtCore import QUrl

class TopologyDialog(QDialog):
    def __init__(self, html_path, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Topology Map (Interactive)")
        self.resize(1000, 700)
        self.html_path = html_path
        
        # [요청하신 스타일 그대로 적용]
        self.setStyleSheet("""
            QDialog { background-color: #2b2b2b; color: white; }
            QLabel { color: #dddddd; font-size: 14px; }
            QPushButton {
                background-color: #444;
                color: white;
                border: 1px solid #666;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #666; border-color: #888; }
            QPushButton:pressed { background-color: #333; }
        """)

        self.layout = QVBoxLayout(self)
        self.initUI()

    def initUI(self):
        # 1. 웹 뷰 (PyVis HTML 로드)
        self.web_view = QWebEngineView()
        self.web_view.setStyleSheet("background-color: #2b2b2b;") # 배경색 통일
        
        if self.html_path and os.path.exists(self.html_path):
            url = QUrl.fromLocalFile(os.path.abspath(self.html_path))
            self.web_view.load(url)
        else:
            self.web_view.setHtml("<h2 style='color:white;text-align:center;'>❌ Map File Not Found</h2>")

        self.layout.addWidget(self.web_view)

        # 2. 하단 컨트롤 바 (스타일 복원)
        btn_layout = QHBoxLayout()
        
        # 팁 라벨 (PyVis 조작법으로 텍스트만 살짝 변경)
        tip_label = QLabel("💡 Tip: 휠(Zoom) / 드래그(Pan) / 노드 클릭(Info)")
        tip_label.setStyleSheet("color: #aaaaaa; font-style: italic;")
        
        # [기능 복원] 저장 버튼
        btn_save = QPushButton("💾 이미지 저장 (Save)")
        btn_save.clicked.connect(self.save_image)
        btn_save.setStyleSheet("background-color: #2e7d32; border-color: #1b5e20;") # 녹색 계열

        # 닫기 버튼
        btn_close = QPushButton("닫기 (Close)")
        btn_close.clicked.connect(self.accept)

        btn_layout.addWidget(tip_label)
        btn_layout.addStretch() # 빈 공간 채우기
        btn_layout.addWidget(btn_save)
        btn_layout.addWidget(btn_close)
        
        self.layout.addLayout(btn_layout)

    def save_image(self):
        """
        [핵심] WebEngine 화면을 캡처하여 이미지로 저장
        Matplotlib의 savefig와 동일한 결과를 만듭니다.
        """
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Topology Map", "Network_Map.png", "PNG Images (*.png);;All Files (*)"
        )
        
        if file_path:
            # 웹 뷰 위젯 자체를 캡처 (Grab)
            pixmap = self.web_view.grab()
            
            # 파일로 저장
            if pixmap.save(file_path):
                QMessageBox.information(self, "Success", f"이미지가 저장되었습니다:\n{file_path}")
            else:
                QMessageBox.critical(self, "Error", "이미지 저장에 실패했습니다.")