# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

from PySide6.QtWidgets import QDialog, QVBoxLayout, QPushButton, QLabel, QWidget
from PySide6.QtCore import Qt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qtagg import NavigationToolbar2QT as NavigationToolbar
from utils.network_visualizer import NetworkVisualizer

class TopologyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Topology Map View")
        self.resize(1000, 800) # 창 크기 넉넉하게
        
        # 전체 레이아웃
        self.layout = QVBoxLayout(self)
        
        self.visualizer = NetworkVisualizer()
        self.initUI()

    def initUI(self):
        # 1. 그래프 생성 시도
        try:
            fig = self.visualizer.create_graph_figure()
        except Exception as e:
            fig = None
            print(f"[Error] Map Generation Failed: {e}")
        
        if fig:
            # 2. 캔버스 생성 (Matplotlib -> Qt 위젯 변환)
            self.canvas = FigureCanvas(fig)
            
            # 3. 툴바 추가 (줌, 이동, 저장 기능 제공)
            self.toolbar = NavigationToolbar(self.canvas, self)
            
            self.layout.addWidget(self.toolbar)
            self.layout.addWidget(self.canvas)
            self.canvas.draw()
        else:
            # 데이터가 없거나 에러 시 안내
            lbl = QLabel("표시할 데이터가 없습니다.\n먼저 스캔을 수행해주세요.")
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet("font-size: 16px; color: #555;")
            self.layout.addWidget(lbl)
            
        # 4. 하단 닫기 버튼
        btn_close = QPushButton("닫기 (Close)")
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.clicked.connect(self.accept)
        btn_close.setStyleSheet("""
            QPushButton {
                background-color: #555; 
                color: white; 
                padding: 10px; 
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #333;
            }
        """)
        self.layout.addWidget(btn_close)