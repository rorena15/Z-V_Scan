# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

from PySide6.QtWidgets import QDialog, QVBoxLayout, QPushButton, QLabel, QHBoxLayout, QFileDialog, QWidget
from PySide6.QtCore import Qt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qtagg import NavigationToolbar2QT as NavigationToolbar
from utils.network_visualizer import NetworkVisualizer

class TopologyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Topology Map")
        self.resize(1000, 800)
        
        # [Dark Theme] 다이얼로그 전체 스타일
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
        self.visualizer = NetworkVisualizer()
        self.initUI()

    def initUI(self):
        try:
            fig = self.visualizer.create_graph_figure()
        except Exception as e:
            fig = None
            print(f"Graph Error: {e}")
        
        if fig:
            self.canvas = FigureCanvas(fig)
            
            # [핵심] 툴바는 생성하되 숨김 (Pan 기능 활성화를 위해 객체는 필요함)
            self.toolbar = NavigationToolbar(self.canvas, self)
            self.toolbar.pan() # 드래그 모드 강제 활성화
            self.toolbar.hide() # 툴바 UI 숨기기
            
            # 휠 줌 이벤트 연결
            self.canvas.mpl_connect('scroll_event', self.on_scroll)
            
            self.layout.addWidget(self.canvas)
            
            # --- 하단 컨트롤 바 (저장 & 닫기) ---
            btn_layout = QHBoxLayout()
            
            # 팁 라벨
            tip_label = QLabel("💡 Tip: 휠(Zoom) / 드래그(Pan)")
            tip_label.setStyleSheet("color: #aaaaaa; font-style: italic;")
            
            # [New] 저장 버튼 (툴바 대신 사용)
            btn_save = QPushButton("💾 이미지 저장 (Save)")
            btn_save.clicked.connect(self.save_image)
            btn_save.setStyleSheet("background-color: #2e7d32; border-color: #1b5e20;") # 녹색 계열

            # 닫기 버튼
            btn_close = QPushButton("닫기 (Close)")
            btn_close.clicked.connect(self.accept)

            btn_layout.addWidget(tip_label)
            btn_layout.addStretch() # 빈 공간
            btn_layout.addWidget(btn_save)
            btn_layout.addWidget(btn_close)
            
            self.layout.addLayout(btn_layout)

        else:
            lbl = QLabel("표시할 데이터가 없습니다.\n(No Data Available)")
            lbl.setAlignment(Qt.AlignCenter)
            self.layout.addWidget(lbl)
            btn_close = QPushButton("닫기")
            btn_close.clicked.connect(self.accept)
            self.layout.addWidget(btn_close)

    def save_image(self):
        #Matplotlib 캔버스를 이미지 파일로 저장
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Topology Map", "Network_Map.png", "PNG Images (*.png);;All Files (*)"
        )
        if file_path:
            # 배경색 유지하며 저장
            self.canvas.figure.savefig(file_path, facecolor='#2b2b2b', edgecolor='none')

    def on_scroll(self, event):
        """마우스 휠 줌 기능 (이전과 동일 로직)"""
        ax = self.canvas.figure.axes[0]
        if event.inaxes != ax: return
        base_scale = 1.1
        if event.button == 'up': scale_factor = 1 / base_scale
        elif event.button == 'down': scale_factor = base_scale
        else: return
        
        cur_xlim = ax.get_xlim()
        cur_ylim = ax.get_ylim()
        xdata = event.xdata
        ydata = event.ydata
        
        new_width = (cur_xlim[1] - cur_xlim[0]) * scale_factor
        new_height = (cur_ylim[1] - cur_ylim[0]) * scale_factor
        relx = (cur_xlim[1] - xdata) / (cur_xlim[1] - cur_xlim[0])
        rely = (cur_ylim[1] - ydata) / (cur_ylim[1] - cur_ylim[0])
        
        ax.set_xlim([xdata - new_width * (1 - relx), xdata + new_width * relx])
        ax.set_ylim([ydata - new_height * (1 - rely), ydata + new_height * rely])
        self.canvas.draw_idle()