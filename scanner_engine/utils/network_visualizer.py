# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import os
import sys
from pyvis.network import Network

class NetworkVisualizer:
    def __init__(self, output_dir="scanner_engine/output"):
        self.output_dir = output_dir
        # 출력 폴더가 없으면 생성
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except OSError:
                pass # 권한 문제 등 예외 처리

    def create_topology(self, assets, output_filename="topology.html"):
        try:
            # 1. PyVis 네트워크 객체 생성 (전체화면, 다크테마)
            net = Network(height="100%", width="100%", bgcolor="#2b2b2b", font_color="white", select_menu=True)
            
            # 2. 물리 엔진 설정 (노드 100개 이상 안정화용 BarnesHut 알고리즘)
            net.barnes_hut(gravity=-3000, central_gravity=0.3, spring_length=150, spring_strength=0.05, damping=0.09, overlap=0)
            
            # 3. 데이터 추가
            net.add_node("Gateway", label="Core Gateway", title="Main Entrance", color="#ff5722", shape="diamond", size=30)

            for asset in assets:
                # DB 데이터 언패킹 (인덱스 에러 방지)
                ip = asset[0] if len(asset) > 0 else "Unknown"
                os_type = asset[1] if len(asset) > 1 else "Unknown"
                memo = asset[2] if len(asset) > 2 else ""
                
                # OS별 아이콘/색상 구분
                color = "#00b0ff" # 기본 PC (Cyan)
                shape = "dot"
                
                os_lower = str(os_type).lower()
                if "server" in os_lower or "linux" in os_lower:
                    color = "#76ff03" # 서버 (Green)
                    shape = "square"
                elif "windows" in os_lower:
                    color = "#2979ff" # 윈도우 (Blue)
                elif "printer" in os_lower:
                    color = "#ffea00" # 프린터 (Yellow)

                # 툴팁 (마우스 오버 시 정보)
                tooltip = f"<b>IP:</b> {ip}<br><b>OS:</b> {os_type}<br><b>Memo:</b> {memo}"
                
                # 노드 추가
                net.add_node(ip, label=ip, title=tooltip, color=color, shape=shape, size=20)
                
                # 엣지 연결 (현재는 스위치 정보가 없으므로 Gateway와 연결)
                net.add_edge("Gateway", ip, color="#555555", width=1)

            # 4. 파일 저장
            # PyInstaller 환경 고려: 절대 경로로 변환
            if getattr(sys, 'frozen', False):
                # EXE 실행 시 임시 폴더가 아닌, EXE 옆 output 폴더에 저장 권장
                base_path = os.path.dirname(sys.executable)
                save_dir = os.path.join(base_path, "scanner_engine", "output")
                if not os.path.exists(save_dir):
                    os.makedirs(save_dir)
                full_path = os.path.join(save_dir, output_filename)
            else:
                full_path = os.path.join(os.getcwd(), self.output_dir, output_filename)
                
            # PyVis의 save_graph는 템플릿 로딩 문제로 절대경로 처리가 중요
            net.save_graph(full_path)
            
            return full_path
            
        except Exception as e:
            # 로거가 있다면 기록, 없으면 콘솔 출력
            print(f"[Visualizer Error] {e}")
            return None