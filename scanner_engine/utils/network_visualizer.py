# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import os
import sys
from utils.logger import AppLogger
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
        #PyVis를 사용하여 인터랙티브 토폴로지 HTML 생성
        #assets: [(ip, os, memo, mac), ...]
        try:
            # 1. PyVis 객체 생성 (옵션 동일)
            net = Network(
                height="100%", 
                width="100%", 
                bgcolor="#1e1e1e", 
                font_color="white", 
                select_menu=False,
                cdn_resources='in_line'
            )
            
            # 2. 물리 엔진 설정
            net.barnes_hut(gravity=-3000, central_gravity=0.3, spring_length=150, spring_strength=0.05, damping=0.09, overlap=0)
            
            # 3. 데이터 추가 (동일)
            net.add_node("Gateway", label="Core Gateway", title="Main Entrance", color="#ff5722", shape="diamond", size=30)

            for asset in assets:
                ip = asset[0] if len(asset) > 0 else "Unknown"
                os_type = asset[1] if len(asset) > 1 else "Unknown"
                memo = asset[2] if len(asset) > 2 else ""
                
                memo_display = memo if memo and str(memo).strip() else "None"
                color = "#00b0ff"
                shape = "dot"
                os_lower = str(os_type).lower()
                
                if "server" in os_lower or "linux" in os_lower:
                    color = "#76ff03"
                    shape = "square"
                elif "windows" in os_lower:
                    color = "#2979ff"
                elif "printer" in os_lower:
                    color = "#ffea00"

                tooltip = f"IP: {ip}OS: {os_type} Memo: {memo_display}"
                net.add_node(ip, label=ip, title=tooltip, color=color, shape=shape, size=20)
                net.add_edge("Gateway", ip, color="#555555", width=1)

            # 4. 저장 경로 설정
            if getattr(sys, 'frozen', False):
                base_path = os.path.dirname(sys.executable)
                save_dir = os.path.join(base_path, "scanner_engine", "output")
            else:
                save_dir = os.path.join(os.getcwd(), self.output_dir)
                
            if not os.path.exists(save_dir):
                os.makedirs(save_dir)
                
            full_path = os.path.join(save_dir, output_filename)
            
            # [Fix] CP949 인코딩 에러 해결
            # 5. HTML 생성 및 UTF-8 강제 저장
            html_content = net.generate_html()
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            return full_path
            
        except Exception as e:
            AppLogger.log_critical(f" [Visualizer Error] ",e)
            return None
