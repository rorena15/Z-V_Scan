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
        
        # 실행 위치 기준 경로 재조정 (EXE 실행 시 경로 문제 방지)
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
            self.output_dir = os.path.join(base_path, 'reports')
        else:
            # 개발 환경에서는 프로젝트 루트의 reports 폴더
            base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.output_dir = os.path.join(base_path, 'reports')

        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except OSError:
                pass 

    def create_topology(self, assets, output_filename="network_topology.html"):
        """
        PyVis를 사용하여 인터랙티브 토폴로지 HTML 생성
        assets: [(ip, os, memo, mac), ...]
        """
        try:
            # 1. PyVis 객체 생성 (notebook=False 필수)
            net = Network(
                height="800px", 
                width="100%", 
                bgcolor="#1e1e1e", 
                font_color="white", 
                select_menu=False,
                cdn_resources='in_line',
                notebook=False
            )
            
            # 2. 중앙 게이트웨이 노드 추가
            net.add_node("Gateway", label="Z-VulnScan\n(Scanner)", title="Main Scanner Device", color="#ff5722", shape="box", size=25)

            # 3. 자산 노드 추가
            for asset in assets:
                try:
                    ip = asset[0]
                    os_type = asset[1] if len(asset) > 1 else "Unknown"
                    memo = asset[2] if len(asset) > 2 else ""
                    mac = asset[3] if len(asset) > 3 else "-"
                except: continue

                memo_display = memo if memo and str(memo).strip() else "-"
                
                # OS별 색상 및 아이콘 설정
                color = "#97c2fc" # 기본
                shape = "dot"
                os_lower = str(os_type).lower()
                
                if "windows" in os_lower:
                    color = "#00bfff" # 파랑
                elif "linux" in os_lower:
                    color = "#ff9900" # 주황
                elif "unknown" in os_lower:
                    color = "#777777" # 회색

                tooltip = f"<b>IP:</b> {ip}<br><b>OS:</b> {os_type}<br><b>MAC:</b> {mac}<br><b>Memo:</b> {memo_display}"
                
                net.add_node(ip, label=ip, title=tooltip, color=color, shape=shape, size=15)
                net.add_edge("Gateway", ip, color="#555555", width=1)

            # 4. [핵심] 물리 엔진 최적화 옵션
            # smooth: false (직선 연결로 렉 감소)
            # stabilization: 미리 계산해서 튕김 방지
            options = """
            var options = {
                "nodes": {
                "font": { "size": 14, "face": "Tahoma", "color": "#ffffff" },
                "borderWidth": 2,
                "shadow": true
                },
            "edges": {
                "color": { "inherit": true },
                "smooth": false, 
                "width": 1
                },
            "physics": {
                "enabled": true,
                "barnesHut": {
                    "gravitationalConstant": -8000,
                    "centralGravity": 0.3,
                    "springLength": 200,
                    "springConstant": 0.04,
                    "damping": 0.09,
                    "avoidOverlap": 0.2
                },
                "stabilization": {
                    "enabled": true,
                    "iterations": 1000,
                    "updateInterval": 50,
                    "onlyDynamicEdges": false,
                    "fit": true
                },
                "minVelocity": 0.75,
                "solver": "barnesHut"
                },
            "interaction": {
                "hover": true,
                "navigationButtons": true,
                "keyboard": true,
                "zoomView": true
                }
            }
            """
            net.set_options(options)

            # 5. 저장
            full_path = os.path.join(self.output_dir, output_filename)
            net.save_graph(full_path)
            return full_path

        except Exception as e:
            AppLogger.log_error(f"[Visualizer Error]", e)
            return None
