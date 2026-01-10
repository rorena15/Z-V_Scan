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

                tooltip = f"IP: {ip} OS: {os_type} MAC: {mac} Memo: {memo}"
                
                net.add_node(ip, label=ip, title=tooltip, color=color, shape=shape, size=15)
                net.add_edge("Gateway", ip, color="#555555", width=1)

            # 4. [핵심] 물리 엔진 최적화 옵션
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

            # 5. [수정] HTML 직접 생성 방식으로 인코딩 문제 회피
            full_path = os.path.join(self.output_dir, output_filename)
            
            # PyVis의 HTML 템플릿을 직접 생성
            html_content = net.generate_html()
            
            # UTF-8로 강제 저장
            try:
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            except Exception as write_error:
                # 혹시 generate_html()이 없는 구버전이면 기존 방식 사용
                try:
                    # 환경변수로 UTF-8 강제 설정
                    import locale
                    original_locale = locale.getpreferredencoding()
                    
                    # Python의 기본 인코딩을 UTF-8로 변경
                    if sys.platform.startswith('win'):
                        # Windows에서 UTF-8 모드 활성화
                        import io
                        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
                    
                    net.save_graph(full_path)
                    
                except Exception as fallback_error:
                    # 최후의 수단: HTML 수동 생성
                    AppLogger.log_error("[Visualizer] Using manual HTML generation", fallback_error)
                    self._save_manual_html(net, full_path)
            
            return full_path

        except Exception as e:
            AppLogger.log_error(f"[Visualizer Error]", e)
            return None
    
    def _save_manual_html(self, net, filepath):
        """수동으로 HTML 파일 생성 (인코딩 문제 완전 회피)"""
        try:
            # vis.js CDN을 사용한 간단한 HTML 템플릿
            nodes_data = []
            edges_data = []
            
            # 노드 데이터 추출
            for node in net.nodes:
                node_dict = {
                    'id': str(node['id']),
                    'label': str(node.get('label', node['id'])),
                    'title': str(node.get('title', '')),
                    'color': str(node.get('color', '#97c2fc')),
                    'shape': str(node.get('shape', 'dot')),
                    'size': int(node.get('size', 15))
                }
                nodes_data.append(node_dict)
            
            # 엣지 데이터 추출
            for edge in net.edges:
                edge_dict = {
                    'from': str(edge['from']),
                    'to': str(edge['to']),
                    'color': str(edge.get('color', '#555555')),
                    'width': int(edge.get('width', 1))
                }
                edges_data.append(edge_dict)
            
            # HTML 템플릿
            html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Z-VulnScan Network Topology</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style type="text/css">
        body {{ margin: 0; padding: 0; background-color: #1e1e1e; }}
        #mynetwork {{ width: 100%; height: 100vh; }}
    </style>
</head>
<body>
<div id="mynetwork"></div>
<script type="text/javascript">
    var nodes = new vis.DataSet({str(nodes_data).replace("'", '"')});
    var edges = new vis.DataSet({str(edges_data).replace("'", '"')});
    
    var container = document.getElementById('mynetwork');
    var data = {{ nodes: nodes, edges: edges }};
    var options = {{
        nodes: {{
            font: {{ size: 14, face: "Tahoma", color: "#ffffff" }},
            borderWidth: 2,
            shadow: true
        }},
        edges: {{
            color: {{ inherit: true }},
            smooth: false,
            width: 1
        }},
        physics: {{
            enabled: true,
            barnesHut: {{
                gravitationalConstant: -8000,
                centralGravity: 0.3,
                springLength: 200,
                springConstant: 0.04,
                damping: 0.09,
                avoidOverlap: 0.2
            }},
            stabilization: {{
                enabled: true,
                iterations: 1000,
                updateInterval: 50
            }},
            minVelocity: 0.75,
            solver: "barnesHut"
        }},
        interaction: {{
            hover: true,
            navigationButtons: true,
            keyboard: true,
            zoomView: true
        }}
    }};
    
    var network = new vis.Network(container, data, options);
</script>
</body>
</html>"""
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_template)
                
        except Exception as e:
            AppLogger.log_error("[Manual HTML Generation Error]", e)