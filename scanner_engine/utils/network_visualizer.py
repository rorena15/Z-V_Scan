# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import networkx as nx
import matplotlib.pyplot as plt
from utils.db_connector import DBConnector

class NetworkVisualizer:
    def create_graph_figure(self):
        # 1. DB에서 자산 정보 로드
        db = DBConnector()
        assets = db.get_all_assets()
        
        # 2. 그래프 객체 생성
        G = nx.Graph()
        
        # 3. 중앙 노드 (Scanner) 설정
        center_node = "My PC\n(Scanner)"
        G.add_node(center_node, node_type='center')
        
        if not assets:
            return None # 데이터가 없으면 빈 값 반환
            
        # 4. 자산 노드 추가 및 연결
        for ip, os_type, memo, mac in assets:
            # 라벨: IP + (OS정보)
            # OS 정보가 너무 길면 줄바꿈 처리
            short_os = os_type.split('|')[0].strip() if '|' in os_type else os_type
            if len(short_os) > 15:
                short_os = short_os[:15] + "..."
                
            label = f"{ip}\n({short_os})"
            
            # 노드 추가 (IP를 ID로 사용)
            G.add_node(label, node_type='asset')
            # 중앙 노드와 연결 (Star Topology)
            G.add_edge(center_node, label)
            
        # 5. 그래프 시각화 스타일 설정
        # 한글 폰트 설정 (Windows/Linux)
        plt.rcParams['font.family'] = 'Malgun Gothic' # 윈도우용 (리눅스는 NanumGothic 등 필요)
        plt.rcParams['axes.unicode_minus'] = False    # 마이너스 기호 깨짐 방지

        fig = plt.figure(figsize=(10, 8))
        
        # 레이아웃 알고리즘 (spring_layout이 가장 무난함)
        pos = nx.spring_layout(G, k=0.6, seed=42) 
        
        # 색상 지정 (중앙=파랑, 자산=초록)
        color_map = []
        for node in G:
            if G.nodes[node].get('node_type') == 'center':
                color_map.append('#1f78b4') # 진한 파랑
            else:
                color_map.append('#33a02c') # 진한 초록
        
        # 그리기
        nx.draw(G, pos, 
                with_labels=True, 
                node_color=color_map, 
                node_size=2500, 
                font_size=8, 
                font_weight='bold', 
                font_color='black',
                edge_color='gray', 
                width=1.0,
                alpha=0.8)
        
        plt.title(f"Network Topology Map (Total: {len(assets)})", fontsize=14, fontweight='bold')
        plt.axis('off') # X, Y축 눈금 숨기기
        
        return fig