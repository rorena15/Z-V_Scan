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
        db = DBConnector()
        assets = db.get_all_assets()
        
        G = nx.Graph()
        
        # 중앙 노드 설정
        center_node = "Scanner\n(My PC)"
        G.add_node(center_node, node_type='center')
        
        if not assets:
            return None
            
        for ip, os_type, memo, mac in assets:
            # OS 이름 줄임 처리
            short_os = os_type.split('|')[0].strip() if '|' in os_type else os_type
            if len(short_os) > 12: 
                short_os = short_os[:12] + ".."
            
            label = f"{ip}\n{short_os}"
            G.add_node(label, node_type='asset')
            G.add_edge(center_node, label)
            
        # ---------------------------------------------------------
        # [스타일 설정: 다크 모드 강제 적용]
        # ---------------------------------------------------------
        plt.rcParams['font.family'] = 'Malgun Gothic'
        plt.rcParams['axes.unicode_minus'] = False

        # 1. Figure(전체 창) 생성 및 배경색 지정
        fig = plt.figure(figsize=(12, 9))
        fig.patch.set_facecolor('#2b2b2b') # 창 전체 배경 (Dark)

        # 2. Axis(그래프 영역) 배경 투명화
        # [핵심 Fix] 그래프가 그려지는 네모난 영역의 흰색 배경을 제거합니다.
        ax = fig.add_subplot(111)
        ax.set_facecolor('#2b2b2b') 
        
        # 레이아웃 계산 (노드 간격 넓힘)
        pos = nx.spring_layout(G, k=0.9, seed=42) 
        
        # 색상 설정
        color_map = []
        for node in G:
            if G.nodes[node].get('node_type') == 'center':
                color_map.append('#4a90e2') # 파랑
            else:
                color_map.append('#50c878') # 초록
        
        # 3. 그리기
        nx.draw_networkx_nodes(G, pos, 
                               node_color=color_map, 
                               node_size=6000, # 노드 크기 더 키움
                               alpha=1.0,
                               ax=ax)
                               
        nx.draw_networkx_edges(G, pos, 
                               edge_color='#888888', 
                               width=1.5, 
                               alpha=0.8,
                               ax=ax)

        nx.draw_networkx_labels(G, pos, 
                                font_size=9, 
                                font_weight='bold', 
                                font_color='white', # 글자 흰색
                                font_family='Malgun Gothic',
                                ax=ax)

        # [핵심 Fix] 축(Axis) 자체를 꺼버려서 흰색 테두리나 배경이 남지 않게 함
        plt.axis('off') 
        
        # 제목 설정
        plt.title(f"Network Topology Map (Total Assets: {len(assets)})", 
                  fontsize=16, fontweight='bold', color='white', pad=20)
        
        plt.tight_layout() # 여백 자동 정리
        
        return fig