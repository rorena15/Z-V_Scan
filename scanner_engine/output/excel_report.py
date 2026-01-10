# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
# output/excel_report.py
# [PREMIUM STYLE] output/excel_report.py

import os
import sys
import sqlite3
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.chart import PieChart3D, Reference, Series
from openpyxl.utils import get_column_letter

from utils.db_connector import DBConnector
from utils.logger import AppLogger

class ExcelGenerator:
    # --- [스타일 상수 정의] ---
    # 1. 헤더 스타일 (짙은 네이비 + 흰색 글씨)
    HEADER_FILL = PatternFill(start_color='1F4E78', end_color='1F4E78', fill_type='solid')
    HEADER_FONT = Font(name='Malgun Gothic', size=11, bold=True, color='FFFFFF')
    
    # 2. KPI 카드 스타일 (상단 요약 박스용)
    KPI_TITLE_FONT = Font(name='Malgun Gothic', size=12, bold=True, color='555555')
    KPI_VALUE_FONT = Font(name='Arial', size=24, bold=True, color='1F4E78')
    
    # 3. 테두리
    BORDER_THIN = Border(
                            left=Side(style='thin'), right=Side(style='thin'), 
                            top=Side(style='thin'), bottom=Side(style='thin')
                        )

    # 4. 위험도 색상 (파스텔 톤으로 고급스럽게)
    RISK_COLORS = {
        "Critical": "FF9999", # 연한 빨강
        "High":     "FFCC99", # 연한 주황
        "Medium":   "FFFFCC", # 연한 노랑
        "Low":      "E2EFDA", # 연한 초록
        "Info":     "F2F2F2", # 연한 회색
        "Safe":     "C6EFCE"  # 진한 초록
    }

    def __init__(self):
        self.db = DBConnector()
        if getattr(sys, 'frozen', False):
            # EXE 실행 시: 실행 파일이 있는 위치의 reports 폴더
            base_path = os.path.dirname(sys.executable)
        else:
            # 개발 환경 시: scanner_engine/output/excel_report.py 기준 3단계 위로 이동
            # 1. output -> 2. scanner_engine -> 3. Project Root
            current_file = os.path.abspath(__file__)
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
            
        self.output_dir = os.path.join(base_path, 'reports')
        
        # reports 폴더가 없으면 생성
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except OSError:
                pass # 권한 문제 등 무시
    def generate(self):
        try:
            wb = Workbook()
            
            # 데이터 조회
            data = self._fetch_data()
            
            # 1. 상세 내역 시트 (Detail)
            self._create_detail_sheet(wb, data)
            
            # 2. 대시보드 시트 (Dashboard) - 맨 앞으로 이동
            self._create_dashboard_sheet(wb, data)

            # 저장
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ZVulnScan_Report_{timestamp}.xlsx"
            filepath = os.path.join(self.output_dir, filename)
            
            wb.save(filepath)
            return filepath

        except Exception as e:
            AppLogger.log_error("Excel Generation Error", e)
            raise e

    def _fetch_data(self):
        """DB 데이터 직접 조회"""
        conn = None
        try:
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            query = """
                SELECT 
                    A.ip_addr, A.hostname, A.os_type,
                    R.vuln_code, R.vuln_name, R.risk_level, R.status, 
                    R.detected_value, R.remediation, R.scan_date
                FROM TBL_SCAN_RESULT R
                JOIN TBL_ASSETS A ON R.asset_id = A.asset_id
                ORDER BY 
                    CASE R.risk_level 
                        WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 
                        WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 
                        ELSE 5 END ASC,
                    A.ip_addr ASC
            """
            cursor.execute(query)
            return cursor.fetchall()
        except Exception as e:
            AppLogger.log_error("DB Fetch Error", e)
            return []
        finally:
            if conn: conn.close()

    def _create_detail_sheet(self, wb, data):
        """[Detail] 상세 내역 테이블"""
        ws = wb.create_sheet("Scan Details")
        
        headers = ["IP Address", "Hostname", "OS", "Code", "Vulnerability", "Risk", "Status", "Detail", "Remediation", "Date"]
        
        # 헤더 그리기
        ws.append(headers)
        for col in range(1, len(headers) + 1):
            cell = ws.cell(row=1, column=col)
            cell.fill = self.HEADER_FILL
            cell.font = self.HEADER_FONT
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = self.BORDER_THIN

        # 데이터 채우기
        for row_idx, row_data in enumerate(data, 2):
            for col_idx, val in enumerate(row_data, 1):
                cell = ws.cell(row=row_idx, column=col_idx, value=str(val))
                cell.border = self.BORDER_THIN
                cell.alignment = Alignment(vertical='top', wrap_text=True)

                # 위험도(Risk) 컬럼 색상 강조
                if col_idx == 6 and val in self.RISK_COLORS:
                    color = self.RISK_COLORS[val]
                    cell.fill = PatternFill(start_color=color, end_color=color, fill_type='solid')
                    cell.alignment = Alignment(horizontal='center', vertical='center')

        # 컬럼 너비 조정
        widths = [16, 18, 15, 12, 30, 10, 10, 40, 40, 20]
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w
            
        # 오토 필터 적용
        ws.auto_filter.ref = ws.dimensions

    def _create_dashboard_sheet(self, wb, data):
        """[Dashboard] KPI 카드 + 3D 차트"""
        if "Sheet" in wb.sheetnames:
            ws = wb["Sheet"]
            ws.title = "Executive Dashboard"
        else:
            ws = wb.create_sheet("Executive Dashboard", 0)
            
        ws.sheet_view.showGridLines = False # 눈금선 제거 (깔끔하게)

        # 1. 데이터 집계
        risk_counts = {k: 0 for k in self.RISK_COLORS.keys()}
        total_vulns = 0
        critical_count = 0
        
        for row in data:
            risk = row[5]
            if risk in risk_counts:
                risk_counts[risk] += 1
            else:
                risk_counts["Info"] += 1
            
            total_vulns += 1
            if risk == "Critical":
                critical_count += 1
                
        # 자산 수 (Unique IP)
        unique_ips = set(row[0] for row in data)
        total_assets = len(unique_ips)

        # 2. 타이틀 영역
        ws['B2'] = "Z-VulnScan Security Report"
        ws['B2'].font = Font(name='Malgun Gothic', size=20, bold=True, color='1F4E78')
        ws['B3'] = f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        ws['B3'].font = Font(color='777777')

        # 3. KPI 카드 영역 (B5 ~ H8)
        # 카드 1: Total Assets
        self._draw_kpi_card(ws, 5, 2, "Total Assets", total_assets, "E2EFDA")
        # 카드 2: Total Vulnerabilities
        self._draw_kpi_card(ws, 5, 5, "Total Issues", total_vulns, "FFF2CC")
        # 카드 3: Critical Risks
        self._draw_kpi_card(ws, 5, 8, "Critical Risks", critical_count, "FFC7CE")

        # 4. 차트 데이터 테이블 (숨김 처리하거나 아래쪽에 배치)
        table_start_row = 12
        ws.cell(row=table_start_row, column=2, value="Risk Level")
        ws.cell(row=table_start_row, column=3, value="Count")
        
        row = table_start_row + 1
        for risk, count in risk_counts.items():
            if count > 0: # 0인 데이터는 차트에서 제외
                ws.cell(row=row, column=2, value=risk)
                ws.cell(row=row, column=3, value=count)
                row += 1
        
        data_end_row = row - 1

        # 5. 3D 차트 생성
        if data_end_row > table_start_row:
            chart = PieChart3D()
            chart.title = "Vulnerability Risk Distribution"
            chart.style = 26 # 엑셀 내장 프리미엄 스타일 (세련된 색상)
            
            labels = Reference(ws, min_col=2, min_row=table_start_row+1, max_row=data_end_row)
            data_ref = Reference(ws, min_col=3, min_row=table_start_row+1, max_row=data_end_row)
            
            chart.add_data(data_ref, titles_from_data=False)
            chart.set_categories(labels)
            
            # 차트 크기 및 위치
            chart.width = 18
            chart.height = 10
            ws.add_chart(chart, "B12") # 차트 배치
        else:
            ws['B12'] = "데이터가 충분하지 않아 차트를 생성할 수 없습니다."

        wb.active = ws

    def _draw_kpi_card(self, ws, row, col, title, value, color_hex):
        """KPI 카드 그리기 헬퍼 함수"""
        # 병합 범위 설정 (3x2 크기)
        ws.merge_cells(start_row=row, start_column=col, end_row=row+2, end_column=col+2)
        
        cell = ws.cell(row=row, column=col)
        cell.value = f"{title}\n{value}"
        cell.font = self.KPI_VALUE_FONT
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        cell.fill = PatternFill(start_color=color_hex, end_color=color_hex, fill_type='solid')
        
        # 테두리 그리기 (병합된 셀 전체에 적용하려면 루프 필요)
        for r in range(row, row+3):
            for c in range(col, col+3):
                ws.cell(row=r, column=c).border = self.BORDER_THIN