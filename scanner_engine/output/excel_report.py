# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import os
import sys
import sqlite3
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.chart import PieChart, Reference
from openpyxl.utils import get_column_letter

from utils.db_connector import DBConnector
from utils.logger import AppLogger

class ExcelGenerator:
    # --- [개선된 스타일 정의] ---
    
    # 1. 색상 팔레트 (모던 블루 테마)
    PRIMARY_BLUE = '0066CC'
    DARK_BLUE = '003D7A'
    LIGHT_BLUE = 'E6F2FF'
    ACCENT_ORANGE = 'FF6B35'
    NEUTRAL_GRAY = 'F5F5F5'
    DARK_GRAY = '4A4A4A'
    
    # 2. 헤더 스타일
    HEADER_FILL = PatternFill(start_color=DARK_BLUE, end_color=DARK_BLUE, fill_type='solid')
    HEADER_FONT = Font(name='Segoe UI', size=11, bold=True, color='FFFFFF')
    
    # 3. 서브헤더 스타일
    SUBHEADER_FILL = PatternFill(start_color=LIGHT_BLUE, end_color=LIGHT_BLUE, fill_type='solid')
    SUBHEADER_FONT = Font(name='Segoe UI', size=10, bold=True, color=DARK_BLUE)
    
    # 4. KPI 카드 스타일
    KPI_TITLE_FONT = Font(name='Segoe UI', size=10, color='666666')
    KPI_VALUE_FONT = Font(name='Segoe UI', size=32, bold=True, color=DARK_BLUE)
    KPI_SUBTITLE_FONT = Font(name='Segoe UI', size=9, color='888888', italic=True)
    
    # 5. 테두리 스타일
    BORDER_THIN = Border(
        left=Side(style='thin', color='CCCCCC'),
        right=Side(style='thin', color='CCCCCC'),
        top=Side(style='thin', color='CCCCCC'),
        bottom=Side(style='thin', color='CCCCCC')
    )
    
    BORDER_THICK = Border(
        left=Side(style='medium', color=DARK_BLUE),
        right=Side(style='medium', color=DARK_BLUE),
        top=Side(style='medium', color=DARK_BLUE),
        bottom=Side(style='medium', color=DARK_BLUE)
    )
    
    # 6. 위험도 색상 (더 명확한 그라데이션)
    RISK_COLORS = {
        "Critical": "DC3545",  # 진한 빨강
        "High":     "FD7E14",  # 주황
        "Medium":   "FFC107",  # 노랑
        "Low":      "28A745",  # 초록
        "Info":     "6C757D",  # 회색
        "Safe":     "20C997"   # 청록
    }
    
    # 7. 위험도 아이콘 (유니코드)
    RISK_ICONS = {
        "Critical": "🔴",
        "High":     "🟠",
        "Medium":   "🟡",
        "Low":      "🟢",
        "Info":     "⚪",
        "Safe":     "✅"
    }

    def __init__(self):
        self.db = DBConnector()
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
            
        self.output_dir = os.path.join(base_path, 'reports')
        
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except OSError:
                pass

    def generate(self):
        try:
            wb = Workbook()
            data = self._fetch_data()
            
            # 데이터 검증
            if not data:
                raise Exception("진단된 자산 데이터가 없습니다.")
            
            # 시트 생성 순서
            self._create_dashboard_sheet(wb, data)
            self._create_summary_sheet(wb, data)
            self._create_detail_sheet(wb, data)
            self._create_remediation_sheet(wb, data)
            
            # 기본 Sheet 제거
            if "Sheet" in wb.sheetnames:
                wb.remove(wb["Sheet"])

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

    def _create_dashboard_sheet(self, wb, data):
        """[Dashboard] 경영진 요약 대시보드"""
        ws = wb.active
        ws.title = "📊 Dashboard"
        ws.sheet_view.showGridLines = False
        
        # 배경색 설정
        for row in ws.iter_rows(min_row=1, max_row=50, min_col=1, max_col=15):
            for cell in row:
                cell.fill = PatternFill(start_color='FFFFFF', end_color='FFFFFF', fill_type='solid')

        # === 타이틀 섹션 ===
        ws.merge_cells('B2:M2')
        title_cell = ws['B2']
        title_cell.value = "Z-VulnScan Security Assessment Report"
        title_cell.font = Font(name='Segoe UI', size=24, bold=True, color=self.DARK_BLUE)
        title_cell.alignment = Alignment(horizontal='left', vertical='center')
        
        ws.merge_cells('B3:M3')
        subtitle_cell = ws['B3']
        subtitle_cell.value = f"Report Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}"
        subtitle_cell.font = Font(name='Segoe UI', size=11, color='666666', italic=True)
        subtitle_cell.alignment = Alignment(horizontal='left', vertical='center')
        
        # 구분선
        ws.merge_cells('B4:M4')
        ws['B4'].fill = PatternFill(start_color=self.PRIMARY_BLUE, end_color=self.PRIMARY_BLUE, fill_type='solid')
        ws.row_dimensions[4].height = 3

        # === 데이터 집계 ===
        risk_counts = {k: 0 for k in self.RISK_COLORS.keys()}
        total_vulns = 0
        
        for row in data:
            risk = row[5]
            if risk in risk_counts:
                risk_counts[risk] += 1
            else:
                risk_counts["Info"] += 1
            total_vulns += 1
        
        unique_ips = set(row[0] for row in data)
        total_assets = len(unique_ips)
        critical_high = risk_counts["Critical"] + risk_counts["High"]

        # === KPI 카드 섹션 ===
        self._draw_modern_kpi(ws, 6, 2, "Total Assets Scanned", total_assets, "🖥️", "E8F4F8")
        self._draw_modern_kpi(ws, 6, 5, "Total Vulnerabilities", total_vulns, "⚠️", "FFF4E6")
        self._draw_modern_kpi(ws, 6, 8, "Critical & High", critical_high, "🔥", "FFE5E5")
        self._draw_modern_kpi(ws, 6, 11, "Compliance Score", 
                             f"{max(0, 100 - (critical_high * 5))}%", "✓", "E8F5E9")

        # === 위험도 분포 테이블 ===
        table_row = 12
        ws.merge_cells(f'B{table_row}:F{table_row}')
        ws[f'B{table_row}'].value = "Risk Distribution Summary"
        ws[f'B{table_row}'].font = Font(name='Segoe UI', size=14, bold=True, color=self.DARK_BLUE)
        
        table_row += 1
        headers = ["Risk Level", "Count", "Percentage", "Status"]
        for col_idx, header in enumerate(headers, 2):
            cell = ws.cell(row=table_row, column=col_idx)
            cell.value = header
            cell.fill = self.HEADER_FILL
            cell.font = self.HEADER_FONT
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = self.BORDER_THIN
        
        table_row += 1
        for risk in ["Critical", "High", "Medium", "Low", "Info"]:
            count = risk_counts[risk]
            percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
            
            # Risk Level
            cell = ws.cell(row=table_row, column=2)
            cell.value = f"{self.RISK_ICONS.get(risk, '')} {risk}"
            cell.fill = PatternFill(start_color=self.RISK_COLORS[risk], 
                                    end_color=self.RISK_COLORS[risk], fill_type='solid')
            cell.font = Font(name='Segoe UI', size=10, bold=True, color='FFFFFF')
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = self.BORDER_THIN
            
            # Count
            ws.cell(row=table_row, column=3, value=count).alignment = Alignment(horizontal='center')
            ws.cell(row=table_row, column=3).border = self.BORDER_THIN
            
            # Percentage
            ws.cell(row=table_row, column=4, value=f"{percentage:.1f}%").alignment = Alignment(horizontal='center')
            ws.cell(row=table_row, column=4).border = self.BORDER_THIN
            
            # Status bar (visual)
            status_cell = ws.cell(row=table_row, column=5)
            bar_length = int(percentage / 10)
            status_cell.value = "█" * bar_length
            status_cell.font = Font(color=self.RISK_COLORS[risk])
            status_cell.border = self.BORDER_THIN
            
            table_row += 1

        # === 차트 생성 ===
        chart = PieChart()
        chart.title = "Vulnerability Distribution"
        chart.style = 10
        
        # 차트 데이터 준비
        chart_start = 25
        ws.cell(row=chart_start, column=2, value="Risk")
        ws.cell(row=chart_start, column=3, value="Count")
        
        row = chart_start + 1
        for risk, count in risk_counts.items():
            if count > 0:
                ws.cell(row=row, column=2, value=risk)
                ws.cell(row=row, column=3, value=count)
                row += 1
        
        data_end = row - 1
        
        if data_end > chart_start:
            labels = Reference(ws, min_col=2, min_row=chart_start+1, max_row=data_end)
            data_ref = Reference(ws, min_col=3, min_row=chart_start+1, max_row=data_end)
            chart.add_data(data_ref, titles_from_data=False)
            chart.set_categories(labels)
            chart.width = 15
            chart.height = 10
            ws.add_chart(chart, "H12")

        # 컬럼 너비 조정
        ws.column_dimensions['A'].width = 2
        ws.column_dimensions['B'].width = 20
        ws.column_dimensions['C'].width = 15
        ws.column_dimensions['D'].width = 15
        ws.column_dimensions['E'].width = 20
        ws.column_dimensions['F'].width = 15

    def _draw_modern_kpi(self, ws, row, col, title, value, icon, bg_color):
        """모던한 KPI 카드 디자인"""
        # 4x3 영역 병합
        ws.merge_cells(start_row=row, start_column=col, end_row=row+3, end_column=col+2)
        
        cell = ws.cell(row=row, column=col)
        cell.value = f"{icon}\n{title}\n{value}"
        cell.fill = PatternFill(start_color=bg_color, end_color=bg_color, fill_type='solid')
        cell.font = Font(name='Segoe UI', size=11, bold=True, color=self.DARK_BLUE)
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        
        # 테두리 적용
        for r in range(row, row+4):
            for c in range(col, col+3):
                ws.cell(row=r, column=c).border = Border(
                    left=Side(style='medium', color=self.PRIMARY_BLUE),
                    right=Side(style='medium', color=self.PRIMARY_BLUE),
                    top=Side(style='medium', color=self.PRIMARY_BLUE),
                    bottom=Side(style='medium', color=self.PRIMARY_BLUE)
                )

    def _create_summary_sheet(self, wb, data):
        """[Summary] 자산별 요약"""
        ws = wb.create_sheet("📋 Summary by Asset")
        
        # 헤더
        headers = ["IP Address", "Hostname", "OS", "Critical", "High", "Medium", "Low", "Total", "Risk Score"]
        ws.append(headers)
        
        for col in range(1, len(headers) + 1):
            cell = ws.cell(row=1, column=col)
            cell.fill = self.HEADER_FILL
            cell.font = self.HEADER_FONT
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = self.BORDER_THIN
        
        # 자산별 집계
        asset_summary = {}
        for row in data:
            ip = row[0]
            if ip not in asset_summary:
                asset_summary[ip] = {
                    'hostname': row[1],
                    'os': row[2],
                    'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0
                }
            risk = row[5]
            if risk in asset_summary[ip]:
                asset_summary[ip][risk] += 1
        
        # 데이터 작성
        for ip, info in sorted(asset_summary.items()):
            total = sum([info['Critical'], info['High'], info['Medium'], info['Low']])
            risk_score = info['Critical'] * 10 + info['High'] * 5 + info['Medium'] * 2 + info['Low']
            
            row_data = [
                ip, info['hostname'], info['os'],
                info['Critical'], info['High'], info['Medium'], info['Low'],
                total, risk_score
            ]
            ws.append(row_data)
            
            row_num = ws.max_row
            for col in range(1, len(row_data) + 1):
                cell = ws.cell(row=row_num, column=col)
                cell.border = self.BORDER_THIN
                cell.alignment = Alignment(horizontal='center', vertical='center')
                
                # 숫자 컬럼 하이라이트
                if col >= 4 and col <= 7:
                    val = row_data[col-1]
                    if val > 0:
                        if col == 4:  # Critical
                            cell.fill = PatternFill(start_color='FFCCCC', end_color='FFCCCC', fill_type='solid')
                        elif col == 5:  # High
                            cell.fill = PatternFill(start_color='FFE6CC', end_color='FFE6CC', fill_type='solid')
        
        # 컬럼 너비
        widths = [15, 20, 12, 10, 10, 10, 10, 10, 12]
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w
        
        ws.auto_filter.ref = ws.dimensions

    def _create_detail_sheet(self, wb, data):
        """[Detail] 상세 취약점 목록"""
        ws = wb.create_sheet("📄 Vulnerability Details")
        
        headers = ["IP", "Hostname", "OS", "Code", "Vulnerability Name", "Risk", "Status", "Details", "Remediation", "Scan Date"]
        ws.append(headers)
        
        for col in range(1, len(headers) + 1):
            cell = ws.cell(row=1, column=col)
            cell.fill = self.HEADER_FILL
            cell.font = self.HEADER_FONT
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = self.BORDER_THIN
        
        for row_idx, row_data in enumerate(data, 2):
            for col_idx, val in enumerate(row_data, 1):
                cell = ws.cell(row=row_idx, column=col_idx, value=str(val))
                cell.border = self.BORDER_THIN
                cell.alignment = Alignment(vertical='top', wrap_text=True)
                
                # Risk 컬럼
                if col_idx == 6 and val in self.RISK_COLORS:
                    icon = self.RISK_ICONS.get(val, '')
                    cell.value = f"{icon} {val}"
                    cell.fill = PatternFill(start_color=self.RISK_COLORS[val], 
                                            end_color=self.RISK_COLORS[val], fill_type='solid')
                    cell.font = Font(bold=True, color='FFFFFF')
                    cell.alignment = Alignment(horizontal='center', vertical='center')
        
        widths = [14, 18, 10, 10, 35, 12, 10, 40, 40, 18]
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w
        
        ws.auto_filter.ref = ws.dimensions
        ws.freeze_panes = 'A2'

    def _create_remediation_sheet(self, wb, data):
        """[Remediation] 조치 가이드"""
        ws = wb.create_sheet("🔧 Remediation Guide")
        
        # 타이틀
        ws.merge_cells('A1:E1')
        ws['A1'] = "Priority Remediation Actions"
        ws['A1'].font = Font(name='Segoe UI', size=16, bold=True, color=self.DARK_BLUE)
        ws['A1'].alignment = Alignment(horizontal='center', vertical='center')
        ws.row_dimensions[1].height = 30
        
        # Critical & High만 필터링
        priority_items = [row for row in data if row[5] in ['Critical', 'High']]
        
        headers = ["Priority", "IP", "Vulnerability", "Risk", "Remediation Action"]
        ws.append(headers)
        
        for col in range(1, len(headers) + 1):
            cell = ws.cell(row=2, column=col)
            cell.fill = self.HEADER_FILL
            cell.font = self.HEADER_FONT
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = self.BORDER_THIN
        
        for idx, row in enumerate(priority_items, 1):
            ws.append([
                idx,
                row[0],
                row[4],
                f"{self.RISK_ICONS.get(row[5], '')} {row[5]}",
                row[8]
            ])
            
            row_num = ws.max_row
            for col in range(1, 6):
                cell = ws.cell(row=row_num, column=col)
                cell.border = self.BORDER_THIN
                cell.alignment = Alignment(vertical='top', wrap_text=True)
                
                if col == 4:  # Risk column
                    cell.fill = PatternFill(start_color=self.RISK_COLORS[row[5]], 
                                            end_color=self.RISK_COLORS[row[5]], fill_type='solid')
                    cell.font = Font(bold=True, color='FFFFFF')
                    cell.alignment = Alignment(horizontal='center', vertical='center')
        
        ws.column_dimensions['A'].width = 10
        ws.column_dimensions['B'].width = 15
        ws.column_dimensions['C'].width = 40
        ws.column_dimensions['D'].width = 15
        ws.column_dimensions['E'].width = 50