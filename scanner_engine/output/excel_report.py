# scanner_engine/output/excel_report.py
import os
import sqlite3
from datetime import datetime
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

class ExcelGenerator:
    def __init__(self):
        # DB 경로 설정
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_path = os.path.join(os.path.dirname(base_dir), 'zvuln_scan.db')
        
        # 저장 경로 (report 폴더)
        self.output_dir = os.path.join(os.path.dirname(base_dir), 'report')
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = os.path.join(self.output_dir, f"ZVulnScan_Enterprise_Report_{timestamp}.xlsx")

        # 스타일 정의
        self.header_font = Font(name='맑은 고딕', size=11, bold=True, color='FFFFFF')
        self.header_fill = PatternFill(start_color='1F497D', end_color='1F497D', fill_type='solid') # Navy
        self.center_align = Alignment(horizontal='center', vertical='center')
        self.left_align = Alignment(horizontal='left', vertical='center')
        self.thin_border = Border(left=Side(style='thin'), right=Side(style='thin'), 
                                  top=Side(style='thin'), bottom=Side(style='thin'))
        
        # 상태별 색상
        self.vuln_fill = PatternFill(start_color='FFC7CE', end_color='FFC7CE', fill_type='solid') # Red text box style
        self.vuln_font = Font(color='9C0006')
        self.safe_fill = PatternFill(start_color='C6EFCE', end_color='C6EFCE', fill_type='solid') # Green text box style
        self.safe_font = Font(color='006100')

    def generate(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        wb = openpyxl.Workbook()
        
        # --- Sheet 1: Dashboard (요약) ---
        ws_dash = wb.active
        ws_dash.title = "Dashboard"
        self._create_dashboard(ws_dash, cursor)
        
        # --- Sheet 2: Asset List (자산 목록) ---
        ws_asset = wb.create_sheet("Asset List")
        self._create_asset_list(ws_asset, cursor)
        
        # --- Sheet 3: Vulnerability Details (상세 취약점) ---
        ws_vuln = wb.create_sheet("Vulnerability Details")
        self._create_vuln_detail(ws_vuln, cursor)

        conn.close()
        wb.save(self.filename)
        return self.filename

    def _apply_header_style(self, ws, headers):
        """헤더 스타일 일괄 적용"""
        for col_num, header_title in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_num, value=header_title)
            cell.font = self.header_font
            cell.fill = self.header_fill
            cell.alignment = self.center_align
            cell.border = self.thin_border

    def _auto_filter_and_width(self, ws):
        """자동 필터 및 컬럼 너비 조정"""
        ws.auto_filter.ref = ws.dimensions
        for column in ws.columns:
            max_length = 0
            column_letter = get_column_letter(column[0].column)
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except: pass
            adjusted_width = (max_length + 2) * 1.1
            ws.column_dimensions[column_letter].width = min(adjusted_width, 60) # 최대 60 고정

    def _create_dashboard(self, ws, cursor):
        ws.merge_cells('A1:D1')
        title = ws['A1']
        title.value = "Z-VulnScan v2.1 Enterprise Audit Summary"
        title.font = Font(size=16, bold=True)
        title.alignment = self.center_align
        
        # 통계 쿼리
        cursor.execute("SELECT COUNT(*) FROM TBL_ASSETS")
        total_assets = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT WHERE status IN ('VULNERABLE', '취약', 'Fail')")
        total_vuln = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT")
        total_checks = cursor.fetchone()[0]
        
        safe_rate = 0
        if total_checks > 0:
            safe_rate = int(((total_checks - total_vuln) / total_checks) * 100)

        # 요약 테이블
        headers = ["Total Assets", "Total Checks", "Vulnerabilities", "Security Score"]
        values = [total_assets, total_checks, total_vuln, f"{safe_rate} / 100"]
        
        for i, (h, v) in enumerate(zip(headers, values)):
            # Header
            cell_h = ws.cell(row=3, column=i+1, value=h)
            cell_h.font = self.header_font
            cell_h.fill = self.header_fill
            cell_h.alignment = self.center_align
            cell_h.border = self.thin_border
            
            # Value
            cell_v = ws.cell(row=4, column=i+1, value=v)
            cell_v.alignment = self.center_align
            cell_v.font = Font(bold=True, size=12)
            cell_v.border = self.thin_border
            
            if h == "Vulnerabilities" and v > 0:
                cell_v.font = Font(bold=True, size=12, color='FF0000')

        ws.column_dimensions['A'].width = 20
        ws.column_dimensions['B'].width = 20
        ws.column_dimensions['C'].width = 20
        ws.column_dimensions['D'].width = 20

    def _create_asset_list(self, ws, cursor):
        headers = ["Asset ID", "IP Address", "Hostname", "OS Type", "Last Seen"]
        self._apply_header_style(ws, headers)
        
        cursor.execute("SELECT asset_id, ip_addr, hostname, os_type, last_seen FROM TBL_ASSETS")
        rows = cursor.fetchall()
        
        for r_idx, row in enumerate(rows, 2):
            for c_idx, val in enumerate(row, 1):
                cell = ws.cell(row=r_idx, column=c_idx, value=val)
                cell.alignment = self.center_align
                cell.border = self.thin_border
        
        self._auto_filter_and_width(ws)

    def _create_vuln_detail(self, ws, cursor):
        headers = ["IP Address", "Code", "Item Name", "Status", "Detailed Result", "Remediation"]
        self._apply_header_style(ws, headers)
        
        sql = """
            SELECT A.ip_addr, V.code, V.name, R.status, R.detected_value, V.remediation
            FROM TBL_SCAN_RESULT R
            JOIN TBL_ASSETS A ON R.asset_id = A.asset_id
            JOIN TBL_VULN_DEF V ON R.vuln_id = V.vuln_id
            ORDER BY A.ip_addr ASC, V.code ASC
        """
        cursor.execute(sql)
        rows = cursor.fetchall()
        
        for r_idx, row in enumerate(rows, 2):
            # Row unpacking
            ip, code, name, status, detail, remediation = row
            
            row_vals = [ip, code, name, status, detail, remediation]
            
            for c_idx, val in enumerate(row_vals, 1):
                cell = ws.cell(row=r_idx, column=c_idx, value=val)
                cell.border = self.thin_border
                cell.alignment = self.left_align
                
                # 가운데 정렬할 컬럼들
                if c_idx in [1, 2, 4]: 
                    cell.alignment = self.center_align

                # 상태별 색상 적용 (Status 컬럼 = 4번째)
                if c_idx == 4:
                    if val in ['VULNERABLE', '취약', 'Fail']:
                        cell.fill = self.vuln_fill
                        cell.font = self.vuln_font
                    else:
                        cell.fill = self.safe_fill
                        cell.font = self.safe_font
        
        self._auto_filter_and_width(ws)