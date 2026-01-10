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
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from utils.os_utils import OSUtils
from utils.oui_lookup import OUILookup

class ExcelGenerator:
    def __init__(self):
        if getattr(sys, 'frozen', False):
            self.project_root = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            self.project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        
        self.db_path = os.path.join(self.project_root, 'zvuln_scan.db')
        self.output_dir = os.path.join(self.project_root, 'reports')
        if not os.path.exists(self.output_dir): os.makedirs(self.output_dir, exist_ok=True)
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = os.path.join(self.output_dir, f"ZVulnScan_Report_{timestamp}.xlsx")

        self.font_name = '맑은 고딕' if OSUtils.is_windows() else 'NanumGothic'
        self.header_font = Font(name=self.font_name, size=11, bold=True, color='FFFFFF')
        self.header_fill = PatternFill(start_color='1F497D', end_color='1F497D', fill_type='solid')
        self.center = Alignment(horizontal='center', vertical='center')
        self.border = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'), bottom=Side(style='thin'))

    def _sanitize(self, value):
        return ILLEGAL_CHARACTERS_RE.sub("", str(value)) if value else "-"

    def generate(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            wb = openpyxl.Workbook()
            
            # 1. Dashboard
            ws_dash = wb.active
            ws_dash.title = "Dashboard"
            
            cursor.execute("SELECT COUNT(*) FROM TBL_ASSETS")
            total_assets = cursor.fetchone()[0]
            
            # [수정] status가 아닌 risk_level 기준으로 카운트 (DB 구조 반영)
            cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT WHERE risk_level IN ('Critical', 'High')")
            total_vuln = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT WHERE risk_level IN ('Medium', 'Low')")
            total_warn = cursor.fetchone()[0]
            
            ws_dash['A1'] = "Z-VulnScan Audit Summary"
            ws_dash['A1'].font = Font(size=16, bold=True)
            
            headers = ["Total Assets", "Critical/High Risks", "Medium/Low Risks"]
            values = [total_assets, total_vuln, total_warn]
            
            for i, (h, v) in enumerate(zip(headers, values), 1):
                ws_dash.cell(row=3, column=i, value=h).font = Font(bold=True)
                ws_dash.cell(row=4, column=i, value=v).alignment = self.center

            # 2. Asset List
            ws_asset = wb.create_sheet("Asset List")
            headers = ["IP Address", "Hostname", "OS Type", "MAC Address", "Vendor", "Memo", "Last Seen"]
            for i, h in enumerate(headers, 1):
                c = ws_asset.cell(row=1, column=i, value=h)
                c.fill = self.header_fill
                c.font = self.header_font
            
            cursor.execute("SELECT ip_addr, hostname, os_type, mac_addr, memo, last_seen FROM TBL_ASSETS")
            for idx, row in enumerate(cursor.fetchall(), 2):
                vendor = OUILookup.lookup(row[3])
                data = [row[0], row[1], row[2], row[3], vendor, row[4], row[5]]
                for c, val in enumerate(data, 1):
                    ws_asset.cell(row=idx, column=c, value=self._sanitize(val)).alignment = self.center

            # 3. Vulnerability Details
            ws_vuln = wb.create_sheet("Vulnerability Details")
            headers = ["IP Address", "Code", "Item Name", "Risk Level", "Status", "Detailed Result", "Remediation"]
            for i, h in enumerate(headers, 1):
                c = ws_vuln.cell(row=1, column=i, value=h)
                c.fill = self.header_fill
                c.font = self.header_font

            # [핵심 수정] JOIN TBL_VULN_DEF 제거 -> 단일 테이블 조회
            sql = """
                SELECT A.ip_addr, R.vuln_code, R.vuln_name, R.risk_level, R.status, R.detected_value, R.remediation
                FROM TBL_SCAN_RESULT R
                JOIN TBL_ASSETS A ON R.asset_id = A.asset_id
                ORDER BY A.ip_addr ASC, R.risk_level DESC
            """
            cursor.execute(sql)
            
            for idx, row in enumerate(cursor.fetchall(), 2):
                # row: ip, code, name, risk, status, detail, rem
                for c, val in enumerate(row, 1):
                    cell = ws_vuln.cell(row=idx, column=c, value=self._sanitize(val))
                    cell.alignment = Alignment(vertical='center', wrap_text=True)
                    
                    if c == 4: # Risk Level
                        if val in ['Critical', 'High']: 
                            cell.font = Font(color='FF0000', bold=True)
                        elif val in ['Medium', 'Low']:
                            cell.font = Font(color='FFA500')

            wb.save(self.filename)
            return self.filename

        except Exception as e:
            raise Exception(f"Excel Error: {str(e)}")
        finally:
            if conn: conn.close()