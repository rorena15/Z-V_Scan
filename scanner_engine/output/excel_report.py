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
import re
from datetime import datetime
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from utils.os_utils import OSUtils
from utils.oui_lookup import OUILookup  # [New] 벤더 조회를 위해 추가

class ExcelGenerator:
    def __init__(self):
        # DB 경로 설정
        if getattr(sys, 'frozen', False):
            self.project_root = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            self.project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        
        # [Fix] DB 및 리포트 경로 설정
        self.db_path = os.path.join(self.project_root, 'zvuln_scan.db')
        
        # [수정] 폴더명을 'reports'로 변경하여 가시성 확보
        self.output_dir = os.path.join(self.project_root, 'reports')

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = os.path.join(self.output_dir, f"ZVulnScan_Report_{timestamp}.xlsx")

        # OS 맞춤 글꼴
        if OSUtils.is_windows():
            self.font_name = '맑은 고딕'
        else:
            self.font_name = 'NanumGothic'

        # 스타일 정의
        self.header_font = Font(name=self.font_name, size=11, bold=True, color='FFFFFF')
        self._signature = "Made_By_Rorena_2025_Seongnam_KR"
        self.header_fill = PatternFill(start_color='1F497D', end_color='1F497D', fill_type='solid')
        self.center_align = Alignment(horizontal='center', vertical='center')
        self.left_align = Alignment(horizontal='left', vertical='center')
        self.thin_border = Border(left=Side(style='thin'), right=Side(style='thin'), 
                                    top=Side(style='thin'), bottom=Side(style='thin'))
        
        # 상태별 색상 정의
        self.vuln_fill = PatternFill(start_color='FFC7CE', end_color='FFC7CE', fill_type='solid') 
        self.vuln_font = Font(name=self.font_name, color='9C0006')
        
        self.warn_fill = PatternFill(start_color='FFEB9C', end_color='FFEB9C', fill_type='solid')
        self.warn_font = Font(name=self.font_name, color='9C5700')

        self.safe_fill = PatternFill(start_color='C6EFCE', end_color='C6EFCE', fill_type='solid') 
        self.safe_font = Font(name=self.font_name, color='006100')

    def _sanitize(self, value):
        if isinstance(value, str):
            return ILLEGAL_CHARACTERS_RE.sub("", value)
        return value

    def generate(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT count(*) FROM TBL_ASSETS")
            count = cursor.fetchone()[0]
            if count == 0:
                conn.close()
                raise Exception("리포트를 생성할 데이터가 없습니다.\n먼저 스캔을 수행해주세요.")
        except sqlite3.OperationalError:
            conn.close()
            raise Exception("진단 데이터가 없습니다.\n먼저 [Network Discovery] 또는 [Vulnerability Audit]을 수행해주세요.")
        except Exception as e:
            conn.close()
            raise e
        
        try:
            wb = openpyxl.Workbook()
        
            # Sheet 1: Dashboard
            ws_dash = wb.active
            ws_dash.title = "Dashboard"
            self._create_dashboard(ws_dash, cursor)
        
            # Sheet 2: Asset List
            ws_asset = wb.create_sheet("Asset List")
            self._create_asset_list(ws_asset, cursor)
        
            # Sheet 3: Vulnerability Details
            ws_vuln = wb.create_sheet("Vulnerability Details")
            self._create_vuln_detail(ws_vuln, cursor)
            
            if "Sheet" in wb.sheetnames and len(wb.sheetnames) > 1:
                wb.remove(wb["Sheet"])

            conn.close()
            wb.save(self.filename)
            return self.filename
        
        except Exception as e:
            if conn: conn.close()
            raise Exception(f"엑셀 생성 중 오류 발생: {str(e)}")

    def _apply_header_style(self, ws, headers):
        for col_num, header_title in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_num, value=header_title)
            cell.font = self.header_font
            cell.fill = self.header_fill
            cell.alignment = self.center_align
            cell.border = self.thin_border

    def _auto_filter_and_width(self, ws):
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
            ws.column_dimensions[column_letter].width = min(adjusted_width, 60)

    def _create_dashboard(self, ws, cursor):
        ws.merge_cells('A1:D1')
        title = ws['A1']
        title.value = "Z-VulnScan Audit Summary"
        title.font = Font(name=self.font_name, size=16, bold=True)
        title.alignment = self.center_align
        
        cursor.execute("SELECT COUNT(*) FROM TBL_ASSETS")
        total_assets = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT WHERE status IN ('VULNERABLE', '취약', 'Fail', 'Critical', 'High')")
        total_vuln = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT WHERE status IN ('WARNING', '경고', 'Medium', 'Low')")
        total_warn = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT")
        total_checks = cursor.fetchone()[0]
        
        deduction = (total_vuln * 10) + (total_warn * 3)
        safe_score = max(0, 100 - deduction) if total_checks > 0 else 0
        if total_vuln > 0 and safe_score > 90: safe_score = 90

        headers = ["Total Assets", "Total Checks", "Risks (Vuln/Warn)", "Security Score"]
        values = [total_assets, total_checks, f"{total_vuln} / {total_warn}", f"{safe_score} / 100"]
        
        for i, (h, v) in enumerate(zip(headers, values)):
            cell_h = ws.cell(row=3, column=i+1, value=h)
            cell_h.font = self.header_font
            cell_h.fill = self.header_fill
            cell_h.alignment = self.center_align
            cell_h.border = self.thin_border
            
            cell_v = ws.cell(row=4, column=i+1, value=v)
            cell_v.alignment = self.center_align
            cell_v.font = Font(name=self.font_name, bold=True, size=12)
            cell_v.border = self.thin_border
            
            if h == "Risks (Vuln/Warn)" and (total_vuln + total_warn) > 0:
                cell_v.font = Font(name=self.font_name, bold=True, size=12, color='FF0000')

        ws.column_dimensions['A'].width = 20
        ws.column_dimensions['B'].width = 20
        ws.column_dimensions['C'].width = 25
        ws.column_dimensions['D'].width = 20

    def _create_asset_list(self, ws, cursor):
        # [수정] 벤더, 메모, MAC 주소 컬럼 추가
        headers = ["Asset ID", "IP Address", "Hostname", "OS Type", "MAC Address", "Vendor", "Memo", "Last Seen"]
        self._apply_header_style(ws, headers)
        
        # [수정] mac_addr, memo 추가 조회
        cursor.execute("SELECT asset_id, ip_addr, hostname, os_type, mac_addr, memo, last_seen FROM TBL_ASSETS")
        rows = cursor.fetchall()
        
        for r_idx, row in enumerate(rows, 2):
            # row: (id, ip, host, os, mac, memo, date)
            mac_addr = row[4]
            # OUI Lookup을 통해 벤더 식별
            vendor = OUILookup.lookup(mac_addr)
            
            # 엑셀에 쓸 데이터 리스트 재구성
            row_data = [row[0], row[1], row[2], row[3], mac_addr, vendor, row[5], row[6]]
            
            for c_idx, val in enumerate(row_data, 1):
                clean_val = self._sanitize(val)
                cell = ws.cell(row=r_idx, column=c_idx, value=clean_val)
                cell.font = Font(name=self.font_name)
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
            ip, code, name, status, detail, remediation = row
            
            vuln_group = ['VULNERABLE', '취약', 'Fail', 'Critical', 'High']
            warn_group = ['WARNING', '경고', 'Medium', 'Low']
            
            is_vuln = status in vuln_group
            is_warn = status in warn_group
            
            if not (is_vuln or is_warn):
                remediation = "-"

            row_vals = [ip, code, name, status, detail, remediation]
            
            for c_idx, val in enumerate(row_vals, 1):
                clean_val = self._sanitize(val)
                cell = ws.cell(row=r_idx, column=c_idx, value=clean_val)
                cell.border = self.thin_border
                cell.alignment = self.left_align
                cell.font = Font(name=self.font_name)
                
                if c_idx in [1, 2, 4]: 
                    cell.alignment = self.center_align

                if c_idx == 4: # Status
                    if is_vuln:
                        cell.fill = self.vuln_fill
                        cell.font = self.vuln_font
                    elif is_warn:
                        cell.fill = self.warn_fill
                        cell.font = self.warn_font
                    else:
                        cell.fill = self.safe_fill
                        cell.font = self.safe_font
        
        self._auto_filter_and_width(ws)