# scanner_engine/output/excel_report.py
import os
import sqlite3
import re  # <--- [추가] 정규식 모듈
from datetime import datetime
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE # <--- [추가] 엑셀 금지 문자 패턴
from utils.os_utils import OSUtils

class ExcelGenerator:
    def __init__(self):
        # DB 경로 설정
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_path = os.path.join(os.path.dirname(base_dir), 'zvuln_scan.db')
        
        # 저장 경로
        self.output_dir = os.path.join(os.path.dirname(base_dir), 'report')
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
        self.header_fill = PatternFill(start_color='1F497D', end_color='1F497D', fill_type='solid')
        self.center_align = Alignment(horizontal='center', vertical='center')
        self.left_align = Alignment(horizontal='left', vertical='center')
        self.thin_border = Border(left=Side(style='thin'), right=Side(style='thin'), 
                                    top=Side(style='thin'), bottom=Side(style='thin'))
        
        # [수정] 상태별 색상 정의 (Red / Yellow / Green)
        # 1. 취약 (Red)
        self.vuln_fill = PatternFill(start_color='FFC7CE', end_color='FFC7CE', fill_type='solid') 
        self.vuln_font = Font(name=self.font_name, color='9C0006')
        
        # 2. 경고 (Yellow) - 추가됨
        self.warn_fill = PatternFill(start_color='FFEB9C', end_color='FFEB9C', fill_type='solid')
        self.warn_font = Font(name=self.font_name, color='9C5700')

        # 3. 양호 (Green)
        self.safe_fill = PatternFill(start_color='C6EFCE', end_color='C6EFCE', fill_type='solid') 
        self.safe_font = Font(name=self.font_name, color='006100')

    def _sanitize(self, value):
        """[핵심] 엑셀에서 허용하지 않는 문자 제거"""
        if isinstance(value, str):
            # openpyxl 제공 정규식으로 불법 문자 제거
            return ILLEGAL_CHARACTERS_RE.sub("", value)
        return value

    def generate(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # 테이블이 존재하는지, 데이터가 있는지 확인
            # 테이블이 없으면 여기서 sqlite3.OperationalError 발생 -> except로 이동
            cursor.execute("SELECT count(*) FROM TBL_ASSETS")
            count = cursor.fetchone()[0]
            
            # 테이블은 있는데 데이터가 0건인 경우
            if count == 0:
                conn.close()
                raise Exception("리포트를 생성할 데이터가 없습니다.\n먼저 스캔을 수행해주세요.")
                
        except sqlite3.OperationalError:
            # "no such table" 에러를 잡아서 사용자 친화적 메시지로 변환
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
        
        # 취약 개수
        cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT WHERE status IN ('VULNERABLE', '취약', 'Fail', 'Critical', 'High')")
        total_vuln = cursor.fetchone()[0]
        
        # 경고 개수
        cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT WHERE status IN ('WARNING', '경고', 'Medium', 'Low')")
        total_warn = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT")
        total_checks = cursor.fetchone()[0]
        
        # 점수 계산 (취약은 크게, 경고는 작게 감점)
        deduction = (total_vuln * 10) + (total_warn * 3)
        safe_score = max(0, 100 - deduction) if total_checks > 0 else 0
        
        if total_vuln > 0 and safe_score > 90:
            safe_score = 90

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
        headers = ["Asset ID", "IP Address", "Hostname", "OS Type", "Last Seen"]
        self._apply_header_style(ws, headers)
        
        cursor.execute("SELECT asset_id, ip_addr, hostname, os_type, last_seen FROM TBL_ASSETS")
        rows = cursor.fetchall()
        
        for r_idx, row in enumerate(rows, 2):
            for c_idx, val in enumerate(row, 1):
                # _sanitize 적용
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
            
            # [수정] 상태 그룹 정의
            vuln_group = ['VULNERABLE', '취약', 'Fail', 'Critical', 'High']
            warn_group = ['WARNING', '경고', 'Medium', 'Low']
            
            is_vuln = status in vuln_group
            is_warn = status in warn_group
            
            # 양호(SAFE)일 때만 조치 방안 숨기기
            # (WARNING일 때도 조치 방안은 보여주는 게 맞음)
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

                # [수정] 3색(Red, Yellow, Green) 분기 적용
                if c_idx == 4: # Status Column
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