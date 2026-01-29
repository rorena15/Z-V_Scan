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
from openpyxl.utils import get_column_letter

# 상위 모듈 참조
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.db_connector import DBConnector
from utils.logger import AppLogger
import core.vuln_matcher as Vuln
class ExcelGenerator:
    # --- KISA 스타일 상수 정의 ---
    COLOR_HEADER_BG = 'E7E6E6'   # 헤더 배경 (연한 회색)
    COLOR_BORDER = '000000'      # 테두리 (검정)
    
    # 위험도 색상
    COLOR_CRITICAL = 'FFCCCC' # 상 (연한 빨강)
    COLOR_HIGH = 'FFE6CC'     # 중 (연한 주황)
    COLOR_GOOD = 'E2EFDA'     # 양호 (연한 초록)
    COLOR_WAIVER = 'D9D9D9'   # 예외 (회색)

    # 폰트
    FONT_TITLE = Font(name='맑은 고딕', size=20, bold=True)
    FONT_HEADER = Font(name='맑은 고딕', size=10, bold=True)
    FONT_NORMAL = Font(name='맑은 고딕', size=9)
    FONT_BOLD = Font(name='맑은 고딕', size=9, bold=True)

    # 테두리 스타일
    BORDER_ALL = Border(
        left=Side(style='thin', color=COLOR_BORDER),
        right=Side(style='thin', color=COLOR_BORDER),
        top=Side(style='thin', color=COLOR_BORDER),
        bottom=Side(style='thin', color=COLOR_BORDER)
    )

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

    def _style_range(self, ws, cell_range, border=None, fill=None, font=None, alignment=None):
        """
        [Fix] 단일 셀('A1')과 범위('A1:B2') 모두 처리하도록 개선
        """
        selection = ws[cell_range]
        
        # 만약 selection이 튜플/리스트가 아니라면(단일 Cell 객체라면), 튜플로 감싸서 반복 가능하게 만듦
        if not isinstance(selection, (tuple, list)):
            selection = ((selection,),)
            
        for row in selection:
            for cell in row:
                if border: cell.border = border
                if fill: cell.fill = fill
                if font: cell.font = font
                if alignment: cell.alignment = alignment

    def generate(self):
        try:
            wb = Workbook()
            
            Vuln.VulnMatcher.sync_kisa_code_on_db(self.db.db_path)
            
            scan_data = self._fetch_scan_result()
            asset_data = self._fetch_asset_list()
            
            if not asset_data:
                raise Exception("진단된 자산 데이터가 없습니다.")
            
            self._create_cover_sheet(wb, asset_data, scan_data)
            self._create_detail_sheet(wb, scan_data)
            self._create_asset_sheet(wb, asset_data)
            
            if "Sheet" in wb.sheetnames:
                wb.remove(wb["Sheet"])

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"주요정보통신기반시설_취약점진단결과_{timestamp}.xlsx"
            filepath = os.path.join(self.output_dir, filename)
            
            wb.save(filepath)
            return filepath

        except Exception as e:
            AppLogger.log_error("Excel Generation Error", e)
            raise e

        
    def _fetch_scan_result(self):
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        try:
            query = """
                SELECT 
                    A.ip_addr, A.hostname, 
                    R.kisa_code, R.vuln_code, R.vuln_name, 
                    R.risk_level, R.status, R.detected_value, 
                    R.raw_output, R.remediation, R.waiver_status, R.waiver_reason
                FROM TBL_SCAN_RESULT R
                JOIN TBL_ASSETS A ON R.asset_id = A.asset_id
                ORDER BY A.ip_addr ASC, R.kisa_code ASC
            """
            cursor.execute(query)
            return cursor.fetchall()
        except Exception as e:
            AppLogger.log_error("Fetch Scan Result Error", e)
            return []
        finally:
            conn.close()

    def _fetch_asset_list(self):
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT ip_addr, hostname, os_type, mac_addr FROM TBL_ASSETS")
            return cursor.fetchall()
        except: return []
        finally: conn.close()

    def _create_cover_sheet(self, wb, asset_data, scan_data):
        ws = wb.active
        ws.title = "1.종합요약"
        
        # 1. 제목
        ws.merge_cells('B2:I3')
        ws['B2'] = "주요정보통신기반시설 기술적 취약점 분석 평가 결과"
        self._style_range(ws, 'B2:I3', border=self.BORDER_ALL, font=self.FONT_TITLE, 
                          alignment=Alignment(horizontal='center', vertical='center'))

        # 2. 결재란
        start_col = 11 # K열
        col_letter = get_column_letter(start_col)
        
        # '결재'
        range_str = f'{col_letter}2:{col_letter}5'
        ws.merge_cells(range_str)
        ws[f'{col_letter}2'] = "결\n\n재"
        self._style_range(ws, range_str, border=self.BORDER_ALL, 
                          fill=PatternFill(start_color=self.COLOR_HEADER_BG, fill_type='solid'),
                          alignment=Alignment(horizontal='center', vertical='center', wrap_text=True))

        roles = ["담 당", "팀 장", "부서장"]
        for i, role in enumerate(roles):
            c = get_column_letter(start_col + 1 + i)
            
            # 직책 (단일 셀)
            ws[f'{c}2'] = role
            self._style_range(ws, f'{c}2', border=self.BORDER_ALL, 
                              fill=PatternFill(start_color=self.COLOR_HEADER_BG, fill_type='solid'),
                              alignment=Alignment(horizontal='center', vertical='center'))
            
            # 서명란 (병합 범위)
            range_sign = f'{c}3:{c}5'
            ws.merge_cells(range_sign)
            self._style_range(ws, range_sign, border=self.BORDER_ALL)

        # 3. 진단 개요
        row = 7
        ws[f'B{row}'] = "■ 진단 개요"
        ws[f'B{row}'].font = Font(name='맑은 고딕', size=12, bold=True)
        row += 1
        
        overview_data = [
            ["진단 기간", datetime.now().strftime("%Y년 %m월 %d일")],
            ["진단 대상", f"총 {len(asset_data)}대 (서버/네트워크 장비)"],
            ["진단 도구", "Z-VulnScan Pro v3.0 (KISA Guide Compliance)"],
            ["수행자", "자체 보안 점검"]
        ]
        
        for title, content in overview_data:
            # 제목 (단일 셀)
            ws[f'B{row}'] = title
            self._style_range(ws, f'B{row}', border=self.BORDER_ALL, 
                              fill=PatternFill(start_color=self.COLOR_HEADER_BG, fill_type='solid'),
                              alignment=Alignment(horizontal='center', vertical='center'))
            
            # 내용 (병합 범위)
            range_content = f'C{row}:E{row}'
            ws.merge_cells(range_content)
            ws[f'C{row}'] = content
            self._style_range(ws, range_content, border=self.BORDER_ALL, 
                              alignment=Alignment(horizontal='left', vertical='center', indent=1))
            row += 1

        # 4. 종합 통계
        row += 2
        ws[f'B{row}'] = "■ 취약점 진단 결과 요약"
        ws[f'B{row}'].font = Font(name='맑은 고딕', size=12, bold=True)
        row += 1
        
        total_vuln = 0
        vuln_high = 0
        vuln_medium = 0
        waived_cnt = 0
        
        for r in scan_data:
            if r[10] == 1: waived_cnt += 1; continue
            if r[6] == "VULNERABLE":
                total_vuln += 1
                if r[5] in ['Critical', 'High']: vuln_high += 1
                else: vuln_medium += 1
        
        deduction = (vuln_high * 5) + (vuln_medium * 2)
        score = max(0, 100 - deduction)
        
        headers = ["진단 대상 수", "취약 항목 수", "예외 처리 수", "종합 점수"]
        values = [f"{len(asset_data)} 대", f"{total_vuln} 건", f"{waived_cnt} 건", f"{score} 점"]
        
        for i, h in enumerate(headers):
            col_idx = 2 + i
            # 헤더
            cell = ws.cell(row=row, column=col_idx)
            cell.value = h
            cell.fill = PatternFill(start_color=self.COLOR_HEADER_BG, fill_type='solid')
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center')
            
            # 값
            val_cell = ws.cell(row=row+1, column=col_idx)
            val_cell.value = values[i]
            val_cell.border = self.BORDER_ALL
            val_cell.alignment = Alignment(horizontal='center')
            val_cell.font = self.FONT_BOLD
            
            ws.column_dimensions[get_column_letter(col_idx)].width = 20

    def _create_detail_sheet(self, wb, data):
        """[Detail] 상세 취약점 목록 (KISA 스타일 + 32k 방어 적용)"""
        ws = wb.create_sheet("📄 Vulnerability Details")
        
        # KISA 스타일 헤더
        headers = ["IP", "Hostname", "OS", "Code", "Vulnerability Name", "Risk", "Status", "Details", "Remediation", "Scan Date"]
        ws.append(headers)
        
        # 헤더 스타일 적용
        for col in range(1, len(headers) + 1):
            cell = ws.cell(row=1, column=col)
            cell.fill = self.HEADER_FILL
            cell.font = self.HEADER_FONT
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = self.BORDER_THIN
        
        # 데이터 입력
        for row_idx, row_data in enumerate(data, 2):
            for col_idx, val in enumerate(row_data, 1):
                
                # [핵심] 32k 글자 수 제한 방어 로직 (Excel Crash 방지)
                cell_text = str(val) if val is not None else "-"
                if len(cell_text) > 32000:
                    cell_text = cell_text[:32000] + "\n...[증적 내용이 너무 길어 엑셀 제한에 의해 잘렸습니다. DB를 확인하세요.]"
                
                cell = ws.cell(row=row_idx, column=col_idx, value=cell_text)
                cell.border = self.BORDER_THIN
                cell.alignment = Alignment(vertical='top', wrap_text=True)
                
                # Risk 컬럼 스타일링 (High/Medium/Low 색상)
                if col_idx == 6 and val in self.RISK_COLORS:
                    icon = self.RISK_ICONS.get(val, '')
                    cell.value = f"{icon} {val}"
                    cell.fill = PatternFill(start_color=self.RISK_COLORS[val], 
                                            end_color=self.RISK_COLORS[val], fill_type='solid')
                    cell.font = Font(bold=True, color='FFFFFF')
                    cell.alignment = Alignment(horizontal='center', vertical='center')
        
        # 열 너비 설정
        widths = [14, 18, 10, 10, 35, 12, 10, 40, 40, 18]
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w
        
        ws.auto_filter.ref = ws.dimensions
        ws.freeze_panes = 'A2'

    def _create_asset_sheet(self, wb, asset_data):
        ws = wb.create_sheet("3.자산목록")
        headers = ["No", "IP 주소", "호스트명", "OS 정보", "MAC 주소"]
        for i, h in enumerate(headers):
            cell = ws.cell(row=1, column=i+1)
            cell.value = h
            cell.fill = PatternFill(start_color=self.COLOR_HEADER_BG, fill_type='solid')
            cell.font = self.FONT_HEADER
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center', vertical='center')
            ws.column_dimensions[get_column_letter(i+1)].width = 20

        for idx, row in enumerate(asset_data, 1):
            vals = [idx, row[0], row[1], row[2], row[3]]
            for c, v in enumerate(vals, 1):
                cell = ws.cell(row=idx+1, column=c)
                cell.value = v
                cell.border = self.BORDER_ALL
                cell.alignment = Alignment(horizontal='center')