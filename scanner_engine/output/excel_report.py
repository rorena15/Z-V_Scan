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
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# 상위 모듈 참조
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.db_connector import DBConnector
from utils.logger import AppLogger
from utils.app_settings import get_report_output_dir
import core.vuln_matcher as Vuln

class ExcelGenerator:
    # --- KISA 스타일 상수 정의 ---
    COLOR_HEADER_BG = 'E7E6E6'   # 헤더 배경 (연한 회색)
    COLOR_BORDER = '000000'      # 테두리 (검정)
    
    # 위험도 색상 코드 (Hex)
    COLOR_CRITICAL = 'FFCCCC' # 상 (연한 빨강)
    COLOR_HIGH = 'FFE6CC'     # 중 (연한 주황)
    COLOR_GOOD = 'E2EFDA'     # 양호 (연한 초록)
    COLOR_WAIVER = 'D9D9D9'   # 예외 (회색)
    COLOR_PARTIAL = 'FFF2CC' # 부분만족 (연한 노랑)
    COLOR_NA = 'F2F2F2'       # 해당없음 (연한 회색)
    COLOR_ERROR = 'D9D9D9'    # 점검불가/접속실패 (진회색)

    # 폰트 정의
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

    # 단순 얇은 테두리 (호환성)
    BORDER_THIN = Border(
        left=Side(style='thin'), right=Side(style='thin'),
        top=Side(style='thin'), bottom=Side(style='thin')
    )

    def __init__(self):
        self.db = DBConnector()
        # [Phase 3: 설정 페이지] 사용자가 지정한 리포트 출력 경로가 있으면 그것을 사용
        self.output_dir = get_report_output_dir()

        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except OSError:
                pass

        # [Fix] 누락되었던 스타일 속성 초기화
        self.HEADER_FILL = PatternFill(start_color=self.COLOR_HEADER_BG, end_color=self.COLOR_HEADER_BG, fill_type='solid')

        self.RISK_COLORS = {
            "Critical": self.COLOR_CRITICAL,
            "High": self.COLOR_HIGH,
            "Medium": "FFFFCC", # 약한 노랑
            "Low": self.COLOR_GOOD,
            "Info": "F2F2F2",
            "Safe": self.COLOR_GOOD
        }

        self.RISK_ICONS = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
            "Info": "⚪",
            "Safe": "✅"
        }

    def clean_text(self, text):
        #엑셀에서 허용하지 않는 특수문자 제거
        if not text:
            return "-"
        text = str(text)
        # 엑셀 허용 문자: 탭(\x09), 줄바꿈(\x0A), 캐리지리턴(\x0D) 제외한
        # 나머지 0x00 ~ 0x1F 사이의 제어 문자를 모두 제거
        return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)

    def _style_range(self, ws, cell_range, border=None, fill=None, font=None, alignment=None):
        """단일 셀('A1')과 범위('A1:B2') 모두 처리하도록 개선"""
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
            
            # KISA 코드 동기화 (안전장치)
            Vuln.VulnMatcher.sync_kisa_code_on_db(self.db.db_path)
            
            scan_data = self._fetch_scan_result()
            asset_data = self._fetch_asset_list()
            
            if not asset_data:
                raise Exception("진단된 자산 데이터가 없습니다.")
            
            self._create_cover_sheet(wb, asset_data, scan_data)
            self._create_detail_sheet(wb, scan_data)
            self._create_asset_sheet(wb, asset_data)
            
            # 기본 Sheet 제거
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
            query = f"""
                SELECT
                    A.ip_addr, A.hostname,
                    R.kisa_code, R.vuln_code, R.vuln_name,
                    R.risk_level, R.status, R.detected_value,
                    R.raw_output, R.remediation, R.waiver_status, R.waiver_reason
                FROM TBL_SCAN_RESULT R
                JOIN TBL_ASSETS A ON R.asset_id = A.asset_id
                WHERE R.vuln_code NOT LIKE 'SYS-%'
                AND {DBConnector.latest_round_condition('R')}
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
            ws[f'B{row}'] = title
            self._style_range(ws, f'B{row}', border=self.BORDER_ALL, 
                              fill=PatternFill(start_color=self.COLOR_HEADER_BG, fill_type='solid'),
                              alignment=Alignment(horizontal='center', vertical='center'))
            
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
        # [버그 수정] "부분만족(PARTIAL)" 항목이 종합점수/요약건수 집계에서 통째로 빠져있던 문제
        partial_cnt = 0
        partial_high = 0
        partial_medium = 0
        waived_cnt = 0

        for r in scan_data:
            if r[10] == 1: waived_cnt += 1; continue
            if r[6] == "VULNERABLE":
                total_vuln += 1
                if r[5] == '상': vuln_high += 1
                else: vuln_medium += 1
            elif r[6] == "PARTIAL":
                partial_cnt += 1
                if r[5] == '상': partial_high += 1
                else: partial_medium += 1

        # 부분만족은 미충족(취약) 대비 절반 가중치로 감점에 반영
        deduction = (vuln_high * 5) + (vuln_medium * 2) + (partial_high * 2.5) + (partial_medium * 1)
        score = max(0, round(100 - deduction))

        headers = ["진단 대상 수", "취약 항목 수", "부분만족 항목 수", "예외 처리 수", "종합 점수"]
        values = [f"{len(asset_data)} 대", f"{total_vuln} 건", f"{partial_cnt} 건", f"{waived_cnt} 건", f"{score} 점"]
        
        for i, h in enumerate(headers):
            col_idx = 2 + i
            cell = ws.cell(row=row, column=col_idx)
            cell.value = h
            cell.fill = PatternFill(start_color=self.COLOR_HEADER_BG, fill_type='solid')
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center')
            
            val_cell = ws.cell(row=row+1, column=col_idx)
            val_cell.value = values[i]
            val_cell.border = self.BORDER_ALL
            val_cell.alignment = Alignment(horizontal='center')
            val_cell.font = self.FONT_BOLD
            
            ws.column_dimensions[get_column_letter(col_idx)].width = 20

    def _create_detail_sheet(self, wb, scan_data):
        """[Detail] 상세 취약점 목록 (KISA 스타일 + 32k 방어 적용)"""
        ws = wb.create_sheet("2.상세점검결과")
        
        # 1. 헤더 설정
        headers = [
            ("A", "No", 5), ("B", "자산 IP", 15), ("C", "호스트명", 20),
            ("D", "진단코드", 12), ("E", "항목명", 30), ("F", "중요도", 10),
            ("G", "진단결과", 10), ("H", "현황(요약)", 30), ("I", "상세 증적 (Evidence)", 60),
            ("J", "조치 방안", 40), ("K", "예외 사유", 20)
        ]
        
        for col, title, width in headers:
            cell = ws[f'{col}1']
            cell.value = title
            cell.fill = self.HEADER_FILL
            cell.font = self.FONT_HEADER
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = self.BORDER_ALL
            ws.column_dimensions[col].width = width
            
        ws.row_dimensions[1].height = 25
        ws.freeze_panes = 'A2'

        # 2. 데이터 입력 루프
        for idx, row in enumerate(scan_data, 1):
            ip, hostname = row[0], row[1]
            kisa_code = row[2] if row[2] else row[3]
            name = row[4]
            risk = row[5]
            status = row[6]
            summary = row[7]
            evidence = row[8]
            remediation = row[9]
            is_waived = row[10]
            waiver_reason = row[11]

            # [핵심] 32k 글자 수 제한 방어 로직
            if evidence and len(str(evidence)) > 32000:
                evidence = str(evidence)[:32000] + "\n...[증적 내용이 너무 길어 엑셀 제한에 의해 잘렸습니다. DB를 확인하세요.]"

            # KISA 상태 한글화 (4단계: 취약/부분만족/양호/해당없음 + 예외/검토필요)
            final_status = "양호"
            if is_waived == 1: final_status = "예외"
            elif status == "VULNERABLE": final_status = "취약"
            elif status == "PARTIAL": final_status = "부분만족"
            elif status == "NA": final_status = "해당없음"
            elif status == "MANUAL": final_status = "검토필요"
            elif status == "ERROR": final_status = "점검불가"
            
            row_vals = [idx, ip, hostname, kisa_code, name, risk, final_status, summary, evidence, remediation, waiver_reason]
            
            r_idx = idx + 1
            for c_idx, val in enumerate(row_vals, 1):
                cell = ws.cell(row=r_idx, column=c_idx)
                cell.value = self.clean_text(val)
                cell.font = self.FONT_NORMAL
                cell.border = self.BORDER_ALL
                cell.alignment = Alignment(vertical='top', wrap_text=True)
                
                # 가운데 정렬
                if c_idx in [1, 2, 4, 6, 7]: 
                    cell.alignment = Alignment(horizontal='center', vertical='top')
                
                # 진단결과(G열) 색상 처리
                if c_idx == 7: 
                    cell.font = self.FONT_BOLD
                    if final_status == "취약": cell.fill = PatternFill(start_color=self.COLOR_CRITICAL, fill_type='solid')
                    elif final_status == "양호": cell.fill = PatternFill(start_color=self.COLOR_GOOD, fill_type='solid')
                    elif final_status == "예외": cell.fill = PatternFill(start_color=self.COLOR_WAIVER, fill_type='solid')
                    elif final_status == "검토필요": cell.fill = PatternFill(start_color=self.COLOR_HIGH, fill_type='solid')
                    elif final_status == "부분만족": cell.fill = PatternFill(start_color=self.COLOR_PARTIAL, fill_type='solid')
                    elif final_status == "해당없음": cell.fill = PatternFill(start_color=self.COLOR_NA, fill_type='solid')
                    elif final_status == "점검불가": cell.fill = PatternFill(start_color=self.COLOR_ERROR, fill_type='solid')

    def _create_asset_sheet(self, wb, asset_data):
        ws = wb.create_sheet("3.자산목록")
        headers = ["No", "IP 주소", "호스트명", "OS 정보", "MAC 주소"]
        for i, h in enumerate(headers):
            cell = ws.cell(row=1, column=i+1)
            cell.value = h
            cell.fill = self.HEADER_FILL
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