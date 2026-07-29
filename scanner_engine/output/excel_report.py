# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[리포트 재설계] 컨설턴트 결과보고서(00. 기준/별첨02~08 xlsm)와 내부 구조를 맞췄다:
카테고리(UNIX/WINDOWS/PC/웹서비스/DBMS)별로 요약통계/보안수준통계 시트 + 호스트
1대당 상세 시트 1개. 컨설턴트는 카테고리마다 파일을 따로 만들지만(별첨02~08),
Z-VulnScan은 파일 하나(통합 워크북) 안에서 시트로만 구분한다(사용자 결정).
관리적/물리적/보안장비/네트워크장비(별첨01/05/06)는 Z-VulnScan이 자동 점검하는
영역이 아니라 이번 재설계 범위에서 제외했다.

점수 산식은 컨설턴트 엑셀(별첨07 PC.xlsm)을 openpyxl(data_only=False)로 직접 열어
실제 수식을 확인해 그대로 옮겼다:
  중요도 값: 상=10, 중=8, 하=6
  결과 값(항목 하나의 감점): 양호=0, 부분만족=중요도값/2, 취약=중요도값, 해당없음은 제외
  보안수준 = (전체점수-취약점수)/전체점수   (전체점수=해당없음 제외 항목의 중요도 값 합계)
매크로가 없는 순수 openpyxl 산출물이라 수식이 아니라 계산된 값을 셀에 직접 쓴다.

서식(색상)은 컨설턴트의 KISA 회색조를 그대로 베끼지 않고, Z-VulnScan 데스크톱 앱과
동일한 브랜드 팔레트(gui/dashboard_widgets.py의 LIGHT_COLORS)를 쓴다 - 리포트만
봐도 Z-VulnScan 산출물임을 알아볼 수 있게 하기 위함(사용자 지시: "서식을 완전히
똑같이 해야할 필요는 없지만 Z-Vuln Scan만의 색으로").
"""
import os
import sys
import sqlite3
import json
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
from output.text_report import RULE_FILES, STATUS_TO_RESULT

# 항목 하나의 "중요도 값" - 컨설턴트 엑셀 수식 그대로(상=10/중=8/하=6)
IMPORTANCE_WEIGHT = {"상": 10, "중": 8, "하": 6}

# 코드 접두어 -> 표시 카테고리명. 순서가 그대로 시트 등장 순서가 된다.
# 관리적/물리적/보안장비/네트워크장비는 자동 점검 대상이 아니라 제외.
CATEGORY_PREFIXES = [
    ("UNIX", ("U-",)),
    ("WINDOWS", ("W-",)),
    ("PC", ("PC-",)),
    ("웹서비스", ("WEB-",)),
    ("DBMS", ("MYSQL-", "POSTGRESQL-")),
]


def _categorize_code(code):
    """kisa_code(없으면 vuln_code) 접두어로 카테고리를 판별한다.
    매칭 안 되면(Discovery 정보 TCP-/UDP-/INFO- 등) None."""
    if not code:
        return None
    for cat_name, prefixes in CATEGORY_PREFIXES:
        if any(code.startswith(p) for p in prefixes):
            return cat_name
    return None


class ExcelGenerator:
    # --- Z-VulnScan 브랜드 팔레트 (gui/dashboard_widgets.py LIGHT_COLORS와 동일 값) ---
    COLOR_HEADER_BG = 'E3ECFE'   # accent_bg - 헤더/구분선 배경
    COLOR_ACCENT = '1F5FE0'      # accent - 제목/강조 텍스트
    COLOR_BORDER = 'D8D8D2'
    COLOR_TEXT = '1A1A1A'

    COLOR_CRITICAL = 'F8C6C6'  # danger_bg - 취약
    COLOR_GOOD = 'C9E9D1'      # success_bg - 양호
    COLOR_PARTIAL = 'F3D27E'   # warning_bg - 부분만족/검토필요
    COLOR_NA = 'E7E7E4'        # muted_bg - 해당없음/점검불가
    COLOR_WAIVER = 'D8D8D2'    # border색 재사용 - 예외

    FONT_TITLE = Font(name='맑은 고딕', size=20, bold=True, color=COLOR_ACCENT)
    FONT_SECTION = Font(name='맑은 고딕', size=12, bold=True, color=COLOR_ACCENT)
    FONT_HEADER = Font(name='맑은 고딕', size=10, bold=True, color=COLOR_TEXT)
    FONT_NORMAL = Font(name='맑은 고딕', size=9)
    FONT_BOLD = Font(name='맑은 고딕', size=9, bold=True)

    BORDER_ALL = Border(
        left=Side(style='thin', color=COLOR_BORDER),
        right=Side(style='thin', color=COLOR_BORDER),
        top=Side(style='thin', color=COLOR_BORDER),
        bottom=Side(style='thin', color=COLOR_BORDER)
    )

    STATUS_FILL = {
        "취약": COLOR_CRITICAL, "양호": COLOR_GOOD, "부분만족": COLOR_PARTIAL,
        "해당없음": COLOR_NA, "예외": COLOR_WAIVER, "검토필요": COLOR_PARTIAL,
        "점검불가": COLOR_NA,
    }

    def __init__(self, evidence_level="full", remediation_level="full"):
        self.db = DBConnector()
        # [라이선스 등급별 리포트 차등] evidence_level: "full"|"vuln_only"
        # remediation_level: "full"|"partial"|"none" - 기존과 동일하게 유지
        self.evidence_level = evidence_level
        self.remediation_level = remediation_level
        self.output_dir = get_report_output_dir()
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except OSError:
                pass

        self.HEADER_FILL = PatternFill(start_color=self.COLOR_HEADER_BG, end_color=self.COLOR_HEADER_BG, fill_type='solid')
        self.rule_lookup = self._load_rule_lookup()
        self._used_sheet_names = set()

    # ------------------------------------------------------------------
    # 공용 유틸 (기존 excel_report.py에서 그대로 유지)
    # ------------------------------------------------------------------
    def clean_text(self, text):
        if not text:
            return "-"
        text = str(text)
        return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)

    def _style_range(self, ws, cell_range, border=None, fill=None, font=None, alignment=None):
        selection = ws[cell_range]
        if not isinstance(selection, (tuple, list)):
            selection = ((selection,),)
        for row in selection:
            for cell in row:
                if border: cell.border = border
                if fill: cell.fill = fill
                if font: cell.font = font
                if alignment: cell.alignment = alignment

    def _unique_sheet_name(self, name):
        """엑셀 시트명 31자 제한 + 중복 방지(호스트명이 같거나 잘려서 겹치는 경우)."""
        name = re.sub(r'[\\/*?:\[\]]', '_', name)[:31]
        base, n = name, 2
        while name in self._used_sheet_names:
            suffix = f"_{n}"
            name = base[:31 - len(suffix)] + suffix
            n += 1
        self._used_sheet_names.add(name)
        return name

    def _final_status(self, status, waived):
        """DB status(+예외처리 여부) -> 화면 표시용 4단계+2 상태 문자열.
        기존 excel_report.py의 매핑을 그대로 유지."""
        if waived == 1: return "예외"
        if status == "VULNERABLE": return "취약"
        if status == "PARTIAL": return "부분만족"
        if status == "NA": return "해당없음"
        if status == "MANUAL": return "검토필요"
        if status == "ERROR": return "점검불가"
        return "양호"

    def _load_rule_lookup(self):
        """{엔진접두어}{code} -> rule dict. output/text_report.py._load_rule_lookup()와
        동일 규칙(RULE_FILES) - database_inspector.py가 DB에 저장하는 vuln_code
        (예: MYSQL-D-01)와 키가 일치해야 한다. 새 파싱 로직을 만들지 않고 그 규칙만
        재사용한다."""
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            # [버그 수정] output/text_report.py의 TextReportGenerator와 동일하게 3단계
            # dirname이 필요하다(__file__ -> output/ -> scanner_engine/ -> 프로젝트 루트).
            # 2단계로 계산하면 scanner_engine/rules를 찾게 되는데 실제 rules/는 그 상위
            # 프로젝트 루트에 있어서 룰 조회가 항상 실패(빈 lookup)하던 버그가 있었다.
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        rules_dir = os.path.join(base_path, 'rules')
        if hasattr(sys, '_MEIPASS') and not os.path.isdir(rules_dir):
            rules_dir = os.path.join(sys._MEIPASS, 'rules')

        lookup = {}
        for filename, prefix in RULE_FILES.items():
            path = os.path.join(rules_dir, filename)
            if not os.path.exists(path):
                continue
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for rule in data:
                    lookup[f"{prefix}{rule['code']}"] = rule
            except Exception as e:
                AppLogger.log_error(f"[ExcelReport] Failed to load {filename}", e)
        return lookup

    def _rule_for(self, code):
        return self.rule_lookup.get(code)

    # ------------------------------------------------------------------
    # 메인 진입점
    # ------------------------------------------------------------------
    def generate(self):
        try:
            wb = Workbook()
            Vuln.VulnMatcher.sync_kisa_code_on_db(self.db.db_path)

            scan_data = self._fetch_scan_result()
            asset_data = self._fetch_asset_assessment_full()

            if not asset_data:
                raise Exception("진단된 자산 데이터가 없습니다.")

            by_category = {cat: [] for cat, _ in CATEGORY_PREFIXES}
            for row in scan_data:
                cat = _categorize_code(row["code"])
                if cat:
                    by_category[cat].append(row)

            self._create_cover_sheet(wb, asset_data, by_category)
            self._create_scope_sheet(wb, asset_data)

            for cat_name, _ in CATEGORY_PREFIXES:
                rows = by_category[cat_name]
                if not rows:
                    continue
                self._create_category_summary_sheet(wb, cat_name, rows)
                self._create_category_security_sheet(wb, cat_name, rows)
                self._create_host_sheets(wb, cat_name, rows)

            round_comparison = self.db.get_round_comparison()
            if round_comparison:
                self._create_diff_sheet(wb, round_comparison)

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

    # ------------------------------------------------------------------
    # DB 조회
    # ------------------------------------------------------------------
    def _fetch_scan_result(self):
        """카테고리/호스트별 시트 구성에 필요한 필드를 딕셔너리 레코드 리스트로 반환한다."""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        try:
            query = f"""
                SELECT
                    A.asset_id, A.ip_addr, A.hostname, A.os_type,
                    A.asset_purpose, A.department, A.owner_name,
                    A.conf_score, A.integ_score, A.avail_score,
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
            cols = [d[0] for d in cursor.description]
            rows = []
            for raw in cursor.fetchall():
                rec = dict(zip(cols, raw))
                rec["code"] = rec["kisa_code"] or rec["vuln_code"]
                rows.append(rec)
            return rows
        except Exception as e:
            AppLogger.log_error("Fetch Scan Result Error", e)
            return []
        finally:
            conn.close()

    def _fetch_asset_assessment_full(self):
        """점검대상 시트용: 자산평가 필드를 포함한 자산 전체 목록(스캔 결과 유무와 무관)."""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT asset_id, ip_addr, hostname, os_type,
                       asset_purpose, department, owner_name,
                       conf_score, integ_score, avail_score
                FROM TBL_ASSETS ORDER BY ip_addr ASC
            """)
            return cursor.fetchall()
        except Exception as e:
            AppLogger.log_error("Fetch Asset Assessment Error", e)
            return []
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 점수 계산 (컨설턴트 엑셀 수식을 파이썬으로 재현)
    # ------------------------------------------------------------------
    def _score_group(self, items):
        """items: [(importance, final_status), ...] 하나의 분류(또는 카테고리) 묶음.
        반환: dict(전체, 점검, 양호, 취약, 부분만족, 해당없음, 전체점수, 취약점수, 보안수준)"""
        counts = {"전체": len(items), "양호": 0, "취약": 0, "부분만족": 0, "해당없음": 0}
        full_score = 0
        vuln_score = 0
        for importance, status in items:
            weight = IMPORTANCE_WEIGHT.get(importance, 8)
            if status == "취약":
                counts["취약"] += 1
                full_score += weight
                vuln_score += weight
            elif status == "부분만족":
                counts["부분만족"] += 1
                full_score += weight
                vuln_score += weight / 2
            elif status == "양호":
                counts["양호"] += 1
                full_score += weight
            else:
                # 해당없음/검토필요/점검불가/예외 - 컨설턴트 수식과 동일하게 점수 계산에서 제외
                counts["해당없음"] += 1
        counts["점검"] = counts["전체"] - counts["해당없음"]
        counts["전체점수"] = full_score
        counts["취약점수"] = vuln_score
        counts["보안수준"] = None if full_score == 0 else (full_score - vuln_score) / full_score
        return counts

    # ------------------------------------------------------------------
    # 시트: 1.종합요약
    # ------------------------------------------------------------------
    def _create_cover_sheet(self, wb, asset_data, by_category):
        ws = wb.active
        ws.title = "1.종합요약"

        ws.merge_cells('B2:I3')
        ws['B2'] = "주요정보통신기반시설 기술적 취약점 분석 평가 결과"
        self._style_range(ws, 'B2:I3', border=self.BORDER_ALL, font=self.FONT_TITLE,
                           alignment=Alignment(horizontal='center', vertical='center'))

        start_col = 11
        col_letter = get_column_letter(start_col)
        range_str = f'{col_letter}2:{col_letter}5'
        ws.merge_cells(range_str)
        ws[f'{col_letter}2'] = "결\n\n재"
        self._style_range(ws, range_str, border=self.BORDER_ALL,
                           fill=self.HEADER_FILL,
                           alignment=Alignment(horizontal='center', vertical='center', wrap_text=True))

        roles = ["담 당", "팀 장", "부서장"]
        for i, role in enumerate(roles):
            c = get_column_letter(start_col + 1 + i)
            ws[f'{c}2'] = role
            self._style_range(ws, f'{c}2', border=self.BORDER_ALL, fill=self.HEADER_FILL,
                               alignment=Alignment(horizontal='center', vertical='center'))
            range_sign = f'{c}3:{c}5'
            ws.merge_cells(range_sign)
            self._style_range(ws, range_sign, border=self.BORDER_ALL)

        row = 7
        ws[f'B{row}'] = "■ 진단 개요"
        ws[f'B{row}'].font = self.FONT_SECTION
        row += 1

        overview_data = [
            ["진단 기간", datetime.now().strftime("%Y년 %m월 %d일")],
            ["진단 대상", f"총 {len(asset_data)}대"],
            ["진단 도구", "Z-VulnScan Pro v3.0 (KISA Guide Compliance)"],
            ["수행자", "자체 보안 점검"]
        ]
        for title, content in overview_data:
            ws[f'B{row}'] = title
            self._style_range(ws, f'B{row}', border=self.BORDER_ALL, fill=self.HEADER_FILL,
                               alignment=Alignment(horizontal='center', vertical='center'))
            range_content = f'C{row}:E{row}'
            ws.merge_cells(range_content)
            ws[f'C{row}'] = content
            self._style_range(ws, range_content, border=self.BORDER_ALL,
                               alignment=Alignment(horizontal='left', vertical='center', indent=1))
            row += 1

        # 카테고리별 보안수준 요약 (기존의 하드코딩 감점식 대신 실제 컨설턴트 산식 사용)
        row += 2
        ws[f'B{row}'] = "■ 카테고리별 보안수준"
        ws[f'B{row}'].font = self.FONT_SECTION
        row += 1

        headers = ["카테고리", "점검항목", "양호", "취약", "부분만족", "해당없음", "보안수준"]
        for i, h in enumerate(headers):
            cell = ws.cell(row=row, column=2 + i)
            cell.value = h
            cell.fill = self.HEADER_FILL
            cell.font = self.FONT_HEADER
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center')
        header_row = row
        row += 1

        for cat_name, _ in CATEGORY_PREFIXES:
            cat_rows = by_category.get(cat_name, [])
            if not cat_rows:
                continue
            items = [(self._rule_for(r["code"]).get("importance", "중") if self._rule_for(r["code"]) else "중",
                      self._final_status(r["status"], r["waiver_status"])) for r in cat_rows]
            stats = self._score_group(items)
            values = [
                cat_name, stats["점검"], stats["양호"], stats["취약"], stats["부분만족"], stats["해당없음"],
                "N/A" if stats["보안수준"] is None else f"{stats['보안수준']*100:.0f}%",
            ]
            for i, v in enumerate(values):
                cell = ws.cell(row=row, column=2 + i)
                cell.value = v
                cell.border = self.BORDER_ALL
                cell.alignment = Alignment(horizontal='center')
                cell.font = self.FONT_BOLD if i == 0 else self.FONT_NORMAL
            row += 1

        for i in range(len(headers)):
            ws.column_dimensions[get_column_letter(2 + i)].width = 16
        ws.row_dimensions[header_row].height = 20

    # ------------------------------------------------------------------
    # 시트: 2.점검대상
    # ------------------------------------------------------------------
    def _create_scope_sheet(self, wb, asset_data):
        ws = wb.create_sheet("2.점검대상")
        headers = [
            ("A", "No", 5), ("B", "IP 주소", 15), ("C", "Hostname", 20), ("D", "OS", 16),
            ("E", "용도", 20), ("F", "부서", 14), ("G", "담당자", 12),
            ("H", "C", 6), ("I", "I", 6), ("J", "A", 6), ("K", "등급", 8),
        ]
        for col, title, width in headers:
            cell = ws[f'{col}1']
            cell.value = title
            cell.fill = self.HEADER_FILL
            cell.font = self.FONT_HEADER
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center', vertical='center')
            ws.column_dimensions[col].width = width
        ws.row_dimensions[1].height = 22
        ws.freeze_panes = 'A2'

        for idx, (asset_id, ip, hostname, os_type, purpose, dept, owner, c, i, a) in enumerate(asset_data, 1):
            grade = DBConnector.compute_asset_grade(c, i, a)
            vals = [idx, ip, hostname or "-", os_type or "-", purpose or "-", dept or "-", owner or "-",
                    c if c is not None else "-", i if i is not None else "-", a if a is not None else "-", grade]
            r_idx = idx + 1
            for c_idx, val in enumerate(vals, 1):
                cell = ws.cell(row=r_idx, column=c_idx)
                cell.value = self.clean_text(val)
                cell.font = self.FONT_NORMAL
                cell.border = self.BORDER_ALL
                cell.alignment = Alignment(horizontal='center', vertical='center')

    # ------------------------------------------------------------------
    # 시트: {카테고리}.요약통계
    # ------------------------------------------------------------------
    def _create_category_summary_sheet(self, wb, cat_name, rows):
        sheet_name = self._unique_sheet_name(f"{cat_name}.요약통계")
        ws = wb.create_sheet(sheet_name)
        headers = [
            ("A", "분류", 14), ("B", "항목코드", 12), ("C", "항목명", 40),
            ("D", "중요도", 8), ("E", "중요도값", 10),
            ("F", "전체", 8), ("G", "점검", 8), ("H", "양호", 8),
            ("I", "취약", 8), ("J", "부분만족", 10), ("K", "해당없음", 10),
        ]
        for col, title, width in headers:
            cell = ws[f'{col}1']
            cell.value = title
            cell.fill = self.HEADER_FILL
            cell.font = self.FONT_HEADER
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center', vertical='center')
            ws.column_dimensions[col].width = width
        ws.row_dimensions[1].height = 22
        ws.freeze_panes = 'A2'

        # 코드별로 묶는다 (여러 호스트가 같은 코드를 가질 수 있음)
        by_code = {}
        order = []
        for r in rows:
            code = r["code"]
            if code not in by_code:
                by_code[code] = []
                order.append(code)
            by_code[code].append(r)

        r_idx = 2
        for code in order:
            code_rows = by_code[code]
            rule = self._rule_for(code)
            name = rule.get("name", code_rows[0]["vuln_name"]) if rule else code_rows[0]["vuln_name"]
            category = rule.get("category", "-") if rule else "-"
            importance = rule.get("importance", "중") if rule else "중"
            items = [(importance, self._final_status(r["status"], r["waiver_status"])) for r in code_rows]
            stats = self._score_group(items)

            vals = [category, code, name, importance, IMPORTANCE_WEIGHT.get(importance, 8),
                    stats["전체"], stats["점검"], stats["양호"], stats["취약"], stats["부분만족"], stats["해당없음"]]
            for c_idx, val in enumerate(vals, 1):
                cell = ws.cell(row=r_idx, column=c_idx)
                cell.value = self.clean_text(val)
                cell.font = self.FONT_NORMAL
                cell.border = self.BORDER_ALL
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=(c_idx == 3))
                if c_idx == 3:
                    cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)
            r_idx += 1

    # ------------------------------------------------------------------
    # 시트: {카테고리}.보안수준통계
    # ------------------------------------------------------------------
    def _create_category_security_sheet(self, wb, cat_name, rows):
        sheet_name = self._unique_sheet_name(f"{cat_name}.보안수준통계")
        ws = wb.create_sheet(sheet_name)
        headers = [
            ("A", "분류", 16), ("B", "전체항목", 10), ("C", "점검항목", 10),
            ("D", "양호", 8), ("E", "취약", 8), ("F", "부분만족", 10), ("G", "해당없음", 10),
            ("H", "전체점수", 10), ("I", "취약점수", 10), ("J", "보안수준", 10),
        ]
        for col, title, width in headers:
            cell = ws[f'{col}1']
            cell.value = title
            cell.fill = self.HEADER_FILL
            cell.font = self.FONT_HEADER
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center', vertical='center')
            ws.column_dimensions[col].width = width
        ws.row_dimensions[1].height = 22

        by_subcat = {}
        order = []
        for r in rows:
            rule = self._rule_for(r["code"])
            subcat = rule.get("category", "기타") if rule else "기타"
            importance = rule.get("importance", "중") if rule else "중"
            if subcat not in by_subcat:
                by_subcat[subcat] = []
                order.append(subcat)
            by_subcat[subcat].append((importance, self._final_status(r["status"], r["waiver_status"])))

        r_idx = 2
        all_items = []
        for subcat in order:
            items = by_subcat[subcat]
            all_items.extend(items)
            stats = self._score_group(items)
            self._write_security_row(ws, r_idx, subcat, stats, bold=False)
            r_idx += 1

        # 전체 합계 행
        total_stats = self._score_group(all_items)
        self._write_security_row(ws, r_idx, "전체", total_stats, bold=True)

    def _write_security_row(self, ws, r_idx, label, stats, bold):
        level_pct = "N/A" if stats["보안수준"] is None else stats["보안수준"]
        vals = [label, stats["전체"], stats["점검"], stats["양호"], stats["취약"],
                stats["부분만족"], stats["해당없음"], stats["전체점수"], stats["취약점수"], level_pct]
        for c_idx, val in enumerate(vals, 1):
            cell = ws.cell(row=r_idx, column=c_idx)
            cell.font = self.FONT_BOLD if bold else self.FONT_NORMAL
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center', vertical='center')
            if c_idx == 10 and isinstance(val, float):
                cell.value = val
                cell.number_format = '0%'
            else:
                cell.value = self.clean_text(val)
        if bold:
            self._style_range(ws, f'A{r_idx}:J{r_idx}', fill=self.HEADER_FILL)

    # ------------------------------------------------------------------
    # 시트: {카테고리}.{호스트} (호스트 1대당 상세 시트)
    # ------------------------------------------------------------------
    def _create_host_sheets(self, wb, cat_name, rows):
        by_asset = {}
        order = []
        for r in rows:
            aid = r["asset_id"]
            if aid not in by_asset:
                by_asset[aid] = []
                order.append(aid)
            by_asset[aid].append(r)

        for aid in order:
            host_rows = by_asset[aid]
            head = host_rows[0]
            host_label = head["hostname"] or head["ip_addr"]
            sheet_name = self._unique_sheet_name(f"{cat_name}.{host_label}")
            ws = wb.create_sheet(sheet_name)
            self._fill_host_sheet(ws, head, host_rows)

    def _fill_host_sheet(self, ws, head, host_rows):
        r = 1
        ws.column_dimensions['A'].width = 14
        ws.column_dimensions['B'].width = 12
        ws.column_dimensions['C'].width = 40
        ws.column_dimensions['D'].width = 10
        ws.column_dimensions['E'].width = 10
        ws.column_dimensions['F'].width = 10
        ws.column_dimensions['G'].width = 12
        ws.column_dimensions['H'].width = 45
        ws.column_dimensions['I'].width = 45

        ws[f'A{r}'] = "▣ 자산 정보"
        ws[f'A{r}'].font = self.FONT_SECTION
        r += 2

        info_pairs = [
            ("Host Name", head["hostname"] or "-", "IP", head["ip_addr"]),
            ("O/S", head["os_type"] or "-", "용도", head["asset_purpose"] or "-"),
            ("부서", head["department"] or "-", "담당자", head["owner_name"] or "-"),
        ]
        for label1, val1, label2, val2 in info_pairs:
            for col, label, val in ((1, label1, val1), (3, label2, val2)):
                lcell = ws.cell(row=r, column=col)
                lcell.value = label
                lcell.fill = self.HEADER_FILL
                lcell.font = self.FONT_HEADER
                lcell.border = self.BORDER_ALL
                lcell.alignment = Alignment(horizontal='center', vertical='center')
                vcell = ws.cell(row=r, column=col + 1)
                vcell.value = self.clean_text(val)
                vcell.border = self.BORDER_ALL
                vcell.font = self.FONT_NORMAL
                vcell.alignment = Alignment(horizontal='left', vertical='center', indent=1)
            r += 1
        r += 1

        c, i, a = head["conf_score"], head["integ_score"], head["avail_score"]
        grade = DBConnector.compute_asset_grade(c, i, a)
        ws[f'A{r}'] = "▣ 자산평가"
        ws[f'A{r}'].font = self.FONT_SECTION
        r += 1
        for col, label in zip((1, 2, 3, 4), ("C", "I", "A", "등급")):
            cell = ws.cell(row=r, column=col)
            cell.value = label
            cell.fill = self.HEADER_FILL
            cell.font = self.FONT_HEADER
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center')
        r += 1
        for col, val in zip((1, 2, 3, 4), (c if c is not None else "-", i if i is not None else "-",
                                            a if a is not None else "-", grade)):
            cell = ws.cell(row=r, column=col)
            cell.value = self.clean_text(val)
            cell.font = self.FONT_BOLD
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center')
        r += 2

        # 영역별 점검 결과 (이 호스트만)
        ws[f'A{r}'] = "▣ 영역별 점검 결과"
        ws[f'A{r}'].font = self.FONT_SECTION
        r += 1
        sec_headers = ["분류", "전체", "점검", "양호", "취약", "부분만족", "해당없음", "전체점수", "취약점수", "보안수준"]
        for col, h in enumerate(sec_headers, 1):
            cell = ws.cell(row=r, column=col)
            cell.value = h
            cell.fill = self.HEADER_FILL
            cell.font = self.FONT_HEADER
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center')
        r += 1

        by_subcat = {}
        order = []
        detail_rows = []
        for row in host_rows:
            rule = self._rule_for(row["code"])
            subcat = rule.get("category", "기타") if rule else "기타"
            importance = rule.get("importance", "중") if rule else "중"
            name = rule.get("name", row["vuln_name"]) if rule else row["vuln_name"]
            remediation = rule.get("remediation", row["remediation"]) if rule else row["remediation"]
            status = self._final_status(row["status"], row["waiver_status"])
            if subcat not in by_subcat:
                by_subcat[subcat] = []
                order.append(subcat)
            by_subcat[subcat].append((importance, status))
            detail_rows.append((subcat, row["code"], name, importance, status, row, remediation))

        all_items = []
        for subcat in order:
            items = by_subcat[subcat]
            all_items.extend(items)
            stats = self._score_group(items)
            self._write_security_row(ws, r, subcat, stats, bold=False)
            r += 1
        total_stats = self._score_group(all_items)
        self._write_security_row(ws, r, "전체", total_stats, bold=True)
        r += 3

        # 상세 점검 현황
        ws[f'A{r}'] = "▣ 상세 점검 현황"
        ws[f'A{r}'].font = self.FONT_SECTION
        r += 1
        detail_headers = ["분류", "코드", "항목명", "중요도", "중요도값", "결과값", "점검결과", "현황(증적)", "조치방안"]
        for col, h in enumerate(detail_headers, 1):
            cell = ws.cell(row=r, column=col)
            cell.value = h
            cell.fill = self.HEADER_FILL
            cell.font = self.FONT_HEADER
            cell.border = self.BORDER_ALL
            cell.alignment = Alignment(horizontal='center', vertical='center')
        ws.row_dimensions[r].height = 24
        r += 1

        for subcat, code, name, importance, status, row, remediation in detail_rows:
            weight = IMPORTANCE_WEIGHT.get(importance, 8)
            if status == "취약":
                item_score = weight
            elif status == "부분만족":
                item_score = weight / 2
            elif status == "양호":
                item_score = 0
            else:
                item_score = "-"

            evidence = row["raw_output"] or row["detected_value"]
            if evidence and len(str(evidence)) > 32000:
                evidence = str(evidence)[:32000] + "\n...[증적 내용이 너무 길어 잘렸습니다. DB를 확인하세요.]"
            if self.evidence_level == "vuln_only" and status not in ("취약", "부분만족"):
                evidence = "(상세 증적은 Professional 이상 등급에서 제공됩니다)"

            if self.remediation_level == "none":
                remediation = "(조치 방안은 Professional 이상 등급에서 제공됩니다)"
            elif self.remediation_level == "partial" and row["risk_level"] not in ("Critical", "High"):
                remediation = "(중요도 상/중 항목만 제공됩니다. 전체 제공은 Enterprise 등급)"

            vals = [subcat, code, name, importance, weight, item_score, status, evidence, remediation]
            for c_idx, val in enumerate(vals, 1):
                cell = ws.cell(row=r, column=c_idx)
                cell.value = self.clean_text(val)
                cell.font = self.FONT_NORMAL
                cell.border = self.BORDER_ALL
                cell.alignment = Alignment(vertical='top', wrap_text=True)
                if c_idx in (1, 2, 4, 5, 6, 7):
                    cell.alignment = Alignment(horizontal='center', vertical='top')
                if c_idx == 7:
                    cell.font = self.FONT_BOLD
                    fill = self.STATUS_FILL.get(status)
                    if fill:
                        cell.fill = PatternFill(start_color=fill, end_color=fill, fill_type='solid')
            r += 1

    # ------------------------------------------------------------------
    # 시트: 4.회차비교 (기존 로직 그대로 유지 - 카테고리 재구성과 무관)
    # ------------------------------------------------------------------
    def _create_diff_sheet(self, wb, round_comparison):
        """[Phase 5: Diff 리포트] 자산별 직전 회차 대비 점수 변화(개선율)를 보여준다.
        2회 이상 스캔된 자산이 하나도 없으면 generate()에서 아예 호출되지 않는다."""
        ws = wb.create_sheet("4.회차비교(개선율)")
        headers = [
            ("A", "IP 주소", 15), ("B", "호스트명", 20),
            ("C", "직전 회차 점수", 14), ("D", "최신 회차 점수", 14), ("E", "변화", 10),
            ("F", "직전 취약 건수", 14), ("G", "최신 취약 건수", 14),
            ("H", "직전 부분만족 건수", 16), ("I", "최신 부분만족 건수", 16),
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

        for idx, row in enumerate(round_comparison, 1):
            improvement = row["improvement"]
            vals = [
                row["ip"], row["hostname"], row["prev_score"], row["current_score"],
                ("+" if improvement > 0 else "") + str(improvement),
                row["prev_vuln_total"], row["current_vuln_total"],
                row["prev_partial_total"], row["current_partial_total"],
            ]
            r_idx = idx + 1
            for c_idx, val in enumerate(vals, 1):
                cell = ws.cell(row=r_idx, column=c_idx)
                cell.value = self.clean_text(val)
                cell.font = self.FONT_NORMAL
                cell.border = self.BORDER_ALL
                cell.alignment = Alignment(horizontal='center', vertical='center')
                if c_idx == 5:
                    cell.font = self.FONT_BOLD
                    if improvement > 0:
                        cell.fill = PatternFill(start_color=self.COLOR_GOOD, fill_type='solid')
                    elif improvement < 0:
                        cell.fill = PatternFill(start_color=self.COLOR_CRITICAL, fill_type='solid')
