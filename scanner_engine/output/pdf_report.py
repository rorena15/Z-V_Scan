# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import os
import re
import sys
import sqlite3
import html
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph,
    Spacer, PageBreak
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend

# 상위 모듈 참조
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.os_utils import OSUtils
from utils.oui_lookup import OUILookup
from utils.db_connector import DBConnector
from utils.app_settings import get_report_output_dir

class PDFGenerator:
    # 색상 팔레트
    PRIMARY_BLUE = colors.HexColor('#0066CC')
    DARK_BLUE = colors.HexColor('#003D7A')
    LIGHT_BLUE = colors.HexColor('#E6F2FF')

    RISK_COLORS = {
        "Critical": colors.HexColor('#DC3545'),
        "High": colors.HexColor('#FD7E14'),
        "Medium": colors.HexColor('#FFC107'),
        "Low": colors.HexColor('#28A745'),
        "Info": colors.HexColor('#6C757D'),
        "Safe": colors.HexColor('#20C997')
    }
    # Paragraph <font color='..'> 마크업은 HexColor 객체가 아니라 문자열이 필요해서
    # RISK_COLORS와 별개로 문자열 버전을 둔다(값은 동일).
    # [버그 수정 - 2026-09] risk_level 실제 저장값이 룰 카테고리마다 다르다 - Windows/
    # Linux 계열은 worker.py가 영문 5단계(Critical/High/Medium/Low/Info)로 변환해
    # 저장하지만, DBMS/PC 계열은 KISA 원본 중요도(상/중/하)를 그대로 저장한다(실제
    # DB 조회로 확인함). 원래 RISK_ICONS/RISK_COLORS는 영문 키만 있어서 상/중/하
    # 행에서는 애초에 매칭이 안 돼 색(이모지)이 전혀 안 붙었다 - 두 표기 다 매핑.
    RISK_HEX = {
        "Critical": "#DC3545", "High": "#FD7E14", "Medium": "#FFC107",
        "Low": "#28A745", "Info": "#6C757D", "Safe": "#20C997",
        "상": "#DC3545", "중": "#FFC107", "하": "#28A745",
    }

    # [PDF 개선 - 2026-09] RISK_ICONS(이모지)는 실제 렌더링 버그였다 - 아래 __init__에서
    # 등록하는 한글 TTF(NanumGothic/맑은 고딕)는 컬러 이모지 글립이 없는 일반 한글용
    # 폰트라 🔴🟠🟡🟢⚪✅는 깨진 네모(.notdef)로 나온다(reportlab은 이모지 폴백 합성을
    # 아예 안 함). 이모지 대신 위 RISK_COLORS를 그대로 텍스트 색으로 쓰는
    # "<font color='#..'><b>Critical</b></font>" 방식으로 교체 - 별도 글립 의존이
    # 없어 항상 안전하게 렌더링된다.

    # [PDF 개선 - 2026-09] 표지 요약 도넛차트용 - Excel 리포트(excel_report.py)가 쓰는
    # Z-VulnScan 브랜드 팔레트(gui/dashboard_widgets.py STATUS_STYLE의 *_text 색상)와
    # 맞춰서 포맷 간 톤을 통일한다. PDF는 STD 등급용 "간결한 요약 보고서"라는 원래
    # 설계 의도를 지켜야 하므로(사용자 확인) Excel처럼 카테고리/호스트별 차트를
    # 여러 개 넣지 않고, 표지에 전체 현황 도넛차트 1개만 추가한다.
    STATUS_CHART_COLORS = {
        "VULNERABLE": colors.HexColor('#C0271F'),
        "PARTIAL": colors.HexColor('#8A6A00'),
        "SAFE": colors.HexColor('#1B8A46'),
        "MANUAL": colors.HexColor('#5B6675'),
        "NA": colors.HexColor('#8B94A3'),
    }
    STATUS_CHART_LABELS = {
        "VULNERABLE": "취약", "PARTIAL": "부분만족", "SAFE": "양호",
        "MANUAL": "검토필요", "NA": "해당없음",
    }

    def __init__(self, remediation_level="full", report_title=None, company_name=None, custom_filename=None,
                 asset_ids=None, codes=None):
        self.db = DBConnector() # DB 커넥터 재사용
        # [라이선스 등급별 리포트 차등] "full"(전체) | "partial"(중요도 상/중만) | "none"(미제공)
        # 기본값은 항상 "full"이라, 호출부에서 값을 넘기지 않으면 지금까지와 동일하게 동작한다.
        # (PDF는 원래 공간 제약상 raw_output 전체를 싣지 않으므로 evidence_level 구분은 없음)
        self.remediation_level = remediation_level
        # [리포트 탭 - 자산별/항목별 선택, 2026-09] None(기본값)이면 지금까지처럼
        # 전체 자산/전체 항목을 담는다 - 하위호환. 값을 넘기면 그 asset_id/코드만
        # 리포트에 포함한다.
        self.asset_ids = list(asset_ids) if asset_ids else None
        self.codes = list(codes) if codes else None
        # [리포트 탭 - 커스터마이징] 표지 제목/브랜딩 문구/저장 파일명을 비워두면
        # 지금까지와 동일한 기본값을 그대로 쓴다(하위 호환).
        self.report_title = (report_title or "").strip() or "주요정보통신기반시설 취약점 분석 요약"
        self.company_name = (company_name or "").strip()
        # [Phase 3: 설정 페이지] 사용자가 지정한 리포트 출력 경로가 있으면 그것을 사용
        self.output_dir = get_report_output_dir()

        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except OSError:
                pass

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_custom = self._sanitize_filename((custom_filename or "").strip())
        base_name = f"{safe_custom}_{timestamp}" if safe_custom else f"ZVulnScan_Report_{timestamp}"
        self.filename = os.path.join(self.output_dir, f"{base_name}.pdf")
        
        # 폰트 설정 (한글 깨짐 방지)
        self.font_path = OSUtils.get_font_path("NanumGothic.ttf")
        self.font_name = "Helvetica"
        self.bold_font = "Helvetica-Bold"
        
        try:
            if os.path.exists(self.font_path):
                pdfmetrics.registerFont(TTFont("CustomFont", self.font_path))
                self.font_name = "CustomFont"
                self.bold_font = "CustomFont"
            elif OSUtils.is_windows() and os.path.exists("C:/Windows/Fonts/malgun.ttf"):
                pdfmetrics.registerFont(TTFont("MalgunGothic", "C:/Windows/Fonts/malgun.ttf"))
                self.font_name = "MalgunGothic"
                self.bold_font = "MalgunGothic"
        except: 
            pass

    @staticmethod
    def _sanitize_filename(name):
        """저장 파일명으로 위험한 문자(경로 구분자 등)를 제거. 빈 문자열이면 빈 문자열
        그대로 반환(호출부가 기본 파일명으로 폴백하는 신호로 씀)."""
        if not name:
            return ""
        return re.sub(r'[\\/*?:"<>|]', '_', name)[:80]

    def _truncate(self, text, limit):
        if not text: return "-"
        text = str(text)
        return text[:limit] + "..." if len(text) > limit else text

    def _header_footer(self, canvas, doc):
        canvas.saveState()
        width, height = A4
        
        # 상단 바
        canvas.setFillColor(self.DARK_BLUE)
        canvas.rect(0, height - 60, width, 60, fill=1, stroke=0)
        
        # 타이틀
        canvas.setFillColor(colors.white)
        canvas.setFont(self.bold_font, 18)
        canvas.drawString(40, height - 35, "KISA Compliance Security Report") # 타이틀 변경
        
        # 날짜
        canvas.setFont(self.font_name, 9)
        canvas.drawString(40, height - 50, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 하단 푸터
        canvas.setFillColor(colors.grey)
        canvas.setFont(self.font_name, 8)
        canvas.drawString(40, 25, "Confidential - Z-VulnScan Pro v3.0")
        canvas.drawRightString(width - 40, 25, f"Page {doc.page}")
        
        canvas.restoreState()

    def _create_kpi_box(self, label, value, color):
        data = [[Paragraph(f"<b>{label}</b>", 
                          ParagraphStyle(name='kpi', fontName=self.font_name, fontSize=10, textColor=colors.HexColor('#666666')))],
                [Paragraph(f"<font size=24 color='{self.DARK_BLUE}'><b>{value}</b></font>", 
                          ParagraphStyle(name='kpi_val', fontName=self.bold_font, alignment=1))]]
        
        table = Table(data, colWidths=[120], rowHeights=[20, 40])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), color),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOX', (0,0), (-1,-1), 2, self.PRIMARY_BLUE),
        ]))
        return table

    def _build_status_pie(self, status_dist):
        """[PDF 개선 - 2026-09] 표지용 전체 판정 분포 도넛(파이)차트 1개.
        STD 등급 요약 보고서라는 원래 의도를 지키기 위해 Excel처럼 카테고리/호스트별로
        여러 개 넣지 않고 표지 한 곳에만 둔다. 0건인 판정은 조각 자체를 빼서
        범례가 실제 존재하는 항목만 보이게 한다."""
        order = ["VULNERABLE", "PARTIAL", "SAFE", "MANUAL", "NA"]
        entries = [(s, status_dist.get(s, 0)) for s in order if status_dist.get(s, 0) > 0]
        if not entries:
            return None

        drawing = Drawing(420, 150)

        pie = Pie()
        pie.x, pie.y = 40, 10
        pie.width = pie.height = 130
        pie.innerRadiusFraction = 0.55  # 대시보드 도넛차트와 톤 맞춤
        pie.data = [cnt for _, cnt in entries]
        pie.labels = None
        pie.simpleLabels = False
        pie.sideLabels = False
        for i, (status, _) in enumerate(entries):
            pie.slices[i].fillColor = self.STATUS_CHART_COLORS.get(status, colors.HexColor('#999999'))
            pie.slices[i].strokeColor = colors.white
            pie.slices[i].strokeWidth = 1
        drawing.add(pie)

        legend = Legend()
        legend.x, legend.y = 220, 110
        legend.dy = 10
        legend.dx = 10
        legend.fontName = self.font_name
        legend.fontSize = 9
        legend.alignment = 'left'
        total = sum(cnt for _, cnt in entries)
        legend.colorNamePairs = [
            (self.STATUS_CHART_COLORS.get(status, colors.HexColor('#999999')),
             f"{self.STATUS_CHART_LABELS.get(status, status)}  {cnt}건 ({cnt*100//total}%)")
            for status, cnt in entries
        ]
        drawing.add(legend)
        return drawing

    def generate(self):
        doc = SimpleDocTemplate(
            self.filename, pagesize=A4, 
            rightMargin=40, leftMargin=40, topMargin=80, bottomMargin=60
        )
        elements = []
        styles = getSampleStyleSheet()
        
        # 스타일 정의
        title_style = ParagraphStyle(
            name='CustomTitle', parent=styles['Heading1'],
            fontName=self.bold_font, fontSize=20, textColor=self.DARK_BLUE, spaceAfter=12
        )
        cell_style = ParagraphStyle(
            name='CellStyle', parent=styles['Normal'],
            fontName=self.font_name, fontSize=8, leading=10
        )

        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()

        # [리포트 탭 - 자산별/항목별 선택] asset_ids/codes가 None이면 조건절 자체를
        # 안 붙여 지금까지와 동일하게 전체를 대상으로 한다(하위호환).
        asset_filter_sql = ""
        asset_filter_params = []
        if self.asset_ids:
            placeholders = ",".join("?" * len(self.asset_ids))
            asset_filter_sql = f" AND asset_id IN ({placeholders})"
            asset_filter_params = list(self.asset_ids)

        code_filter_sql = ""
        code_filter_params = []
        if self.codes:
            placeholders = ",".join("?" * len(self.codes))
            code_filter_sql = (
                " AND (CASE WHEN kisa_code IS NOT NULL AND kisa_code != '' "
                f"THEN kisa_code ELSE vuln_code END) IN ({placeholders})"
            )
            code_filter_params = list(self.codes)

        try:
            # 자산 조회
            assets_sql = "SELECT asset_id, ip_addr, os_type, hostname, mac_addr, description FROM TBL_ASSETS"
            if self.asset_ids:
                placeholders = ",".join("?" * len(self.asset_ids))
                assets_sql += f" WHERE asset_id IN ({placeholders})"
            assets_sql += " ORDER BY ip_addr ASC"
            cursor.execute(assets_sql, asset_filter_params if self.asset_ids else [])
            all_assets = cursor.fetchall()

            if not all_assets:
                raise Exception("No assets found.")

            # [효율성 개선] 예전엔 자산마다 따로 쿼리해서(N+1) 자산 수가 많을수록
            # DB 왕복이 그만큼 늘었다 - excel_report.py의 _fetch_scan_result()처럼
            # 전체 자산분을 한 번에 가져와 asset_id로 파이썬에서 그룹핑한다.
            # [버그 수정] WHERE 절이 SYS-%만 제외해서, get_all_latest_findings()와
            # 달리 TCP-xx/UDP-xx(포트스캔) · CONN-xx(접속실패 메타행) 같은 비-진단성
            # 행이 진단 결과처럼 섞여 나왔다 - 동일하게 제외한다.
            cursor.execute(f"""
                SELECT
                    asset_id,
                    CASE WHEN kisa_code IS NOT NULL AND kisa_code != '' THEN kisa_code ELSE vuln_code END as code_display,
                    vuln_name, risk_level, status, detected_value, remediation
                FROM TBL_SCAN_RESULT R
                WHERE waiver_status = 0
                AND vuln_code NOT LIKE 'SYS-%' AND vuln_code NOT LIKE 'CONN-%'
                AND vuln_code NOT LIKE 'TCP-%' AND vuln_code NOT LIKE 'UDP-%'
                AND {DBConnector.latest_round_condition('R')}
                {asset_filter_sql}{code_filter_sql}
                ORDER BY asset_id ASC,
                    CASE risk_level
                        WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                        WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4
                        ELSE 5 END ASC
            """, asset_filter_params + code_filter_params)
            findings_by_asset = {}
            for row in cursor.fetchall():
                findings_by_asset.setdefault(row[0], []).append(row[1:])

            # 통계 조회 (예외처리 제외, 최신 회차만 집계)
            # [버그 수정] status='VULNERABLE'만 집계해 "부분만족(PARTIAL)" 항목이 통째로 빠지던 문제
            cursor.execute(f"""
                SELECT status, risk_level, COUNT(*) FROM TBL_SCAN_RESULT R
                WHERE waiver_status=0 AND status IN ('VULNERABLE', 'PARTIAL')
                AND {DBConnector.latest_round_condition('R')}
                {asset_filter_sql}{code_filter_sql}
                GROUP BY status, risk_level
            """, asset_filter_params + code_filter_params)
            vuln_risk_stats = {}
            partial_risk_stats = {}
            for status, risk, cnt in cursor.fetchall():
                (vuln_risk_stats if status == 'VULNERABLE' else partial_risk_stats)[risk] = cnt

            total_vulns = sum(vuln_risk_stats.values())
            total_partial = sum(partial_risk_stats.values())
            critical_high = vuln_risk_stats.get('Critical', 0) + vuln_risk_stats.get('High', 0)

            # [PDF 개선 - 2026-09] 표지 도넛차트용 전체 판정 분포(SAFE/MANUAL/NA 포함).
            # 위 vuln_risk_stats/partial_risk_stats는 위험도별 집계라 차트에 바로 못
            # 쓰고, 판정(status) 기준 전체 건수가 따로 필요하다.
            cursor.execute(f"""
                SELECT status, COUNT(*) FROM TBL_SCAN_RESULT R
                WHERE waiver_status=0
                AND vuln_code NOT LIKE 'SYS-%' AND vuln_code NOT LIKE 'CONN-%'
                AND vuln_code NOT LIKE 'TCP-%' AND vuln_code NOT LIKE 'UDP-%'
                AND {DBConnector.latest_round_condition('R')}
                {asset_filter_sql}{code_filter_sql}
                GROUP BY status
            """, asset_filter_params + code_filter_params)
            status_dist = dict(cursor.fetchall())

            # === 1. Executive Summary ===
            elements.append(Spacer(1, 1*cm))
            elements.append(Paragraph(f"<b>{html.escape(self.report_title)}</b>",
                                   ParagraphStyle(name='cover', fontName=self.bold_font, fontSize=24,
                                                textColor=self.DARK_BLUE, alignment=1)))
            # [리포트 탭 - 커스터마이징] 회사명/브랜딩 문구 - 지정 안 하면 아예 표시 안 함
            if self.company_name:
                elements.append(Spacer(1, 0.3*cm))
                elements.append(Paragraph(html.escape(self.company_name),
                                       ParagraphStyle(name='cover_company', fontName=self.font_name, fontSize=13,
                                                    textColor=colors.HexColor('#555555'), alignment=1)))
            elements.append(Spacer(1, 1.5*cm))

            # KPI
            kpi_data = [[
                self._create_kpi_box("점검 자산 수", len(all_assets), colors.HexColor('#E8F4F8')),
                self._create_kpi_box("발견 취약점", total_vulns, colors.HexColor('#FFF4E6')),
                self._create_kpi_box("부분만족", total_partial, colors.HexColor('#FFF9E0')),
                self._create_kpi_box("조치 필요(상/중)", critical_high, colors.HexColor('#FFE5E5'))
            ]]
            elements.append(Table(kpi_data, colWidths=[110, 110, 110, 110], style=[('ALIGN',(0,0),(-1,-1),'CENTER')]))

            status_pie = self._build_status_pie(status_dist)
            if status_pie:
                elements.append(Spacer(1, 0.8*cm))
                elements.append(status_pie)

            elements.append(PageBreak())

            # === 2. 상세 리포트 ===
            for asset in all_assets:
                asset_id, ip, os_type, hostname, _, _ = asset

                elements.append(Paragraph(f"자산 상세 분석: {ip} ({hostname})", title_style))
                elements.append(Spacer(1, 0.3*cm))

                # PDF에서는 공간 제약상 'raw_output' 전체를 출력하지 않고 'detected_value(요약)'를 출력함
                # (KISA Code/제외 조건/정렬은 위에서 미리 한 번에 조회해둔 findings_by_asset 사용)
                rows = findings_by_asset.get(asset_id, [])

                # 테이블 헤더 (양호/취약/경고를 명확히 구분하는 판정 컬럼 추가)
                table_data = [['Code', '점검 항목', '판정', '위험도', '현황 요약', '조치 방안']]

                status_label = {"VULNERABLE": "취약", "SAFE": "양호", "WARNING": "주의", "MANUAL": "검토필요", "PARTIAL": "부분만족", "NA": "해당없음", "ERROR": "점검불가"}

                for r in rows:
                    code, name, risk, status, detail, rem = r

                    # [라이선스 등급별 리포트 차등]
                    if self.remediation_level == "none":
                        rem = "(Professional 이상 등급에서 제공)"
                    elif self.remediation_level == "partial" and risk not in ("Critical", "High"):
                        rem = "(상/중 항목만 제공, 전체는 Enterprise)"

                    # 텍스트 길이 제한 (PDF 깨짐 방지)
                    name = self._truncate(name, 40)
                    detail = self._truncate(detail, 80) # 요약본만 표시
                    rem = self._truncate(rem, 60)

                    risk_hex = self.RISK_HEX.get(risk, '#666666')
                    risk_cell = Paragraph(
                        f"<font color='{risk_hex}'><b>{html.escape(risk or '-')}</b></font>", cell_style
                    )

                    table_data.append([
                        code,
                        Paragraph(html.escape(name), cell_style),
                        status_label.get(status, status or "-"),
                        risk_cell,
                        Paragraph(html.escape(detail), cell_style),
                        Paragraph(html.escape(rem), cell_style)
                    ])

                if not rows:
                    table_data.append(["-", "취약점 없음 (안전)", "-", "-", "-", "-"])

                t = Table(table_data, colWidths=[45, 100, 45, 55, 130, 95], repeatRows=1)
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), self.DARK_BLUE),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTNAME', (0,0), (-1,-1), self.font_name),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                    ('ALIGN', (0,0), (-1,0), 'CENTER'),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ]))
                
                # 배경색 (홀짝)
                for i in range(1, len(table_data)):
                    if i % 2 == 0:
                        t.setStyle(TableStyle([('BACKGROUND', (0,i), (-1,i), colors.HexColor('#F9F9F9'))]))

                elements.append(t)
                elements.append(PageBreak())

        except Exception as e:
            # 에러 발생 시 빈 PDF라도 생성하여 툴 멈춤 방지
            elements.append(Paragraph(f"Report Generation Error: {str(e)}", title_style))
            
        finally:
            conn.close()

        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        return self.filename