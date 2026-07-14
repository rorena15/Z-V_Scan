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

# 상위 모듈 참조
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.os_utils import OSUtils
from utils.oui_lookup import OUILookup
from utils.db_connector import DBConnector

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
    
    RISK_ICONS = {
        "Critical": "🔴", "High": "🟠", "Medium": "🟡",
        "Low": "🟢", "Info": "⚪", "Safe": "✅"
    }

    def __init__(self):
        self.db = DBConnector() # DB 커넥터 재사용
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
                
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = os.path.join(self.output_dir, f"ZVulnScan_Report_{timestamp}.pdf")
        
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

        try:
            # 자산 조회
            cursor.execute("SELECT asset_id, ip_addr, os_type, hostname, mac_addr, memo FROM TBL_ASSETS ORDER BY ip_addr ASC")
            all_assets = cursor.fetchall()
            
            if not all_assets:
                raise Exception("No assets found.")

            # 통계 조회 (예외처리 제외, 실제 취약 판정 건만 집계)
            cursor.execute("""
                SELECT risk_level, COUNT(*) FROM TBL_SCAN_RESULT
                WHERE waiver_status=0 AND status='VULNERABLE'
                GROUP BY risk_level
            """)
            risk_stats = dict(cursor.fetchall())
            
            total_vulns = sum(risk_stats.values())
            critical_high = risk_stats.get('Critical', 0) + risk_stats.get('High', 0)

            # === 1. Executive Summary ===
            elements.append(Spacer(1, 1*cm))
            elements.append(Paragraph("<b>주요정보통신기반시설 취약점 분석 요약</b>", 
                                   ParagraphStyle(name='cover', fontName=self.bold_font, fontSize=24, 
                                                textColor=self.DARK_BLUE, alignment=1)))
            elements.append(Spacer(1, 1.5*cm))
            
            # KPI
            kpi_data = [[
                self._create_kpi_box("점검 자산 수", len(all_assets), colors.HexColor('#E8F4F8')),
                self._create_kpi_box("발견 취약점", total_vulns, colors.HexColor('#FFF4E6')),
                self._create_kpi_box("조치 필요(상/중)", critical_high, colors.HexColor('#FFE5E5'))
            ]]
            elements.append(Table(kpi_data, colWidths=[140, 140, 140], style=[('ALIGN',(0,0),(-1,-1),'CENTER')]))
            elements.append(PageBreak())

            # === 2. 상세 리포트 ===
            for asset in all_assets:
                asset_id, ip, os_type, hostname, _, _ = asset
                
                elements.append(Paragraph(f"🔍 자산 상세 분석: {ip} ({hostname})", title_style))
                elements.append(Spacer(1, 0.3*cm))

                # [수정된 SQL Query] KISA Code와 증적 로직 반영
                # PDF에서는 공간 제약상 'raw_output' 전체를 출력하지 않고 'detected_value(요약)'를 출력함
                # 하지만 vuln_code 대신 kisa_code를 우선 표시하도록 COALESCE 사용
                sql = """
                    SELECT 
                        CASE WHEN kisa_code IS NOT NULL AND kisa_code != '' THEN kisa_code ELSE vuln_code END as code_display,
                        vuln_name, risk_level, status, detected_value, remediation
                    FROM TBL_SCAN_RESULT
                    WHERE asset_id = ? AND waiver_status = 0 AND vuln_code NOT LIKE 'SYS-%'
                    ORDER BY
                        CASE risk_level
                            WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 
                            WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 
                            ELSE 5 END ASC
                """
                cursor.execute(sql, (asset_id,))
                rows = cursor.fetchall()

                # 테이블 헤더 (양호/취약/경고를 명확히 구분하는 판정 컬럼 추가)
                table_data = [['Code', '점검 항목', '판정', '위험도', '현황 요약', '조치 방안']]

                status_label = {"VULNERABLE": "취약", "SAFE": "양호", "WARNING": "주의", "MANUAL": "검토필요", "PARTIAL": "부분만족", "NA": "해당없음", "ERROR": "점검불가"}

                for r in rows:
                    code, name, risk, status, detail, rem = r

                    # 텍스트 길이 제한 (PDF 깨짐 방지)
                    name = self._truncate(name, 40)
                    detail = self._truncate(detail, 80) # 요약본만 표시
                    rem = self._truncate(rem, 60)

                    risk_icon = self.RISK_ICONS.get(risk, '')

                    table_data.append([
                        code,
                        Paragraph(html.escape(name), cell_style),
                        status_label.get(status, status or "-"),
                        f"{risk_icon} {risk}",
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