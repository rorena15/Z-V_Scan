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
    Spacer, PageBreak, KeepTogether, Image
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

from utils.os_utils import OSUtils
from utils.oui_lookup import OUILookup

class PDFGenerator:
    # 색상 팔레트 (Excel과 동일)
    PRIMARY_BLUE = colors.HexColor('#0066CC')
    DARK_BLUE = colors.HexColor('#003D7A')
    LIGHT_BLUE = colors.HexColor('#E6F2FF')
    ACCENT_ORANGE = colors.HexColor('#FF6B35')
    
    RISK_COLORS = {
        "Critical": colors.HexColor('#DC3545'),
        "High": colors.HexColor('#FD7E14'),
        "Medium": colors.HexColor('#FFC107'),
        "Low": colors.HexColor('#28A745'),
        "Info": colors.HexColor('#6C757D'),
        "Safe": colors.HexColor('#20C997')
    }
    
    RISK_ICONS = {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🟢",
        "Info": "⚪",
        "Safe": "✅"
    }

    def __init__(self):
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
            
        self.output_dir = os.path.join(base_path, 'reports')
        self.db_path = os.path.join(base_path, 'zvuln_scan.db')
        
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except OSError:
                pass
                
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = os.path.join(self.output_dir, f"ZVulnScan_Report_{timestamp}.pdf")
        
        # 폰트 설정
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
        """모던한 헤더/푸터 디자인"""
        canvas.saveState()
        width, height = A4
        
        # 상단 블루 바
        canvas.setFillColor(self.DARK_BLUE)
        canvas.rect(0, height - 60, width, 60, fill=1, stroke=0)
        
        # 타이틀
        canvas.setFillColor(colors.white)
        canvas.setFont(self.bold_font, 18)
        canvas.drawString(40, height - 35, "Z-VulnScan Security Report")
        
        # 날짜
        canvas.setFont(self.font_name, 9)
        canvas.drawString(40, height - 50, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 하단 푸터
        canvas.setFillColor(colors.HexColor('#CCCCCC'))
        canvas.setLineWidth(0.5)
        canvas.line(40, 40, width - 40, 40)
        
        canvas.setFillColor(colors.grey)
        canvas.setFont(self.font_name, 8)
        canvas.drawString(40, 25, "Confidential - Internal Use Only")
        canvas.drawRightString(width - 40, 25, f"Page {doc.page}")
        
        canvas.restoreState()

    def _create_kpi_box(self, label, value, color):
        """KPI 박스 생성"""
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
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        return table

    def _create_pie_chart(self, risk_counts):
        """위험도 분포 파이 차트"""
        drawing = Drawing(250, 200)
        pie = Pie()
        pie.x = 50
        pie.y = 50
        pie.width = 150
        pie.height = 150
        
        # 데이터 준비
        labels = []
        data = []
        chart_colors = []
        
        for risk in ["Critical", "High", "Medium", "Low", "Info", "Safe"]:
            if risk_counts.get(risk, 0) > 0:
                labels.append(f"{risk}: {risk_counts[risk]}")
                data.append(risk_counts[risk])
                chart_colors.append(self.RISK_COLORS.get(risk, colors.grey))
        
        pie.data = data
        pie.labels = labels
        pie.slices.strokeWidth = 0.5
        
        for i, color in enumerate(chart_colors):
            pie.slices[i].fillColor = color
        
        drawing.add(pie)
        return drawing

    def generate(self):
        doc = SimpleDocTemplate(
            self.filename, 
            pagesize=A4, 
            rightMargin=40, 
            leftMargin=40, 
            topMargin=80, 
            bottomMargin=60
        )
        
        elements = []
        styles = getSampleStyleSheet()
        
        # 커스텀 스타일
        title_style = ParagraphStyle(
            name='CustomTitle',
            parent=styles['Heading1'],
            fontName=self.bold_font,
            fontSize=20,
            textColor=self.DARK_BLUE,
            spaceAfter=12,
            leftIndent=0
        )
        
        heading_style = ParagraphStyle(
            name='CustomHeading',
            parent=styles['Heading2'],
            fontName=self.bold_font,
            fontSize=14,
            textColor=self.DARK_BLUE,
            spaceAfter=10,
            spaceBefore=15,
            borderPadding=5,
            leftIndent=0
        )
        
        cell_style = ParagraphStyle(
            name='CellStyle',
            parent=styles['Normal'],
            fontName=self.font_name,
            fontSize=8,
            leading=10
        )

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # 자산 데이터 조회
            cursor.execute("SELECT asset_id, ip_addr, os_type, hostname, mac_addr, memo FROM TBL_ASSETS ORDER BY ip_addr ASC")
            all_assets = cursor.fetchall()
            
            if not all_assets:
                raise Exception("진단된 자산 데이터가 없습니다.")

            # 전체 취약점 통계 수집
            cursor.execute("""
                SELECT risk_level, COUNT(*) 
                FROM TBL_SCAN_RESULT 
                GROUP BY risk_level
            """)
            risk_stats = dict(cursor.fetchall())
            
            total_vulns = sum(risk_stats.values())
            critical_high = risk_stats.get('Critical', 0) + risk_stats.get('High', 0)

            # === 1. 커버 페이지 (Executive Summary) ===
            elements.append(Spacer(1, 2*cm))
            
            # 메인 타이틀
            cover_title = Paragraph(
                "<b>Security Vulnerability</b><br/><b>Assessment Report</b>",
                ParagraphStyle(name='cover', fontName=self.bold_font, fontSize=28, 
                             textColor=self.DARK_BLUE, alignment=1, leading=35)
            )
            elements.append(cover_title)
            elements.append(Spacer(1, 1.5*cm))
            
            # KPI 카드 배치
            kpi_data = [[
                self._create_kpi_box("Total Assets", len(all_assets), colors.HexColor('#E8F4F8')),
                self._create_kpi_box("Total Issues", total_vulns, colors.HexColor('#FFF4E6')),
                self._create_kpi_box("Critical & High", critical_high, colors.HexColor('#FFE5E5'))
            ]]
            
            kpi_table = Table(kpi_data, colWidths=[140, 140, 140])
            kpi_table.setStyle(TableStyle([
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            elements.append(kpi_table)
            elements.append(Spacer(1, 1*cm))
            
            # 위험도 분포 테이블
            elements.append(Paragraph("<b>Risk Distribution Summary</b>", heading_style))
            elements.append(Spacer(1, 0.3*cm))
            
            dist_data = [['Risk Level', 'Count', 'Percentage', 'Visual']]
            for risk in ["Critical", "High", "Medium", "Low", "Info"]:
                count = risk_stats.get(risk, 0)
                percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
                bar = "█" * int(percentage / 5)
                
                icon = self.RISK_ICONS.get(risk, '')
                dist_data.append([
                    f"{icon} {risk}",
                    str(count),
                    f"{percentage:.1f}%",
                    bar
                ])
            
            dist_table = Table(dist_data, colWidths=[120, 80, 80, 200])
            dist_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.DARK_BLUE),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,-1), self.font_name),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F9F9F9')]),
            ]))
            
            # 위험도별 색상 적용
            for i, risk in enumerate(["Critical", "High", "Medium", "Low", "Info"], 1):
                dist_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,i), (0,i), self.RISK_COLORS.get(risk, colors.grey)),
                    ('TEXTCOLOR', (0,i), (0,i), colors.white),
                ]))
            
            elements.append(dist_table)
            elements.append(PageBreak())

            # === 2. 자산 목록 페이지 ===
            elements.append(Paragraph("📋 Scanned Assets Overview", title_style))
            elements.append(Spacer(1, 0.5*cm))
            
            asset_data = [['No.', 'IP Address', 'Hostname', 'OS Type', 'Vendor']]
            for idx, asset in enumerate(all_assets, 1):
                vendor = OUILookup.lookup(asset[4])
                asset_data.append([
                    str(idx),
                    asset[1],
                    self._truncate(asset[3], 25),
                    self._truncate(asset[2], 15),
                    self._truncate(vendor, 20)
                ])

            asset_table = Table(asset_data, colWidths=[30, 100, 130, 100, 120])
            asset_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.DARK_BLUE),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,-1), self.font_name),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F5F5F5')]),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            elements.append(asset_table)
            elements.append(PageBreak())

            # === 3. 자산별 상세 리포트 ===
            for idx, asset in enumerate(all_assets):
                asset_id, ip, os_type, hostname, mac_addr, memo = asset
                vendor = OUILookup.lookup(mac_addr)
                
                # 자산 헤더
                elements.append(Paragraph(f"🔍 Detailed Analysis: {ip}", title_style))
                elements.append(Spacer(1, 0.3*cm))
                
                # 자산 정보 박스
                info_data = [
                    ['IP Address', ip, 'OS Type', os_type],
                    ['Hostname', hostname or '-', 'Vendor', vendor],
                    ['MAC Address', mac_addr or '-', 'Memo', memo or '-']
                ]
                
                info_table = Table(info_data, colWidths=[100, 140, 100, 140])
                info_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (0,-1), self.LIGHT_BLUE),
                    ('BACKGROUND', (2,0), (2,-1), self.LIGHT_BLUE),
                    ('FONTNAME', (0,0), (-1,-1), self.font_name),
                    ('FONTSIZE', (0,0), (-1,-1), 9),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                    ('ALIGN', (0,0), (0,-1), 'RIGHT'),
                    ('ALIGN', (2,0), (2,-1), 'RIGHT'),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                    ('TOPPADDING', (0,0), (-1,-1), 6),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ]))
                elements.append(info_table)
                elements.append(Spacer(1, 0.5*cm))

                # 취약점 조회
                sql = """
                    SELECT vuln_code, vuln_name, risk_level, status, detected_value, remediation
                    FROM TBL_SCAN_RESULT 
                    WHERE asset_id = ?
                    ORDER BY 
                        CASE risk_level 
                            WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 
                            WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 
                            ELSE 5 END ASC
                """
                cursor.execute(sql, (asset_id,))
                rows = cursor.fetchall()

                # 통계 계산
                vuln_cnt = sum(1 for r in rows if r[2] in ['Critical', 'High'])
                warn_cnt = sum(1 for r in rows if r[2] in ['Medium', 'Low'])
                safe_cnt = len(rows) - (vuln_cnt + warn_cnt)
                
                deduction = (vuln_cnt * 10) + (warn_cnt * 3)
                score = max(0, 100 - deduction)

                # 점수 박스
                score_color = colors.HexColor('#20C997') if score >= 80 else \
                             colors.HexColor('#FFC107') if score >= 60 else \
                             colors.HexColor('#DC3545')
                
                stats_data = [[
                    Paragraph(f"<b>Security Score</b><br/><font size=20 color='{score_color}'>{score}</font>", 
                             ParagraphStyle(name='score', fontName=self.font_name, alignment=1)),
                    Paragraph(f"<b>Critical/High</b><br/><font size=16 color='#DC3545'>{vuln_cnt}</font>", 
                             ParagraphStyle(name='stat', fontName=self.font_name, alignment=1)),
                    Paragraph(f"<b>Medium/Low</b><br/><font size=16 color='#FFC107'>{warn_cnt}</font>", 
                             ParagraphStyle(name='stat', fontName=self.font_name, alignment=1)),
                    Paragraph(f"<b>Safe Items</b><br/><font size=16 color='#28A745'>{safe_cnt}</font>", 
                             ParagraphStyle(name='stat', fontName=self.font_name, alignment=1))
                ]]
                
                stats_table = Table(stats_data, colWidths=[120, 120, 120, 120])
                stats_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
                    ('BOX', (0,0), (-1,-1), 2, self.PRIMARY_BLUE),
                    ('INNERGRID', (0,0), (-1,-1), 1, colors.HexColor('#DDDDDD')),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                    ('TOPPADDING', (0,0), (-1,-1), 10),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 10),
                ]))
                elements.append(stats_table)
                elements.append(Spacer(1, 0.5*cm))

                # 취약점 상세 테이블
                elements.append(Paragraph("<b>Vulnerability Details</b>", heading_style))
                elements.append(Spacer(1, 0.2*cm))
                
                table_data = [['Code', 'Vulnerability Name', 'Risk', 'Details', 'Remediation']]
                
                for r in rows:
                    code, name, risk, status, detail, rem = r
                    
                    detail = str(detail).replace("\n", " ")[:100]
                    rem = str(rem).replace("\n", " ")[:80]
                    
                    risk_icon = self.RISK_ICONS.get(risk, '')
                    
                    p_name = Paragraph(html.escape(self._truncate(name, 30)), cell_style)
                    p_detail = Paragraph(html.escape(detail), cell_style)
                    p_rem = Paragraph(html.escape(rem), cell_style)
                    
                    table_data.append([code, p_name, f"{risk_icon} {risk}", p_detail, p_rem])

                if not rows:
                    table_data.append(["-", "No vulnerabilities found", "-", "-", "-"])

                detail_table = Table(table_data, colWidths=[40, 110, 60, 130, 130], repeatRows=1)
                
                ts = TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), self.DARK_BLUE),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTNAME', (0,0), (-1,-1), self.font_name),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                    ('ALIGN', (0,0), (-1,0), 'CENTER'),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#FAFAFA')]),
                ])
                
                # 위험도별 색상
                for i, row in enumerate(rows, 1):
                    risk_val = row[2]
                    if risk_val in self.RISK_COLORS:
                        ts.add('BACKGROUND', (2, i), (2, i), self.RISK_COLORS[risk_val])
                        ts.add('TEXTCOLOR', (2, i), (2, i), colors.white)

                detail_table.setStyle(ts)
                elements.append(detail_table)

                if idx < len(all_assets) - 1:
                    elements.append(PageBreak())

        finally:
            conn.close()

        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        return self.filename