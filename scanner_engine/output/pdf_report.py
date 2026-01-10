# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
# [FINAL FIXED] scanner_engine/output/pdf_report.py

import os
import sys
import sqlite3
import html
import re
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# [중요] DB 경로 로드 및 폰트 유틸
from utils.os_utils import OSUtils
from utils.oui_lookup import OUILookup

class PDFGenerator:
    def __init__(self):
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            # output -> scanner_engine -> Project Root (3단계 위)
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
            
        self.output_dir = os.path.join(base_path, 'reports')
        
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except OSError:
                pass
                
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = os.path.join(self.output_dir, f"Scan_Report_{timestamp}.pdf")
        
        # 폰트 설정
        self.font_path = OSUtils.get_font_path("NanumGothic.ttf")
        self.font_name = "Helvetica"
        try:
            if os.path.exists(self.font_path):
                pdfmetrics.registerFont(TTFont("CustomFont", self.font_path))
                self.font_name = "CustomFont"
            elif OSUtils.is_windows() and os.path.exists("C:/Windows/Fonts/malgun.ttf"):
                pdfmetrics.registerFont(TTFont("MalgunGothic", "C:/Windows/Fonts/malgun.ttf"))
                self.font_name = "MalgunGothic"
        except: pass

    def _truncate(self, text, limit):
        if not text: return "-"
        text = str(text)
        return text[:limit] + "..." if len(text) > limit else text

    def _header_footer(self, canvas, doc):
        canvas.saveState()
        width, height = A4
        canvas.setFont(self.font_name, 20)
        canvas.drawString(30, height - 40, "Z-VulnScan Executive Report")
        canvas.setStrokeColor(colors.darkblue)
        canvas.setLineWidth(1.5)
        canvas.line(30, height - 55, width - 30, height - 55)
        canvas.setFont(self.font_name, 9)
        canvas.setFillColor(colors.gray)
        canvas.drawString(30, height - 70, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        canvas.drawRightString(width - 30, height - 70, f"Page {doc.page}")
        canvas.restoreState()

    def generate(self):
        doc = SimpleDocTemplate(self.filename, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=90, bottomMargin=50)
        elements = []
        styles = getSampleStyleSheet()
        
        cell_style = ParagraphStyle(name='CellStyle', parent=styles['Normal'], fontName=self.font_name, fontSize=8, leading=10)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # 1. 자산 목록 조회
            cursor.execute("SELECT asset_id, ip_addr, os_type, hostname, mac_addr, memo FROM TBL_ASSETS ORDER BY ip_addr ASC")
            all_assets = cursor.fetchall()
            
            if not all_assets:
                raise Exception("진단된 자산 데이터가 없습니다.")

            # 2. 요약 페이지
            elements.append(Paragraph(f"<b>[Network Scan Summary] Total Assets: {len(all_assets)}</b>", styles['Heading2']))
            elements.append(Spacer(1, 10))

            summary_data = [['IP Address', 'Hostname', 'OS Type', 'Vendor']]
            for asset in all_assets:
                vendor = OUILookup.lookup(asset[4])
                summary_data.append([asset[1], self._truncate(asset[3], 20), self._truncate(asset[2], 15), self._truncate(vendor, 20)])

            summary_table = Table(summary_data, colWidths=[120, 140, 100, 140])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,-1), self.font_name),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ]))
            elements.append(summary_table)
            elements.append(PageBreak())

            # 3. 상세 리포트
            for idx, asset in enumerate(all_assets):
                asset_id, ip, os_type, hostname, mac_addr, memo = asset
                vendor = OUILookup.lookup(mac_addr)
                
                elements.append(Paragraph(f"<b>Detail Report : {ip}</b>", styles['Heading2']))
                elements.append(Spacer(1, 5))

                info_table = Table([
                    [f"Target IP: {ip}", f"OS Type: {os_type}"],
                    [f"Hostname: {hostname}", f"Vendor: {vendor}"],
                    [f"Memo: {memo or '-'}", ""]
                ], colWidths=[260, 260])
                info_table.setStyle(TableStyle([
                    ('FONTNAME', (0,0), (-1,-1), self.font_name),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
                    ('BACKGROUND', (0,0), (-1,-1), colors.whitesmoke),
                ]))
                elements.append(info_table)
                elements.append(Spacer(1, 15))

                # [핵심 수정] JOIN 제거 -> 단일 테이블 조회 (DB 구조 반영)
                sql = """
                    SELECT vuln_code, vuln_name, risk_level, status, detected_value, remediation
                    FROM TBL_SCAN_RESULT 
                    WHERE asset_id = ?
                    ORDER BY risk_level DESC, vuln_code ASC
                """
                cursor.execute(sql, (asset_id,))
                rows = cursor.fetchall()

                # 통계 계산 (risk_level 기준)
                vuln_cnt = sum(1 for r in rows if r[2] in ['Critical', 'High'])
                warn_cnt = sum(1 for r in rows if r[2] in ['Medium', 'Low'])
                safe_cnt = len(rows) - (vuln_cnt + warn_cnt)
                
                deduction = (vuln_cnt * 10) + (warn_cnt * 3)
                score = max(0, 100 - deduction)

                stats_table = Table([[f"Score: {score}", f"Critical/High: {vuln_cnt}", f"Med/Low: {warn_cnt}", f"Safe: {safe_cnt}"]], 
                                    colWidths=[140, 120, 120, 120])
                stats_table.setStyle(TableStyle([
                    ('FONTNAME', (0,0), (-1,-1), self.font_name),
                    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                    ('BOX', (0,0), (-1,-1), 1, colors.black),
                    ('BACKGROUND', (0,0), (-1,-1), colors.aliceblue),
                ]))
                elements.append(stats_table)
                elements.append(Spacer(1, 20))

                # 상세 테이블
                table_data = [['Code', 'Item Name', 'Risk', 'Status', 'Issue Summary', 'Action']]
                for r in rows:
                    code, name, risk, status, detail, rem = r
                    
                    # 텍스트 정제
                    detail = str(detail).replace("\n", " ")[:80]
                    rem = str(rem).replace("\n", " ")[:50]
                    
                    # Risk 표시
                    risk_display = risk if risk else "-"
                    status_display = "Vuln" if status != "Safe" else "Safe"

                    p_detail = Paragraph(html.escape(detail), cell_style)
                    p_rem = Paragraph(html.escape(rem), cell_style)
                    
                    table_data.append([code, self._truncate(name, 20), risk_display, status_display, p_detail, p_rem])

                if not rows:
                    table_data.append(["-", "No Data", "-", "-", "-", "-"])

                main_table = Table(table_data, colWidths=[45, 100, 50, 40, 150, 150], repeatRows=1)
                
                # 스타일링 (Risk 색상 적용)
                ts = TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTNAME', (0,0), (-1,-1), self.font_name),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('GRID', (0,0), (-1,-1), 0.25, colors.lightgrey),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ])
                
                for i, row in enumerate(rows, 1):
                    risk_val = row[2]
                    if risk_val in ['Critical', 'High']:
                        ts.add('TEXTCOLOR', (2, i), (2, i), colors.red)
                    elif risk_val in ['Medium', 'Low']:
                        ts.add('TEXTCOLOR', (2, i), (2, i), colors.orange)
                    elif row[3] == 'Safe':
                        ts.add('TEXTCOLOR', (2, i), (2, i), colors.green)

                main_table.setStyle(ts)
                elements.append(main_table)

                if idx < len(all_assets) - 1: elements.append(PageBreak())

        finally:
            conn.close()

        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        return self.filename