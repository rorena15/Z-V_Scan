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
import re
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.units import mm

from utils.os_utils import OSUtils
from utils.oui_lookup import OUILookup

class PDFGenerator:
    def __init__(self):
        # [Fix] 실행 위치(Project Root) 기준 경로 설정
        if getattr(sys, 'frozen', False):
            self.project_root = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            self.project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
            
        self.db_path = os.path.join(self.project_root, 'zvuln_scan.db')
        
        # [수정] 폴더명을 'reports'로 변경
        self.output_dir = os.path.join(self.project_root, 'reports')
        _signature = "Made_By_rorena_2025_Seongnam_KR"
        
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except:
                self.output_dir = os.getcwd() 
                
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = os.path.join(self.output_dir, f"Scan_Report_{timestamp}.pdf")
        self.font_path = OSUtils.get_font_path("NanumGothic.ttf")

        # 폰트 등록 로직
        self.font_name = "Helvetica"
        try:
            if os.path.exists(self.font_path):
                pdfmetrics.registerFont(TTFont("CustomFont", self.font_path))
                self.font_name = "CustomFont"
            elif OSUtils.is_windows() and os.path.exists("C:/Windows/Fonts/malgun.ttf"):
                pdfmetrics.registerFont(TTFont("MalgunGothic", "C:/Windows/Fonts/malgun.ttf"))
                self.font_name = "MalgunGothic"
        except Exception as e:
            print(f"[Error] Font loading failed: {e}")

    def _truncate(self, text, limit):
        if not text: return "-"
        text = str(text)
        if len(text) > limit:
            return text[:limit] + "..."
        return text

    # 각 페이지마다 고정적으로 그려질 헤더/푸터 함수
    def _header_footer(self, canvas, doc):
        canvas.saveState()
        width, height = A4
        
        # 1. 헤더 (Title)
        canvas.setFont(self.font_name, 20)
        canvas.drawString(30, height - 40, "Z-VulnScan Executive Report Trial")
        
        # 2. 헤더 라인
        canvas.setStrokeColor(colors.darkblue)
        canvas.setLineWidth(1.5)
        canvas.line(30, height - 55, width - 30, height - 55)
        
        # 3. 메타 정보
        canvas.setFont(self.font_name, 9)
        canvas.setFillColor(colors.gray)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        canvas.drawString(30, height - 70, f"Generated: {timestamp}  |  Confidential Document")
        canvas.drawRightString(width - 30, height - 70, f"Page {doc.page}")
        
        # 4. 푸터
        canvas.line(30, 40, width - 30, 40)
        canvas.setFont(self.font_name, 8)
        canvas.drawRightString(width - 30, 25, "Created by Z-Vuln Scan (Trial Version) - Contact: [rorena1586@gmail.com]")
        
        canvas.restoreState()

    def generate(self):
        doc = SimpleDocTemplate(
            self.filename, 
            pagesize=A4,
            rightMargin=30, leftMargin=30, 
            topMargin=90, bottomMargin=50
        )
        
        elements = []
        styles = getSampleStyleSheet()
        normal_style = styles['Normal']
        normal_style.fontName = self.font_name

        cell_style = ParagraphStyle(
            name='CellStyle',
            parent=styles['Normal'],
            fontName=self.font_name,
            fontSize=8,
            leading=10
        )

        # --- 1. 데이터 조회 (전체 자산) ---
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # [수정] LIMIT 1 제거, ORDER BY IP, fetchall() 사용
            cursor.execute("SELECT asset_id, ip_addr, os_type, hostname, mac_addr, memo FROM TBL_ASSETS ORDER BY ip_addr ASC")
            all_assets = cursor.fetchall()
            
        except Exception as e:
            conn.close()
            raise Exception(f"DB Error: {e}")

        if not all_assets:
            conn.close()
            raise Exception("진단된 자산 데이터가 없습니다.")

        # --- [추가] 2. 전체 자산 요약 (Network Summary Page) ---
        # 리포트 맨 첫 페이지에 발견된 전체 호스트 리스트를 표로 보여줍니다.
        title_para = Paragraph(f"<b>[Network Scan Summary] Total Assets: {len(all_assets)}</b>", styles['Heading2'])
        elements.append(title_para)
        elements.append(Spacer(1, 10))

        summary_header = ['IP Address', 'Hostname', 'OS Type', 'Vendor']
        summary_data = [summary_header]

        for asset in all_assets:
            s_ip = asset[1]
            s_host = self._truncate(asset[3], 20)
            s_os = self._truncate(asset[2], 15)
            # Mac Address로 벤더 조회
            s_vendor = self._truncate(OUILookup.lookup(asset[4]), 20)
            summary_data.append([s_ip, s_host, s_os, s_vendor])

        summary_table = Table(summary_data, colWidths=[120, 140, 100, 140])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey), # 헤더 배경
            ('TEXTCOLOR', (0,0), (-1,0), colors.black),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,-1), self.font_name),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
        ]))
        elements.append(summary_table)
        elements.append(PageBreak()) # 요약 페이지 끝, 다음 장부터 상세 내용

        # --- 3. 개별 자산 상세 리포트 반복 (Loop) ---
        for idx, asset in enumerate(all_assets):
            asset_id, ip, os_type, hostname, mac_addr, memo = asset
            vendor = OUILookup.lookup(mac_addr)
            if not memo: memo = "-"

            # 제목 (어떤 IP의 리포트인지 명시)
            elements.append(Paragraph(f"<b>Detail Report : {ip}</b>", styles['Heading2']))
            elements.append(Spacer(1, 5))

            # 3-1. 자산 정보 요약 박스
            info_data = [
                [f"Target IP: {ip}", f"OS Type: {os_type}"],
                [f"Hostname: {hostname}", f"Vendor: {vendor}"],
                [f"Memo: {memo}", ""]
            ]
            
            info_table = Table(info_data, colWidths=[260, 260])
            info_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), self.font_name),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('TEXTCOLOR', (0,0), (-1,-1), colors.black),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
                ('BACKGROUND', (0,0), (-1,-1), colors.whitesmoke),
            ]))
            elements.append(info_table)
            elements.append(Spacer(1, 15))

            # 3-2. 취약점 통계 (Scorecard)
            sql = """
                SELECT V.code, V.name, R.status, R.detected_value, V.remediation
                FROM TBL_SCAN_RESULT R
                JOIN TBL_VULN_DEF V ON R.vuln_id = V.vuln_id
                WHERE R.asset_id = ?
                ORDER BY V.code ASC
            """
            cursor.execute(sql, (asset_id,))
            rows = cursor.fetchall()

            vuln_cnt = sum(1 for r in rows if r[2] in ['VULNERABLE', '취약', 'Fail', 'Critical', 'High'])
            warn_cnt = sum(1 for r in rows if r[2] in ['WARNING', '경고', 'Medium', 'Low'])
            safe_cnt = len(rows) - (vuln_cnt + warn_cnt)
            
            deduction = (vuln_cnt * 10) + (warn_cnt * 3)
            score = max(0, 100 - deduction)
            if vuln_cnt > 0 and score > 90: score = 90

            stats_data = [[
                f"Security Score: {score} / 100", 
                f"Vuln: {vuln_cnt}", 
                f"Warn: {warn_cnt}", 
                f"Safe: {safe_cnt}"
            ]]
            
            stats_table = Table(stats_data, colWidths=[200, 100, 100, 100])
            stats_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), self.font_name),
                ('FONTSIZE', (0,0), (0,0), 14),
                ('FONTSIZE', (1,0), (-1,-1), 10),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TEXTCOLOR', (1,0), (1,0), colors.red),
                ('TEXTCOLOR', (2,0), (2,0), colors.orange),
                ('TEXTCOLOR', (3,0), (3,0), colors.green),
                ('BOX', (0,0), (-1,-1), 1, colors.grey),
                ('BACKGROUND', (0,0), (-1,-1), colors.aliceblue),
            ]))
            elements.append(stats_table)
            elements.append(Spacer(1, 20))

            # 3-3. 상세 결과 테이블
            table_data = [['Code', 'Item Name', 'Status', 'Issue Summary', 'Action Plan']]
            
            for r in rows:
                code = r[0]
                name = self._truncate(r[1], 15)
                status_raw = r[2]
                
                # 안전한 문자열 변환
                raw_detail = str(r[3]) if r[3] is not None else "-"
                raw_remediation = str(r[4]) if r[4] is not None else "-"
                
                # 텍스트 정제
                text = raw_detail.replace("[Banner Info]", "").replace("[banner info]", "")
                text = re.sub(r'[^\w\s\.\-\:\;\(\)\[\]\/=\,\"\']', ' ', text)
                text = re.sub(r'\s+', ' ', text).strip()
                if len(text) > 80: text = text[:80] + "..."
                if not text: text = "-"
                
                detail_text = html.escape(text)
                remediation_text = html.escape(raw_remediation)

                # 상태별 표시
                is_vuln = status_raw in ['VULNERABLE', '취약', 'Fail', 'Critical', 'High']
                is_warn = status_raw in ['WARNING', '경고', 'Medium', 'Low']
                
                if is_vuln: display_status = "Vuln"
                elif is_warn: display_status = "Warn"
                else: 
                    display_status = "Safe"
                    remediation_text = "-"
                    
                p_detail = Paragraph(detail_text, cell_style)
                p_remediation = Paragraph(remediation_text, cell_style)
                table_data.append([code, name, display_status, p_detail, p_remediation])
                
            if not rows:
                table_data.append(["-", "No Vulnerabilities Found", "-", "-", "-"])

            main_table = Table(table_data, colWidths=[45, 120, 50, 160, 160], repeatRows=1)
            
            style = TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('ALIGN', (0,0), (0,-1), 'CENTER'), # Code
                ('ALIGN', (2,0), (2,-1), 'CENTER'), # Status
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('FONTNAME', (0,0), (-1,-1), self.font_name),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('GRID', (0,0), (-1,-1), 0.25, colors.lightgrey),
            ])

            for i, row in enumerate(table_data[1:], start=1):
                status = row[2]
                if status == "Vuln":
                    style.add('TEXTCOLOR', (2, i), (2, i), colors.red)
                    style.add('FONTSIZE', (2, i), (2, i), 9)
                elif status == "Warn":
                    style.add('TEXTCOLOR', (2, i), (2, i), colors.orange)
                else:
                    style.add('TEXTCOLOR', (2, i), (2, i), colors.green)

            main_table.setStyle(style)
            elements.append(main_table)

            # 마지막 자산이 아니라면 페이지를 넘깁니다.
            if idx < len(all_assets) - 1:
                elements.append(PageBreak())

        conn.close()
        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        return self.filename