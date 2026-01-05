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
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.units import mm

from utils.os_utils import OSUtils
from utils.oui_lookup import OUILookup

class PDFGenerator:
    def __init__(self):
        # [Fix] 실행 위치(Project Root) 기준 경로 설정 (유지)
        if getattr(sys, 'frozen', False):
            self.project_root = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            self.project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
            
        self.db_path = os.path.join(self.project_root, 'zvuln_scan.db')
        self.output_dir = os.path.join(self.project_root, 'report')
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

    # [New] 각 페이지마다 고정적으로 그려질 헤더/푸터 함수
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
        
        # 3. 메타 정보 (날짜 등)
        canvas.setFont(self.font_name, 9)
        canvas.setFillColor(colors.gray)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        canvas.drawString(30, height - 70, f"Generated: {timestamp}  |  Confidential Document")
        canvas.drawRightString(width - 30, height - 70, f"Page {doc.page}")
        
        # 4. 푸터 (Signature)
        canvas.line(30, 40, width - 30, 40)
        canvas.setFont(self.font_name, 8)
        canvas.drawRightString(width - 30, 25, "Created by Z-Vuln Scan (Trial Version) - Contact: [rorena1586@gmail.com]")
        
        canvas.restoreState()

    def generate(self):
        # [핵심] SimpleDocTemplate 사용 (자동 페이지 넘김 지원)
        # topMargin을 넉넉히 주어 헤더와 겹치지 않게 함
        doc = SimpleDocTemplate(
            self.filename, 
            pagesize=A4,
            rightMargin=30, leftMargin=30, 
            topMargin=90, bottomMargin=50
        )
        
        elements = [] # PDF에 들어갈 내용물(Flowables)을 담을 리스트
        styles = getSampleStyleSheet()
        normal_style = styles['Normal']
        normal_style.fontName = self.font_name

        cell_style = ParagraphStyle(
            name='CellStyle',
            parent=styles['Normal'],
            fontName=self.font_name, # 한글 폰트
            fontSize=8,              # 글자 크기
            leading=10               # 줄 간격
        )
        # --- 1. 데이터 조회 ---
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT asset_id, ip_addr, os_type, hostname, mac_addr, memo FROM TBL_ASSETS ORDER BY last_seen DESC LIMIT 1")
            asset = cursor.fetchone()
        except Exception:
            raise Exception("진단 데이터가 없습니다.")
        
        if not asset:
            conn.close()
            raise Exception("리포트 데이터 없음")

        asset_id, ip, os_type, hostname, mac_addr, memo = asset
        vendor = OUILookup.lookup(mac_addr)
        if not memo: memo = "-"

        # --- 2. 자산 정보 요약 박스 (Summary Info) ---
        # 정보를 테이블 형태로 깔끔하게 배치
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
        elements.append(Spacer(1, 15)) # 여백 추가

        # --- 3. 취약점 통계 (Scorecard) ---
        sql = """
            SELECT V.code, V.name, R.status, R.detected_value, V.remediation
            FROM TBL_SCAN_RESULT R
            JOIN TBL_VULN_DEF V ON R.vuln_id = V.vuln_id
            WHERE R.asset_id = ?
            ORDER BY V.code ASC
        """
        cursor.execute(sql, (asset_id,))
        rows = cursor.fetchall()
        conn.close()

        vuln_cnt = sum(1 for r in rows if r[2] in ['VULNERABLE', '취약', 'Fail', 'Critical', 'High'])
        warn_cnt = sum(1 for r in rows if r[2] in ['WARNING', '경고', 'Medium', 'Low'])
        safe_cnt = len(rows) - (vuln_cnt + warn_cnt)
        
        # 점수 계산
        deduction = (vuln_cnt * 10) + (warn_cnt * 3)
        score = max(0, 100 - deduction)
        if vuln_cnt > 0 and score > 90: score = 90

        # 통계 테이블
        stats_data = [[
            f"Security Score: {score} / 100", 
            f"Vuln: {vuln_cnt}", 
            f"Warn: {warn_cnt}", 
            f"Safe: {safe_cnt}"
        ]]
        
        stats_table = Table(stats_data, colWidths=[200, 100, 100, 100])
        stats_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,-1), self.font_name),
            ('FONTSIZE', (0,0), (0,0), 14), # Score 폰트 크게
            ('FONTSIZE', (1,0), (-1,-1), 10),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TEXTCOLOR', (1,0), (1,0), colors.red),    # Vuln Red
            ('TEXTCOLOR', (2,0), (2,0), colors.orange), # Warn Orange
            ('TEXTCOLOR', (3,0), (3,0), colors.green),  # Safe Green
            ('BOX', (0,0), (-1,-1), 1, colors.grey),
            ('BACKGROUND', (0,0), (-1,-1), colors.aliceblue),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 20))

        # --- 4. 상세 결과 테이블 (Main Table) ---
        # 헤더
        table_data = [['Code', 'Item Name', 'Status', 'Issue Summary', 'Action Plan']]
        
        # 내용 채우기
        for r in rows:
            code = r[0]
            name = self._truncate(r[1], 15) # 글자수 제한
            status_raw = r[2]
            
            raw_detail = r[3] if r[3] else "-"      # 값이 None일 경우 처리
            raw_remediation = r[4] if r[4] else "-" # 값이 None일 경우 처리
            
            if isinstance(raw_detail, str):
                # 태그를 빈 문자열로 치환하고 앞뒤 공백 제거
                text = raw_detail.replace("[Banner Info]", "").replace("[banner info]", "")
                
                text = re.sub(r'[^\w\s\.\-\:\;\(\)\[\]\/=\,\"\']', ' ', text)
                
                text = re.sub(r'\s+', ' ', text).strip()
                
                if len(text) > 80:
                    text = text[:80] + "..."
                
                raw_detail = text
                
                # 태그 지웠더니 남는 게 없으면 '-' 처리
                if not raw_detail: 
                    raw_detail = "-"
            
            detail_text = html.escape(raw_detail)
            remediation_text = html.escape(raw_remediation)

            # 상태 표시 문자열 정제
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

        # 테이블 스타일링
        # colWidths 합계가 A4 가로폭(약 595pt) - 여백(60) = 535 내외여야 함
        main_table = Table(table_data, colWidths=[45, 120, 50, 160, 160], repeatRows=1) # [중요] repeatRows=1 : 페이지 넘어가도 헤더 반복
        
        style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkblue), # 헤더 배경
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),     # 헤더 글자색
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('ALIGN', (0,0), (0,-1), 'CENTER'), # Code 센터
            ('ALIGN', (2,0), (2,-1), 'CENTER'), # Status 센터
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (-1,-1), self.font_name),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('GRID', (0,0), (-1,-1), 0.25, colors.lightgrey),
        ])

        # 행별 색상 처리 (취약점 강조)
        for i, row in enumerate(table_data[1:], start=1):
            status = row[2]
            if status == "Vuln":
                style.add('TEXTCOLOR', (2, i), (2, i), colors.red)
                style.add('FONTSIZE', (2, i), (2, i), 9) # 강조
            elif status == "Warn":
                style.add('TEXTCOLOR', (2, i), (2, i), colors.orange)
            else:
                style.add('TEXTCOLOR', (2, i), (2, i), colors.green)

        main_table.setStyle(style)
        elements.append(main_table)


        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        
        return self.filename