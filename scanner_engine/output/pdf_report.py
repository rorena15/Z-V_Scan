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
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
from datetime import datetime
from utils.os_utils import OSUtils

class PDFGenerator:
    def __init__(self):
        # DB 경로 설정
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_path = os.path.join(os.path.dirname(base_dir), 'zvuln_scan.db')
        
        # 저장 경로
        output_dir = os.path.join(os.path.dirname(base_dir), 'report')
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except:
                output_dir = os.getcwd()
                
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = os.path.join(output_dir, f"Scan_Report_{timestamp}.pdf")
        self.font_path = OSUtils.get_font_path("NanumGothic.ttf")

    def _truncate(self, text, limit):
        #텍스트가 길면 자르고 ...을 붙임 (오버플로우 방지)
        if not text: return "-"
        text = str(text)
        if len(text) > limit:
            return text[:limit] + "..."
        return text

    def generate(self):
        c = canvas.Canvas(self.filename, pagesize=A4)
        width, height = A4 # A4 = 595.27 x 841.89 points

        # 1. 폰트 등록
        font_name = "Helvetica"
        try:
            if os.path.exists(self.font_path):
                pdfmetrics.registerFont(TTFont("CustomFont", self.font_path))
                font_name = "CustomFont"
            elif OSUtils.is_windows() and os.path.exists("C:/Windows/Fonts/malgun.ttf"):
                pdfmetrics.registerFont(TTFont("MalgunGothic", "C:/Windows/Fonts/malgun.ttf"))
                font_name = "MalgunGothic"
        except Exception as e:
            print(f"[Error] Font loading failed: {e}")

        # 2. 타이틀 & 안내 문구
        c.setFont(font_name, 22)
        c.drawString(40, height - 50, "Z-Vuln Scan Executive Summary")
        
        c.setFont(font_name, 9)
        c.setFillColor(colors.gray)
        c.drawString(40, height - 70, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  * 상세 기술 내용은 별첨 Excel 파일 참조")
        c.setFillColor(colors.black)
        c.line(40, height - 80, width - 40, height - 80)

        # 3. 데이터 조회
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # [수정 포인트] 테이블이 없거나 데이터가 없을 때 발생하는 에러를 잡습니다.
            cursor.execute("SELECT asset_id, ip_addr, os_type, hostname FROM TBL_ASSETS ORDER BY last_seen DESC LIMIT 1")
            asset = cursor.fetchone()
        except sqlite3.OperationalError:
            # 테이블이 없는 경우 (DB가 아직 생성되지 않음)
            raise Exception("진단 데이터가 없습니다.\n먼저 [Network Discovery] 또는 [Vulnerability Audit]을 수행해주세요.")
        except Exception as e:
            # 기타 DB 에러
            raise Exception(f"DB 조회 중 오류가 발생했습니다: {str(e)}")
        
        if not asset:
            # 테이블은 있는데 데이터가 없는 경우
            conn.close() # 연결 닫기 필수
            raise Exception("리포트를 생성할 데이터가 없습니다.\n먼저 스캔을 수행해주세요.")

        asset_id, ip, os_type, hostname = asset
        c.setFont(font_name, 11)
        c.drawString(40, height - 100, f"Target: {ip} ({os_type})  |  Host: {hostname}")

        # 조치 방안 포함 조회
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

        # 4. 상단 스코어 보드
        vuln_cnt = sum(1 for r in rows if r[2] in ['VULNERABLE', '취약', 'Fail', 'Critical', 'High'])
        warn_cnt = sum(1 for r in rows if r[2] in ['WARNING', '경고', 'Medium', 'Low'])
        safe_cnt = len(rows) - (vuln_cnt + warn_cnt)
        
        #점수 산정 기준 강화
        deduction = (vuln_cnt * 10) + (warn_cnt * 3)
        score = max(0, 100 - deduction)
        
        # 취약점이 있으면 A등급(90점 이상) 불가
        if vuln_cnt > 0 and score > 90:
            score = 90

        # 스코어 박스
        c.setStrokeColor(colors.grey)
        c.setFillColor(colors.whitesmoke)
        c.roundRect(width - 200, height - 140, 160, 50, 5, fill=1) # 둥근 사각형
        
        c.setFillColor(colors.black)
        c.setFont(font_name, 14)
        c.drawString(width - 190, height - 110, f"Security Score: {score}")
        
        c.setFont(font_name, 9)
        c.setFillColor(colors.red)
        c.drawString(width - 190, height - 125, f"Vuln: {vuln_cnt}")
        c.setFillColor(colors.orange)
        c.drawString(width - 140, height - 125, f"Warn: {warn_cnt}")
        c.setFillColor(colors.green)
        c.drawString(width - 90, height - 125, f"Safe: {safe_cnt}")

        # 5. 테이블 데이터 구성
        # 헤더: Code, Item, Status, Detail(요약), Action(요약)
        data = [['Code', 'Item Name', 'Status', 'Issue Summary', 'Action Plan']]
        
        # [중요] 컬럼 너비 조정 (합계 약 515pt)
        # Code(40) + Item(100) + Status(45) + Issue(165) + Action(165) = 515
        col_widths = [40, 100, 45, 165, 165] 

        for r in rows:
            code = r[0]
            # [오버플로우 방지] 글자 수 제한 적용
            name = self._truncate(r[1], 12)       # 항목명 12자 제한
            status_raw = r[2]
            detail = self._truncate(r[3], 25)     # 상세내용 25자 제한
            remediation = self._truncate(r[4], 25)# 조치방안 25자 제한

            # 상태 판정
            is_vuln = status_raw in ['VULNERABLE', '취약', 'Fail', 'Critical', 'High']
            is_warn = status_raw in ['WARNING', '경고', 'Medium', 'Low']
            
            if is_vuln: display_status = "Vuln"
            elif is_warn: display_status = "Warn"
            else: 
                display_status = "Safe"
                remediation = "-" # 양호하면 조치방안 끔

            data.append([code, name, display_status, detail, remediation])

        if not rows:
            data.append(["-", "No Data", "-", "-", "-"])

        # 6. 테이블 스타일
        table = Table(data, colWidths=col_widths)
        style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('ALIGN', (0,0), (0,-1), 'CENTER'), # Code 가운데
            ('ALIGN', (2,0), (2,-1), 'CENTER'), # Status 가운데
            ('FONTNAME', (0,0), (-1,-1), font_name),
            ('FONTSIZE', (0,0), (-1,-1), 8),    # 폰트 크기 8 (작게)
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('GRID', (0,0), (-1,-1), 0.25, colors.lightgrey),
        ])

        # 상태별 색상 적용
        for i, row in enumerate(data[1:], start=1):
            if row[2] == "Vuln":
                style.add('TEXTCOLOR', (2, i), (2, i), colors.red)
            elif row[2] == "Warn":
                style.add('TEXTCOLOR', (2, i), (2, i), colors.orange)
            else:
                style.add('TEXTCOLOR', (2, i), (2, i), colors.green)

        table.setStyle(style)
        
        # 테이블 그리기
        table.wrapOn(c, width, height)
        table.drawOn(c, 40, height - 160 - (len(data) * 16))

        c.save()
        return self.filename