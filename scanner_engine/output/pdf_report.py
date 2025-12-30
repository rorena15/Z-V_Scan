# scanner_engine/output/pdf_report.py
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
        # 상위 폴더의 DB 경로 찾기
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_path = os.path.join(os.path.dirname(base_dir), 'zvuln_scan.db')
        
        # 저장 경로 (dist 폴더 대응)
        output_dir = os.path.join(os.path.dirname(base_dir), 'report')
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except:
                output_dir = os.getcwd() # 실패 시 현재 경로
                
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = os.path.join(output_dir, f"Scan_Report_{timestamp}.pdf")
        self.font_path = OSUtils.get_font_path("NanumGothic.ttf")

    def generate(self):
        c = canvas.Canvas(self.filename, pagesize=A4)
        width, height = A4

        # 1. 한글 폰트 등록 (Windows 기준)
        try:
            if os.path.exists(self.font_path):
                # 확보한 경로의 폰트 등록
                pdfmetrics.registerFont(TTFont("CustomFont", self.font_path))
                font_name = "CustomFont"
            else:
                print(f"[Warning] Font file not found: {self.font_path}")
                # 윈도우라면 맑은고딕 백업 시도
                if OSUtils.is_windows() and os.path.exists("C:/Windows/Fonts/malgun.ttf"):
                    pdfmetrics.registerFont(TTFont("MalgunGothic", "C:/Windows/Fonts/malgun.ttf"))
                    font_name = "MalgunGothic"
        except Exception as e:
            print(f"[Error] Font loading failed: {e}")

        # 2. 타이틀 섹션
        c.setFont(font_name, 24)
        c.drawString(50, height - 50, "Z-Vuln Scan 보안 진단 리포트")
        
        c.setFont(font_name, 10)
        c.drawString(50, height - 70, f"생성 일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.line(50, height - 80, width - 50, height - 80)

        # 3. DB에서 데이터 가져오기
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 가장 최근에 스캔된 자산 찾기
        cursor.execute("SELECT asset_id, ip_addr, os_type, hostname FROM TBL_ASSETS ORDER BY last_seen DESC LIMIT 1")
        asset = cursor.fetchone()
        
        if not asset:
            c.drawString(50, height - 100, "데이터 없음: 스캔된 자산이 없습니다.")
            c.save()
            return

        asset_id, ip, os_type, hostname = asset
        
        # 자산 정보 출력
        c.setFont(font_name, 12)
        c.drawString(50, height - 110, f"Target IP: {ip} ({os_type})")
        c.drawString(50, height - 130, f"Hostname: {hostname}")

        # 진단 결과 조회 (JOIN)
        sql = """
            SELECT V.code, V.name, R.status, R.detected_value, V.category
            FROM TBL_SCAN_RESULT R
            JOIN TBL_VULN_DEF V ON R.vuln_id = V.vuln_id
            WHERE R.asset_id = ?
            ORDER BY V.code ASC
        """
        cursor.execute(sql, (asset_id,))
        rows = cursor.fetchall()
        conn.close()

        # 통계 계산
        total = len(rows)
        vuln_cnt = sum(1 for r in rows if r[2] in ['VULNERABLE', '취약', 'Fail'])
        safe_cnt = total - vuln_cnt
        score = int((safe_cnt / total) * 100) if total > 0 else 0

        # 4. 요약 차트 (텍스트로 대체하거나 간단한 도형)
        c.setFillColor(colors.lightgrey)
        c.rect(400, height - 140, 150, 80, fill=1)
        c.setFillColor(colors.black)
        c.setFont(font_name, 14)
        c.drawString(420, height - 90, f"보안 점수: {score}점")
        c.setFont(font_name, 10)
        c.drawString(420, height - 110, f"취약: {vuln_cnt} / 양호: {safe_cnt}")

        # 5. 결과 테이블 그리기
        data = [['코드', '항목명', '상태', '상세 결과']] # 헤더
        
        # 데이터가 너무 길면 잘라서 넣기
        for r in rows:
            code = r[0]
            name = r[1]
            status = "취약" if r[2] in ['VULNERABLE', '취약', 'Fail'] else "양호"
            detail = r[3][:30] + "..." if len(r[3]) > 30 else r[3] # 너무 길면 자름
            data.append([code, name, status, detail])

        if not rows:
            data.append(["-", "진단된 항목 없음", "-", "-"])

        # 테이블 스타일 설정
        table = Table(data, colWidths=[50, 200, 50, 200])
        style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.navy),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,-1), font_name),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ])
        
        # 상태에 따라 행 색상 변경 (취약은 빨간 글씨)
        for i, row in enumerate(data[1:], start=1):
            if row[2] == "취약":
                style.add('TEXTCOLOR', (2, i), (2, i), colors.red)
            else:
                style.add('TEXTCOLOR', (2, i), (2, i), colors.green)

        table.setStyle(style)
        
        # 테이블 위치 잡기 (페이지 넘김 처리는 생략된 약식 버전)
        table.wrapOn(c, width, height)
        table.drawOn(c, 50, height - 160 - (len(data) * 20))

        c.save()
        return self.filename