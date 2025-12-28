# Copyright (c) 2025 rorena15
# All rights reserved.
# Proprietary License - No redistribution or modification without permission.
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import sqlite3
import os
import sys

# 상위 폴더 모듈 참조
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.db_connector import DBConnector

class PDFGenerator:
    def __init__(self):
        self.filename = "Security_Report.pdf"
        # [핵심] 한글 폰트 등록 (Windows 기준: 맑은 고딕)
        try:
            font_path = "C:/Windows/Fonts/malgun.ttf"
            if os.path.exists(font_path):
                pdfmetrics.registerFont(TTFont('Malgun', font_path))
                self.font_name = 'Malgun'
            else:
                self.font_name = 'Helvetica' # 폰트 없으면 기본 영문
        except:
            self.font_name = 'Helvetica'

    def generate(self):
        c = canvas.Canvas(self.filename, pagesize=A4)
        width, height = A4

        # 1. 타이틀
        c.setFont(self.font_name, 24)
        c.drawString(50, height - 50, "Asset-Watch 보안 진단 보고서")
        
        c.setFont(self.font_name, 10)
        c.drawString(50, height - 80, "본 보고서는 KISA 주요정보통신기반시설 가이드라인을 기준으로 작성되었습니다.")

        # 2. DB 데이터 조회
        db = DBConnector()
        if db.conn:
            cursor = db.conn.cursor(dictionary=True)
            
            # 취약점 발견 현황 (Fail 항목만)
            sql = """
                SELECT A.ip_addr, V.code, V.title, R.status, R.detected_value 
                FROM TBL_SCAN_RESULT R
                JOIN TBL_ASSETS A ON R.asset_id = A.asset_id
                JOIN TBL_VULN_DEF V ON R.vuln_id = V.vuln_id
                ORDER BY A.ip_addr, V.code
            """
            cursor.execute(sql)
            rows = cursor.fetchall()
            
            y = height - 120
            c.setFont(self.font_name, 10)
            
            c.drawString(50, y, "[진단 결과 상세]")
            y -= 20
            
            for row in rows:
                if y < 50: # 페이지 넘김 처리 (간단 구현)
                    c.showPage()
                    c.setFont(self.font_name, 10)
                    y = height - 50
                
                # 색상 처리 (취약하면 빨강)
                if row['status'] == 'VULNERABLE':
                    c.setFillColorRGB(1, 0, 0)
                else:
                    c.setFillColorRGB(0, 0, 0)
                    
                line = f"[{row['code']}] {row['ip_addr']} - {row['title']} : {row['status']}"
                c.drawString(50, y, line)
                
                # 상세 내용 (작게)
                c.setFillColorRGB(0.3, 0.3, 0.3)
                detail = f"   └ {row['detected_value'][:60]}..." # 길이 제한
                c.drawString(50, y-12, detail)
                
                y -= 30

            cursor.close()
            db.conn.close()

        c.save()
        print(f"Report Generated: {os.path.abspath(self.filename)}")

if __name__ == "__main__":
    gen = PDFGenerator()
    gen.generate()