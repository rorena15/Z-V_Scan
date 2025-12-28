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
            # 폰트 경로는 배포 환경에 따라 수정이 필요할 수 있습니다.
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
        c.drawString(50, height - 50, "Z-Vuln Scan 보안 진단 보고서")
        
        c.setFont(self.font_name, 10)
        c.drawString(50, height - 80, "본 보고서는 KISA 주요정보통신기반시설 가이드라인을 기준으로 작성되었습니다.")

        # 2. DB 데이터 조회 (SQLite 방식 적용)
        db = DBConnector()
        conn = db.create_connection() # DBConnector의 메서드 호출

        if conn:
            # [수정 1] SQLite에서 컬럼명으로 접근하기 위한 설정 (dictionary=True 대체)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # [수정 2] 쿼리 수정 (V.title -> V.name)
            # 앞서 db_connector.py에서 테이블 생성 시 컬럼명을 'name'으로 정의했으므로 일치시켜야 함
            sql = """
                SELECT A.ip_addr, V.code, V.name, R.status, R.detected_value 
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
                if y < 50: # 페이지 넘김 처리
                    c.showPage()
                    c.setFont(self.font_name, 10)
                    y = height - 50
                
                # 색상 처리 (취약하면 빨강)
                # 'VULNERABLE' 혹은 '취약' 상태일 때 빨간색 표시
                if row['status'] in ['VULNERABLE', '취약']:
                    c.setFillColorRGB(1, 0, 0)
                else:
                    c.setFillColorRGB(0, 0, 0)
                
                # [수정 3] row['title'] -> row['name'] 변경
                line = f"[{row['code']}] {row['ip_addr']} - {row['name']} : {row['status']}"
                c.drawString(50, y, line)
                
                # 상세 내용 (작게)
                c.setFillColorRGB(0.3, 0.3, 0.3)
                # None 타입 방지를 위한 안전한 처리
                det_val = row['detected_value'] if row['detected_value'] else ""
                detail = f"   └ {det_val[:60]}..." 
                c.drawString(50, y-12, detail)
                
                y -= 30

            cursor.close()
            conn.close()

        c.save()
        print(f"Report Generated: {os.path.abspath(self.filename)}")

if __name__ == "__main__":
    gen = PDFGenerator()
    gen.generate()