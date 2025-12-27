from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import sys
import os

# DB 연동을 위한 경로 설정
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.db_connector import DBConnector

class PDFGenerator:
    def __init__(self, filename="Security_Audit_Report.pdf"):
        self.filename = filename
        self.db = DBConnector()

    def generate_report(self):
        doc = SimpleDocTemplate(self.filename, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()

        # 1. 타이틀
        title_style = styles['Title']
        elements.append(Paragraph("Asset-Watch Security Audit Report", title_style))
        elements.append(Spacer(1, 20))

        # 2. 요약 정보 (DB 쿼리)
        conn = self.db.create_connection()
        cursor = conn.cursor()
        
        # 총 자산 수
        cursor.execute("SELECT COUNT(*) FROM TBL_ASSETS")
        total_assets = cursor.fetchone()[0]
        
        # 발견된 취약점 수
        cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT WHERE status='VULNERABLE'")
        total_vulns = cursor.fetchone()[0]

        summary_text = f"Total Assets Scanned: {total_assets}  |  Vulnerabilities Found: {total_vulns}"
        elements.append(Paragraph(summary_text, styles['Normal']))
        elements.append(Spacer(1, 20))

        # 3. 상세 취약점 테이블 데이터 구성
        data = [['Asset IP', 'Vuln Code', 'Severity', 'Status', 'Details']] # 헤더

        sql = """
            SELECT A.ip_addr, V.code, V.severity, R.status, R.detected_value
            FROM TBL_SCAN_RESULT R
            JOIN TBL_ASSETS A ON R.asset_id = A.asset_id
            JOIN TBL_VULN_DEF V ON R.vuln_id = V.vuln_id
            ORDER BY A.ip_addr
        """
        cursor.execute(sql)
        rows = cursor.fetchall()
        
        for row in rows:
            # 내용이 너무 길면 자르기
            detail = row[4][:30] + "..." if len(row[4]) > 30 else row[4]
            data.append([row[0], row[1], row[2], row[3], detail])

        cursor.close()
        conn.close()

        # 4. 테이블 스타일링
        table = Table(data, colWidths=[100, 60, 60, 80, 180])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        elements.append(table)
        
        # PDF 생성
        doc.build(elements)
        print(f"[PDF] Report Generated: {self.filename}")
        return self.filename

if __name__ == "__main__":
    pdf = PDFGenerator()
    pdf.generate_report()