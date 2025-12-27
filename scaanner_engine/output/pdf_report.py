from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
# 폰트 깨짐 방지를 위한 표준 폰트 임포트 (한글 지원은 별도 설정 필요하나 일단 영문 기준)
import sys
import os

# DB 연동 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

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
        elements.append(Paragraph("Asset-Watch Security Audit Report", styles['Title']))
        elements.append(Spacer(1, 20))

        conn = self.db.create_connection()
        if conn is None:
            # DB 연결 실패 시 에러 발생시키지 않고 빈 PDF라도 생성하거나 메시지 출력
            print("[Error] DB Connection Failed.")
            return

        try:
            cursor = conn.cursor()

            # 2. 요약 정보 조회 (데이터가 없어도 0으로 처리되도록 함)
            cursor.execute("SELECT COUNT(*) FROM TBL_ASSETS")
            res_asset = cursor.fetchone()
            total_assets = res_asset[0] if res_asset else 0
            
            cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT WHERE status='VULNERABLE'")
            res_vuln = cursor.fetchone()
            total_vulns = res_vuln[0] if res_vuln else 0

            summary_text = f"Total Assets Scanned: {total_assets}  |  Vulnerabilities Found: {total_vulns}"
            elements.append(Paragraph(summary_text, styles['Normal']))
            elements.append(Spacer(1, 20))

            # 3. 상세 데이터 조회
            # 헤더(제목) 행 미리 추가
            data = [['Asset IP', 'Vuln Code', 'Severity', 'Status', 'Details']]

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
                # [수정 포인트 1] DB에 값이 NULL(None)일 경우 에러 방지 (""로 변환)
                ip = str(row[0])
                code = str(row[1])
                severity = str(row[2])
                status = str(row[3])
                
                raw_detail = row[4] if row[4] is not None else ""
                detail = raw_detail[:30] + "..." if len(raw_detail) > 30 else raw_detail
                
                data.append([ip, code, severity, status, detail])

        except Exception as e:
            # SQL 에러 시 로그 출력 후 종료
            print(f"Error fetching data: {e}")
            raise e
        finally:
            if conn:
                conn.close()

        # 4. 표 생성 (데이터가 있을 때만 스타일 적용)
        # [수정 포인트 2] 헤더만 있고 데이터가 없으면 표를 그리지 않거나 안내 문구 출력
        if len(data) > 1:
            table = Table(data, colWidths=[100, 60, 60, 80, 180])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),       # 헤더 배경색
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # 헤더 글자색
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),     # 데이터 행 배경색
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(table)
        else:
            # 데이터가 없을 경우 메시지 표시
            elements.append(Paragraph("No vulnerabilities detected or no scan performed yet.", styles['Normal']))

        # PDF 빌드
        doc.build(elements)
        print(f"[PDF] Report Generated: {self.filename}")
        return self.filename

if __name__ == "__main__":
    pdf = PDFGenerator()
    pdf.generate_report()