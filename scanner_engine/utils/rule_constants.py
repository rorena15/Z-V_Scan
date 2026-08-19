# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[버그 수정 - 중복 제거] db_connector.py, text_report.py, excel_report.py 세 곳에
RULE_FILES/IMPORTANCE_WEIGHT가 각각 복사돼 있었다(db_connector.py의 예전 주석에
"세 번째 사본"이라고 스스로 적어놓았을 정도). rules/*.json 구성이 바뀔 때 세 곳을
전부 손으로 맞춰야 했고, 하나라도 놓치면 대시보드 보안수준 점수가 Excel 리포트
표지 점수와 조용히 어긋난다 - 이 모듈 하나로 통합한다.
"""

# 엔진별 룰 파일과, database_inspector.py가 내부 저장 키에 붙이는 접두어
RULE_FILES = {
    "linux_rules.json": "",
    "windows_rules.json": "",
    "pc_rules.json": "",
    "mysql_rules.json": "MYSQL-",
    "postgresql_rules.json": "POSTGRESQL-",
    "mssql_rules.json": "MSSQL-",
    "oracle_rules.json": "ORACLE-",
    "web_rules.json": "",
}

IMPORTANCE_WEIGHT = {"상": 10, "중": 8, "하": 6}
