# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import os
import re
import sys
import json
import sqlite3
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.db_connector import DBConnector
from utils.app_settings import get_report_output_dir
from utils.logger import AppLogger
from utils import rule_crypto
# [버그 수정] RULE_FILES가 이 파일/db_connector.py/excel_report.py 세 곳에 따로
# 복사돼 있어 하나만 안 고치면 조용히 어긋났다 - 공용 모듈로 통합.
from utils.rule_constants import RULE_FILES

SYS_DETAIL_LABELS = [
    ("SYS-OS_INFO", "시스템 정보"),
    ("SYS-IP_INFO", "IP 정보"),
    ("SYS-PORT_INFO", "PORT 정보"),
    ("SYS-SERVICE_INFO", "서비스 정보"),
]

# [매크로 호환] "전체 진단 현황_붙여넣기" 집계 매크로가 기대하는 "점검 결과" 문자열.
# 각 영역 결과보고서(별첨02 UNIX 등)의 실제 수식에서 정확히 이 값들과 비교한다
# (예: `=IF(O35="양호",0,IF(O35="부분만족",...))`, `=IF(OR(O35="취약",O35="부분만족"),...)`,
# `=IF($O35="N/A","-",...)`) - 다른 표기(예: "해당없음")를 쓰면 수식이 매칭에 실패한다.
STATUS_TO_RESULT = {
    "SAFE": "양호",
    "VULNERABLE": "취약",
    "PARTIAL": "부분만족",
    "NA": "N/A",
    "MANUAL": "N/A",   # 수동 확인 필요 항목이 자동 채점(위험도 합산)에 잘못 반영되지 않도록 N/A 처리
    "ERROR": "N/A",    # 접속 실패 등 점검 자체가 안 된 항목도 동일하게 N/A 처리
}


class TextReportGenerator:
    """
    호스트별 TXT 리포트를 생성.
    [코드] 항목명 / 권고 / [START] 현황 / (CMD) 명령어+원본출력(증적) / [END] 형식.

    한 호스트당 3개 구획으로 구성:
      1) Discovery  - 자산 탐지/포트 스캔 결과 (TCP-xx, UDP-xx, INFO-00)
      2) Audit      - KISA 진단 항목 (U-xx/W-xx/D-xx/WEB-xx), 카테고리별 그룹핑
      3) SYSTEM Detail - 시스템/IP/PORT/서비스 원시 정보 부록
    """

    def __init__(self, evidence_level="full", remediation_level="full"):
        # [버그 수정] 예전엔 이 생성자가 등급 정보를 아예 안 받아서, TXT로 내보내면
        # Standard 등급이어도 ExcelGenerator/PDFGenerator와 달리 증적/조치방안이
        # 전부 그대로 노출됐다(라이선스 등급 제한을 통째로 우회하는 경로였음).
        # evidence_level: "full"|"vuln_only" / remediation_level: "full"|"partial"|"none"
        # - ExcelGenerator와 동일한 의미, 동일한 값을 그대로 받아 쓴다.
        self.evidence_level = evidence_level
        self.remediation_level = remediation_level
        self.db = DBConnector()
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))

        # [Phase 3: 설정 페이지] 사용자가 지정한 리포트 출력 경로가 있으면 그것을 사용
        self.output_dir = get_report_output_dir()
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except OSError:
                pass

        self.rule_lookup = self._load_rule_lookup(base_path)

    def _load_rule_lookup(self, base_path):
        """vuln_code(엔진 접두어 포함) -> rule dict(category/command 포함) 매핑"""
        lookup = {}
        rules_dir = os.path.join(base_path, 'rules')
        if hasattr(sys, '_MEIPASS') and not os.path.isdir(rules_dir):
            rules_dir = os.path.join(sys._MEIPASS, 'rules')

        for filename, prefix in RULE_FILES.items():
            path = os.path.join(rules_dir, filename)
            if not os.path.exists(path) and not os.path.exists(rule_crypto.get_enc_path(path)):
                continue
            try:
                data = rule_crypto.load_ruleset(path)
                for rule in data:
                    lookup[f"{prefix}{rule['code']}"] = rule
            except Exception as e:
                AppLogger.log_error(f"[TextReport] Failed to load {filename}", e)
        return lookup

    @staticmethod
    def _is_discovery_code(vuln_code):
        return vuln_code.startswith("TCP-") or vuln_code.startswith("UDP-") or vuln_code == "INFO-00"

    @staticmethod
    def _is_system_detail_code(vuln_code):
        return vuln_code.startswith("SYS-")

    @staticmethod
    def _extract_real_hostname(os_info, fallback):
        """
        placeholder("(vendor) Device")가 아니라 실제 호스트명이 필요해, 이미 수집해 둔
        SYS-OS_INFO 원문(uname -a / systeminfo)에서 직접 추출한다.
        """
        if os_info:
            m = re.search(r'Host Name:\s*(\S+)', os_info)
            if m:
                return m.group(1)
            m = re.match(r'^\s*Linux\s+(\S+)', os_info)
            if m:
                return m.group(1)
        return fallback

    @staticmethod
    def _sanitize_filename(name):
        # 파일명의 첫 ']' ~ 다음 '_' 구간을 hostname으로 그대로 읽으므로
        # 파일시스템 금지 문자만 제거하고 hostname 자체는 최대한 원형 유지
        cleaned = re.sub(r'[\\/:*?"<>|\s\[\]]+', '-', str(name)).strip('-')
        return cleaned or "unknown"

    def generate(self):
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT asset_id, ip_addr, hostname, os_type FROM TBL_ASSETS ORDER BY ip_addr ASC")
            assets = cursor.fetchall()
            if not assets:
                raise Exception("진단된 자산 데이터가 없습니다.")

            # [효율성 개선] 자산마다 따로 쿼리하던 N+1 패턴 대신, 전체 자산의 결과를
            # 한 번에 가져와 asset_id 기준으로 파이썬에서 그룹핑한다 -
            # excel_report.py._fetch_scan_result()와 동일한 방식.
            cursor.execute(f"""
                SELECT asset_id, vuln_code, kisa_code, vuln_name, status, detected_value,
                       raw_output, remediation, waiver_status, operator, risk_level
                FROM TBL_SCAN_RESULT R
                WHERE {DBConnector.latest_round_condition('R')}
                ORDER BY asset_id ASC, vuln_code ASC
            """)
            rows_by_asset = {}
            for row in cursor.fetchall():
                rows_by_asset.setdefault(row[0], []).append(row[1:])

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            written_files = []

            for asset_id, ip, hostname, os_type in assets:
                rows = rows_by_asset.get(asset_id)
                if not rows:
                    continue

                content, real_host = self._render_host_block(ip, hostname, os_type, rows)

                # [매크로 호환] 대상 워크북(UNIX/WINDOWS/PC/DBMS)들은 파일명 태그가 아니라
                # 본문의 [U-xx]/[W-xx]/[PC-xx]/[D-xx] 코드로 필터링하므로 태그는 구분용일 뿐이다
                tag = "WINDOWS" if "windows" in (os_type or "").lower() else "UNIX"
                safe_host = self._sanitize_filename(real_host)
                filename = f"[{tag}]{safe_host}_{timestamp}.txt"
                filepath = os.path.join(self.output_dir, filename)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                written_files.append(filepath)

            if not written_files:
                raise Exception("내보낼 스캔 결과가 없습니다.")
            return written_files
        finally:
            conn.close()

    def _render_host_block(self, ip, hostname, os_type, rows):
        discovery_rows = []
        audit_rows = []
        sys_detail = {}

        for vuln_code, kisa_code, name, status, detail, raw_output, remediation, waived, operator, risk_level in rows:
            if self._is_system_detail_code(vuln_code):
                sys_detail[vuln_code] = raw_output
            elif self._is_discovery_code(vuln_code):
                discovery_rows.append((vuln_code, kisa_code, name, status, detail, raw_output, remediation, waived))
            else:
                audit_rows.append((vuln_code, kisa_code, name, status, detail, raw_output, remediation, waived, operator, risk_level))

        buf = []
        fallback_host = hostname if hostname and hostname != "-" else ip
        real_host = self._extract_real_hostname(sys_detail.get("SYS-OS_INFO", ""), fallback_host)
        display_host = real_host

        buf.append("** [주요정보통신기반시설] ")
        buf.append("")
        buf.append(f"** 해당 파일은 {display_host}의 스크립트 결과 파일 입니다. ")
        buf.append("")
        buf.append("** 담당자에게 전달해주시기 바랍니다. ")
        buf.append("")
        buf.append(f"---------[ {display_host} Result - {ip} ]-------")
        buf.append("")
        buf.append(f"        1.   OS version is \"{os_type or 'Unknown'}\" ")
        buf.append("")
        buf.append(f"        2.   Hostname is \"{display_host}\" ")
        buf.append("")
        buf.append(f"        3.   Today is \"{datetime.now().strftime('%Y-%m-%d %p %I:%M')}\" ")
        buf.append("")
        buf.append("----------------------------------------------------")

        # ---------------- 1) Discovery ----------------
        buf.append("")
        buf.append("                     Discovery (자산 탐지 및 포트 스캔) ")
        buf.append("")
        buf.append("----------------------------------------------------")
        if discovery_rows:
            for vuln_code, kisa_code, name, status, detail, raw_output, remediation, waived in discovery_rows:
                buf.append("")
                buf.append(f"[{vuln_code}] {name} ")
                buf.append(f"현황 : {detail} ")
                buf.append("---------- ")
                buf.append(f"(증적) {raw_output if raw_output else '-'} ")
        else:
            buf.append("")
            buf.append("(탐지된 포트 정보 없음) ")

        # ---------------- 2) Audit ----------------
        buf.append("")
        buf.append("----------------------------------------------------")
        buf.append("                     Audit (KISA 취약점 진단) ")
        buf.append("----------------------------------------------------")

        grouped = {}
        order = []
        for vuln_code, kisa_code, name, status, detail, raw_output, remediation, waived, operator, risk_level in audit_rows:
            rule = self.rule_lookup.get(vuln_code, {})
            category = rule.get('category', '기타')
            if category not in grouped:
                grouped[category] = []
                order.append(category)

            # [버그 수정] 라이선스 등급별 차등 - ExcelGenerator/PDFGenerator와 동일한
            # 규칙을 여기서도 적용한다(evidence_level="vuln_only"면 취약/부분만족만
            # 증적 노출, remediation_level로 조치방안 노출 범위 제한).
            if self.evidence_level == "vuln_only" and status not in ("VULNERABLE", "PARTIAL"):
                raw_output = "(상세 증적은 Professional 이상 등급에서 제공됩니다)"
            if self.remediation_level == "none":
                remediation = "(조치 방안은 Professional 이상 등급에서 제공됩니다)"
            elif self.remediation_level == "partial" and risk_level not in ("Critical", "High"):
                remediation = "(중요도 상/중 항목만 제공됩니다. 전체 제공은 Enterprise 등급)"

            grouped[category].append({
                "code": kisa_code or vuln_code,
                "name": name,
                "status": status,
                "detail": detail,
                "raw_output": raw_output,
                "remediation": remediation,
                # [수동/육안 점검] manual_audit_dialog.py가 operator="수동입력"으로 저장한 건은
                # 실제로 이 명령이 실행된 적이 없다 - 룰의 자동진단용 command를 그대로 보여주면
                # 마치 그 명령을 돌려서 나온 결과처럼 오인될 수 있어 별도 표기로 구분한다.
                "command": rule.get('command', ''),
                "is_manual": (operator == "수동입력"),
                "waived": waived,
            })

        for idx, category in enumerate(order, 1):
            buf.append("")
            buf.append("-------------- ")
            buf.append(f" {idx}. {category}  ")
            buf.append("-------------- ")
            for item in grouped[category]:
                buf.append("")
                buf.append(f"[{item['code']}] {item['name']} ")
                buf.append(f"권고 : {item['remediation'] or '-'} ")
                buf.append("[START] ")
                # [매크로 호환] "전체 진단 현황_붙여넣기" 집계 매크로(HideonLog/HideonLogF)는
                # 이 블록 안에서 [RESULT]/[REASON] 태그가 붙은 줄을 찾아 #숨김.RawData의
                # "점검 결과"/"진단 코멘트" 컬럼을 자동 채운다. 태그가 없으면 두 컬럼이 항상
                # 빈칸으로 남아 담당자가 전부 수동 입력해야 하므로 반드시 포함해야 한다.
                # 값은 각 영역 결과보고서(별첨02 등)의 실제 수식이 비교하는 문자열과 정확히
                # 일치해야 한다: "양호"/"취약"/"부분만족"/"N/A" (영문 그대로).
                result_val = STATUS_TO_RESULT.get(item['status'], "N/A")
                reason_val = re.sub(r'\s+', ' ', (item['detail'] or "")).strip()
                buf.append(f"[RESULT] {result_val} ")
                buf.append(f"[REASON] {reason_val} ")
                buf.append("현황 ")
                waived_note = " (예외 처리됨)" if item['waived'] == 1 else ""
                # [수정] detail(judge_rule의 _single_condition_result가 만드는
                # "취약 설정 발견: {full_output[:40]}..." 등)이 원본 명령 출력을 그대로
                # 잘라 붙이므로, 그 40자 안에 줄바꿈이 섞여 있으면 이 줄이 여러 줄로
                # 쪼개져 출력된다. [REASON] 줄(위 reason_val)과 동일하게 공백으로
                # 정규화해서 항상 한 줄로 유지 - 교차검증 파서를 포함해 "현황 :" 줄을
                # 단일 라인으로 가정하는 모든 소비자가 깨지지 않도록 한다.
                status_val = re.sub(r'\s+', ' ', (item['detail'] or "")).strip()
                buf.append(f": {status_val}{waived_note} ")
                buf.append("---------- ")
                if item['is_manual']:
                    buf.append("(육안 점검으로 인한 별첨 증적 처리) ")
                elif item['command']:
                    buf.append(f"(CMD) {item['command']} ")
                buf.append(f"{item['raw_output'] if item['raw_output'] else '-'} ")
                buf.append("[END] ")

        # ---------------- 3) SYSTEM Detail ----------------
        buf.append("")
        buf.append("---------------------------------------------------- ")
        buf.append("")
        buf.append("                     SYSTEM Detail ")
        buf.append("")
        buf.append("---------------------------------------------------- ")
        for code, label in SYS_DETAIL_LABELS:
            buf.append("")
            buf.append(f"                [{label}] ")
            buf.append("")
            content = sys_detail.get(code, "").strip()
            buf.append(content if content else "(수집된 정보 없음)")

        return "\n".join(buf), real_host
