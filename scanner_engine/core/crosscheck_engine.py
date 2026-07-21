# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[교차검증 모드] 파싱된 컨설턴트 TXT 레코드를 Z-VulnScan 룰셋으로 재판정하고,
컨설턴트 원 판정과 대조(Diff)한다.

이 모드는 scanner_engine/core/ 의 실제 접속/스캔 로직(ssh_inspector 등)을
전혀 호출하지 않는다 - 오직 이미 확보된 증적 텍스트(raw_output)만 입력으로 쓰고,
판정은 순수 함수 utils.rule_judge.judge_rule()만 재사용한다. 교차검증 결과는
기존 스캔 이력 DB(TBL_SCAN_RESULT)에 쓰지 않는다 (scan_round/회차비교 로직에
영향을 주지 않기 위함) - 이 모듈은 DB에 전혀 접근하지 않는다.
"""
import os
import sys
import json

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from output.text_report import RULE_FILES, STATUS_TO_RESULT  # noqa: E402
from utils.rule_judge import judge_rule  # noqa: E402
from utils.logger import AppLogger  # noqa: E402

# D-xx 코드는 mysql_rules.json/postgresql_rules.json이 공유한다(이름도 동일, command만 다름 -
# database_inspector.py L197-199 주석 참고). 두 파일이 모두 대상이 될 수 있는 접두어 없는
# "bare code" 룰셋 목록.
_SHARED_CODE_RULESETS = {"mysql_rules.json", "postgresql_rules.json"}

MISSING_CODE_LIMITATION_NOTE = (
    "'누락 항목'은 TXT에 실제로 등장한 코드 접두어(룰셋)를 기준으로만 계산됩니다. "
    "특정 룰셋 카테고리(예: DB 점검)가 통째로 TXT에 없는 경우, 그 룰셋 전체가 "
    "누락되었다는 사실 자체는 이 기능으로 감지할 수 없습니다 - 호스트별 예상 점검 "
    "범위는 별도로 수동 확인해야 합니다."
)


def get_rules_dir():
    """text_report.py.__init__()과 동일한 경로 계산(frozen/_MEIPASS 분기 포함) -
    PyInstaller 빌드에서도 rules/ 를 정확히 찾기 위함."""
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(parent_dir)  # parent_dir=scanner_engine/, 그 부모가 프로젝트 루트

    rules_dir = os.path.join(base_path, 'rules')
    if hasattr(sys, '_MEIPASS') and not os.path.isdir(rules_dir):
        rules_dir = os.path.join(sys._MEIPASS, 'rules')
    return rules_dir


def load_rulesets(rules_dir=None):
    """{ruleset_filename: [rule_dict, ...]} 형태로 rules/*.json 원본을 로드한다."""
    rules_dir = rules_dir or get_rules_dir()
    rulesets = {}
    for filename in RULE_FILES:
        path = os.path.join(rules_dir, filename)
        if not os.path.exists(path):
            continue
        try:
            with open(path, 'r', encoding='utf-8') as f:
                rulesets[filename] = json.load(f)
        except Exception as e:
            AppLogger.log_error(f"[CrossCheck] Failed to load {filename}", e)
    return rulesets


def build_code_index(rulesets):
    """bare code -> [(ruleset_file, rule_dict), ...]. U-/W-/PC-/WEB-는 1개,
    D-xx(mysql/postgresql 공유)만 2개가 된다."""
    index = {}
    for filename, rules in rulesets.items():
        for rule in rules:
            code = rule.get('code')
            if not code:
                continue
            index.setdefault(code, []).append((filename, rule))
    return index


def _normalize_cmd(cmd):
    return " ".join((cmd or "").split())


def resolve_rule(record, code_index):
    """반환: (rule_dict|None, ruleset_file|None, ambiguous: bool)"""
    candidates = code_index.get(record["code"])
    if not candidates:
        return None, None, False
    if len(candidates) == 1:
        filename, rule = candidates[0]
        return rule, filename, False

    # 후보 2개 이상 (D-xx) - (CMD) 줄과 각 후보 rule['command']를 비교해 좁힌다.
    record_cmd = _normalize_cmd(record.get("command"))
    if not record_cmd:
        return None, None, True

    exact_matches = [c for c in candidates if _normalize_cmd(c[1].get('command')) == record_cmd]
    if len(exact_matches) == 1:
        filename, rule = exact_matches[0]
        return rule, filename, False

    partial_matches = [
        c for c in candidates
        if record_cmd in _normalize_cmd(c[1].get('command')) or _normalize_cmd(c[1].get('command')) in record_cmd
    ]
    if len(partial_matches) == 1:
        filename, rule = partial_matches[0]
        return rule, filename, False

    return None, None, True


def rejudge_record(record, code_index):
    """resolve_rule 후 judge_rule()로 재판정한다.

    execute_fn=None을 고정으로 쓴다: TXT에는 룰 최상위 command 실행 결과 하나만
    남아있고, criteria(세부기준) 각각의 개별 증적은 원래부터 저장되지 않으므로
    (judge_rule 자체가 execute_fn 없이는 세부기준마다 이 하나의 full_output을
    공유하도록 되어 있음) 여기서 나오는 결과는 criteria형 룰에 한해 근사치다.
    """
    rule, ruleset_file, ambiguous = resolve_rule(record, code_index)
    result = {
        "record": record,
        "rule_found": rule is not None,
        "ruleset_file": ruleset_file,
        "ruleset_ambiguous": ambiguous,
        "rejudged_status": None,
        "rejudged_result": None,
        "rejudged_detail": None,
        "has_criteria": False,
        "approx_note": None,
        "engine_error": None,
    }
    if rule is None:
        return result

    result["has_criteria"] = bool(rule.get("criteria"))
    if result["has_criteria"]:
        result["approx_note"] = (
            "세부기준별 개별 증적 없음 (근사치 - TXT의 증적은 존재하지만 이 룰 최상위 "
            "명령(CMD) 결과 하나뿐이라, 세부기준마다 원래 실행해야 할 별도 명령 대신 "
            "이 공통 출력을 그대로 재사용합니다. 그 출력에 세부기준의 safe/vulnerable_keyword가 "
            "문맥과 무관하게 우연히 포함돼 있으면 - 예: 주석 처리된 설정 줄도 통과 - "
            "오탐이 발생할 수 있습니다)"
        )

    try:
        status, detail = judge_rule(rule, record.get("raw_output", ""), execute_fn=None)
        result["rejudged_status"] = status
        result["rejudged_detail"] = detail
        result["rejudged_result"] = STATUS_TO_RESULT.get(status, "N/A")
    except Exception as e:
        result["engine_error"] = str(e)
        AppLogger.log_error(f"[CrossCheck] judge_rule failed for {record.get('code')}", e)

    return result


def diff_records(rejudge_results):
    """RejudgeResult 목록 -> DiffEntry 목록"""
    entries = []
    for r in rejudge_results:
        record = r["record"]

        if not record.get("code"):
            classification = "NO_KISA_CODE"
            detail_note = record.get("parse_warning") or "컨설턴트 항목에 매핑된 KISA 코드가 없습니다(주통 해당사항 없음 등)."
        elif not record.get("parse_ok", True):
            classification = "PARSE_ERROR"
            detail_note = record.get("parse_warning") or "파싱 실패"
        elif r["ruleset_ambiguous"]:
            classification = "AMBIGUOUS_RULESET"
            detail_note = "동일 코드가 여러 룰셋(MySQL/PostgreSQL)에 존재하고 (CMD)로도 구분할 수 없습니다."
        elif not r["rule_found"]:
            classification = "MISSING_IN_RULESET"
            detail_note = "현재 룰셋 파일에 이 코드가 존재하지 않습니다."
        elif r["engine_error"]:
            classification = "PARSE_ERROR"
            detail_note = f"재판정 엔진 오류: {r['engine_error']}"
        elif not record.get("consultant_result"):
            classification = "NO_CONSULTANT_RESULT"
            detail_note = f"컨설턴트 쪽에 결과값 자체가 없습니다(수동 확인 항목 등). Z-VulnScan 재판정: {r['rejudged_result']}"
        elif record.get("consultant_result") == "확인":
            # [실제 컨설턴트 포맷] 컨설턴트 스크립트 자신도 자동 판정을 보류하고 "확인"으로
            # 남긴 항목 - Z-VulnScan 재판정과 다르다고 해서 "불일치"로 단정할 근거가 컨설턴트
            # 쪽에도 없으므로, 일반 MISMATCH와 구분해 별도로 표시한다.
            classification = "CONSULTANT_UNCERTAIN"
            detail_note = f"컨설턴트도 자동판정 보류(확인 필요) / Z-VulnScan 재판정: {r['rejudged_result']}"
        elif r["has_criteria"]:
            # [실측 확인됨] criteria(세부기준)형 룰은 execute_fn 없이 재판정하면 모든
            # 세부기준이 동일한 최상위 raw_output 하나를 공유한다. 예: U-06의
            # safe_keyword="wheel"은 grep 결과에 "pam_wheel.so"라는 문자열만 있어도
            # (실제로 비활성 상태여도) 우연히 매칭돼 버려 원래 "취약"이던 항목이
            # "부분만족"으로 잘못 재판정되는 사례가 실측으로 확인됐다. 그래서 MATCH가
            # 나와도 우연의 일치일 수 있고, MISMATCH가 나와도 실제 불일치가 아닐 수
            # 있어 자동 대조 자체가 신뢰할 수 없다 - MATCH/MISMATCH로 단정하지 않고
            # 항상 "수동 검증 필요"로 분류한다.
            classification = "MANUAL_VERIFICATION_NEEDED"
            detail_note = (
                f"세부기준형 룰(criteria) - 자동 재판정은 근사치라 신뢰할 수 없어 수동 확인 필요. "
                f"컨설턴트: {record.get('consultant_result')} / Z-VulnScan 재판정: {r['rejudged_result']}"
            )
        elif record.get("consultant_result") == r["rejudged_result"]:
            classification = "MATCH"
            detail_note = "일치"
        else:
            classification = "MISMATCH"
            detail_note = f"컨설턴트: {record.get('consultant_result')} / 재판정: {r['rejudged_result']}"

        entries.append({
            "host": record.get("host"), "ip": record.get("ip"),
            "code": record.get("code"), "name": record.get("name"),
            "category": record.get("category"),
            "consultant_result": record.get("consultant_result"),
            "rejudged_result": r["rejudged_result"],
            "classification": classification,
            "approx_note": r["approx_note"],
            "detail_note": detail_note,
        })
    return entries


def _prefix_of(code):
    """'U-01' -> 'U-', 'WEB-05' -> 'WEB-', 'PC-03' -> 'PC-' 등"""
    if '-' in code:
        return code.rsplit('-', 1)[0] + '-'
    return code


def find_missing_codes(records, rulesets, rejudge_results=None):
    """호스트별로 TXT에 실제 등장한 코드의 접두어만으로 대상 룰셋을 한정하고,
    '그 룰셋 전체 코드 - 실제 파싱된 코드'로 누락을 계산한다.

    한계: MISSING_CODE_LIMITATION_NOTE 참고 - 완전히 빠진 룰셋 카테고리 자체는
    감지하지 못한다.
    """
    resolved_ruleset_by_code = {}
    if rejudge_results:
        for r in rejudge_results:
            if r["ruleset_file"]:
                resolved_ruleset_by_code[r["record"]["code"]] = r["ruleset_file"]

    by_host = {}
    for rec in records:
        # [실제 컨설턴트 포맷] 코드가 아예 없는 항목(주통 해당사항 없음 등)은 어떤 룰셋과도
        # 매칭할 수 없으므로 누락 계산에서 제외 - 포함하면 _prefix_of(None)에서 예외 발생.
        if not rec.get("parse_ok", True) or not rec.get("code"):
            continue
        by_host.setdefault((rec["host"], rec["ip"]), []).append(rec)

    missing = []
    for (host, ip), host_records in by_host.items():
        seen_codes = {r["code"] for r in host_records}

        target_rulesets = set()
        for rec in host_records:
            code = rec["code"]
            if code in resolved_ruleset_by_code:
                target_rulesets.add(resolved_ruleset_by_code[code])
                continue
            prefix = _prefix_of(code)
            for filename, rules in rulesets.items():
                if filename in _SHARED_CODE_RULESETS and code not in resolved_ruleset_by_code:
                    continue  # D-xx인데 어느 쪽인지 못 밝혔으면 누락 계산 대상에서 제외(오탐 방지)
                if any(_prefix_of(rule.get('code', '')) == prefix for rule in rules):
                    target_rulesets.add(filename)

        for filename in target_rulesets:
            for rule in rulesets.get(filename, []):
                code = rule.get('code')
                if code and code not in seen_codes:
                    missing.append({
                        "host": host, "ip": ip, "ruleset_file": filename,
                        "code": code, "name": rule.get('name', code),
                    })

    return missing


def run_cross_check(filepaths, rules_dir=None):
    """엔드투엔드 오케스트레이션. 파싱은 별도 모듈(crosscheck_parser)이 담당하므로
    호출부(GUI)가 먼저 parse_files()를 실행한 뒤 그 결과를 넘긴다 - 이 함수는
    '레코드 이후' 단계(룰 로딩~재판정~Diff)만 책임진다."""
    from core.crosscheck_parser import parse_files

    summary = {
        "total": 0, "match": 0, "mismatch": 0, "missing_in_ruleset": 0,
        "ambiguous": 0, "parse_error": 0, "approx_count": 0, "missing_codes": 0,
        "no_kisa_code": 0, "no_consultant_result": 0, "consultant_uncertain": 0,
        "manual_verification_needed": 0,
    }
    result = {
        "records": [], "parse_errors": [], "diff_entries": [], "missing_entries": [],
        "failed_files": [], "summary": summary,
    }

    try:
        records, warning_records, failed_files = parse_files(filepaths)
        result["records"] = records
        result["parse_errors"] = warning_records
        result["failed_files"] = failed_files

        rulesets = load_rulesets(rules_dir)
        code_index = build_code_index(rulesets)

        rejudge_results = [rejudge_record(r, code_index) for r in records if r.get("parse_ok", True)]
        # 파싱 실패 레코드도 diff 테이블에는 PARSE_ERROR로 노출해야 하므로 빈 RejudgeResult로 채워 합류
        for r in records:
            if not r.get("parse_ok", True):
                rejudge_results.append({
                    "record": r, "rule_found": False, "ruleset_file": None,
                    "ruleset_ambiguous": False, "rejudged_status": None,
                    "rejudged_result": None, "rejudged_detail": None,
                    "has_criteria": False, "approx_note": None, "engine_error": None,
                })

        diff_entries = diff_records(rejudge_results)
        missing_entries = find_missing_codes(records, rulesets, rejudge_results)

        result["diff_entries"] = diff_entries
        result["missing_entries"] = missing_entries

        summary["total"] = len(diff_entries)
        for entry in diff_entries:
            key = {
                "MATCH": "match", "MISMATCH": "mismatch",
                "MISSING_IN_RULESET": "missing_in_ruleset",
                "AMBIGUOUS_RULESET": "ambiguous", "PARSE_ERROR": "parse_error",
                "NO_KISA_CODE": "no_kisa_code",
                "NO_CONSULTANT_RESULT": "no_consultant_result",
                "CONSULTANT_UNCERTAIN": "consultant_uncertain",
                "MANUAL_VERIFICATION_NEEDED": "manual_verification_needed",
            }.get(entry["classification"])
            if key:
                summary[key] += 1
            if entry["approx_note"]:
                summary["approx_count"] += 1
        summary["missing_codes"] = len(missing_entries)

    except Exception as e:
        AppLogger.log_error("[CrossCheck] run_cross_check failed", e)
        result["engine_error"] = str(e)

    return result


# ----------------------------------------------------------------------
# [DB 직접대조 모드] 컨설턴트 증적을 우리 룰 키워드로 재판정하는 방식은, 서로 다른
# 스크립트가 만든 증적 문장이 우리 safe_keyword("OK" 등)/vulnerable_keyword와
# 우연히도 일치할 수가 없어서 실측상 신뢰도가 매우 낮다는 게 확인됐다(예: safe_keyword가
# "OK"인 룰은 컨설턴트의 한국어 서술형 증적에 "OK"라는 글자가 나올 리 없어 항상
# 취약으로 오판정). 이 모드는 재판정을 아예 하지 않고, Z-VulnScan이 같은 호스트를
# 실제로 스캔해 DB에 이미 저장해 둔 "최종 판정값"을 코드 단위로 직접 대조한다 -
# 키워드 매칭 문제 자체를 우회한다.
#
# 기존 run_cross_check()/rejudge_record() 경로는 "DB 미접근" 원칙을 유지해야 하므로
# (독립 오프라인 재판정이 이 기능의 원래 취지), DB 접근은 이 섹션의 함수들에만
# 국한한다 - 호출부(GUI)가 사용자에게 명시적으로 "DB 직접대조" 모드를 선택하게 한
# 경우에만 여기로 진입한다.
# ----------------------------------------------------------------------

def get_latest_db_results(db, asset_id):
    """asset_id의 최신 회차(scan_round) 결과를 {code: status} 형태로 반환한다.
    code는 kisa_code가 있으면 그걸(컨설턴트 TXT의 코드와 동일 체계), 없으면 vuln_code를 쓴다."""
    import sqlite3
    conn = sqlite3.connect(db.db_path, check_same_thread=False)
    cursor = conn.cursor()
    try:
        cursor.execute(f"""
            SELECT vuln_code, kisa_code, status
            FROM TBL_SCAN_RESULT R
            WHERE asset_id = ?
            AND {db.latest_round_condition('R')}
        """, (asset_id,))
        rows = cursor.fetchall()
    finally:
        conn.close()

    results = {}
    for vuln_code, kisa_code, status in rows:
        key = kisa_code or vuln_code
        if key:
            results[key] = status
    return results


def diff_records_db(records, db):
    """레코드를 Z-VulnScan DB의 실제 스캔 결과와 코드 단위로 직접 대조한다
    (재판정 없음 - 키워드 매칭 신뢰도 문제를 우회)."""
    from output.text_report import STATUS_TO_RESULT

    entries = []
    db_results_by_ip = {}

    for record in records:
        code = record.get("code")
        ip = record.get("ip")

        if not code:
            classification = "NO_KISA_CODE"
            detail_note = record.get("parse_warning") or "컨설턴트 항목에 매핑된 KISA 코드가 없습니다(주통 해당사항 없음 등)."
            z_result = None
        elif not record.get("parse_ok", True):
            classification = "PARSE_ERROR"
            detail_note = record.get("parse_warning") or "파싱 실패"
            z_result = None
        else:
            if ip not in db_results_by_ip:
                asset_id = db.get_asset_id(ip)
                db_results_by_ip[ip] = get_latest_db_results(db, asset_id) if asset_id else None
            code_map = db_results_by_ip[ip]

            if code_map is None:
                classification = "DB_NO_ASSET"
                detail_note = f"Z-VulnScan DB에 이 IP({ip})로 스캔된 자산이 없습니다."
                z_result = None
            elif code not in code_map:
                classification = "DB_NO_SCAN_RESULT"
                detail_note = "Z-VulnScan이 이 호스트에서 이 코드를 스캔한 이력이 없습니다."
                z_result = None
            else:
                z_status = code_map[code]
                z_result = STATUS_TO_RESULT.get(z_status, "N/A")
                consultant_result = record.get("consultant_result")
                if not consultant_result:
                    classification = "NO_CONSULTANT_RESULT"
                    detail_note = f"컨설턴트 쪽에 결과값이 없습니다. Z-VulnScan(DB) 실제 판정: {z_result}"
                elif consultant_result == "확인":
                    classification = "CONSULTANT_UNCERTAIN"
                    detail_note = f"컨설턴트도 자동판정 보류(확인 필요) / Z-VulnScan(DB) 실제 판정: {z_result}"
                elif consultant_result == z_result:
                    classification = "MATCH"
                    detail_note = "일치 (Z-VulnScan 실제 스캔 결과 기준)"
                else:
                    classification = "MISMATCH"
                    detail_note = f"컨설턴트: {consultant_result} / Z-VulnScan(DB) 실제 판정: {z_result}"

        entries.append({
            "host": record.get("host"), "ip": record.get("ip"),
            "code": code, "name": record.get("name"),
            "category": record.get("category"),
            "consultant_result": record.get("consultant_result"),
            "rejudged_result": z_result,
            "classification": classification,
            "approx_note": None,  # DB 직접대조는 근사치가 아니라 실제 판정값이므로 항상 없음
            "detail_note": detail_note,
        })

    return entries


def run_cross_check_db(filepaths, db):
    """DB 직접대조 모드 엔드투엔드 오케스트레이션. run_cross_check()과 달리 룰 재판정을
    하지 않고, Z-VulnScan이 실제로 스캔해 DB에 저장한 판정값과 코드 단위로 비교한다."""
    from core.crosscheck_parser import parse_files

    summary = {
        "total": 0, "match": 0, "mismatch": 0, "no_kisa_code": 0, "parse_error": 0,
        "no_consultant_result": 0, "consultant_uncertain": 0,
        "db_no_asset": 0, "db_no_scan_result": 0,
    }
    result = {
        "records": [], "parse_errors": [], "diff_entries": [], "missing_entries": [],
        "failed_files": [], "summary": summary,
    }

    try:
        records, warning_records, failed_files = parse_files(filepaths)
        result["records"] = records
        result["parse_errors"] = warning_records
        result["failed_files"] = failed_files

        diff_entries = diff_records_db(records, db)
        result["diff_entries"] = diff_entries

        summary["total"] = len(diff_entries)
        for entry in diff_entries:
            key = {
                "MATCH": "match", "MISMATCH": "mismatch",
                "NO_KISA_CODE": "no_kisa_code", "PARSE_ERROR": "parse_error",
                "NO_CONSULTANT_RESULT": "no_consultant_result",
                "CONSULTANT_UNCERTAIN": "consultant_uncertain",
                "DB_NO_ASSET": "db_no_asset", "DB_NO_SCAN_RESULT": "db_no_scan_result",
            }.get(entry["classification"])
            if key:
                summary[key] += 1

    except Exception as e:
        AppLogger.log_error("[CrossCheck] run_cross_check_db failed", e)
        result["engine_error"] = str(e)

    return result
