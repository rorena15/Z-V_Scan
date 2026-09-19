# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import re

# 명령 실행 결과에 이런 문구가 있으면 "그 기능/서비스 자체가 대상 시스템에 없다"는 신호로 보고
# 취약/양호가 아니라 "해당없음"으로 분류한다.
NA_SIGNALS = [
    "command not found", "not found", "No such file or directory",
    "찾을 수 없습니다", "존재하지 않음", "not recognized as", "인식되지 않습니다",
    "레지스트리 키 또는 값이 존재하지 않음", "Cannot find",
    # 네트워크 장비 CLI가 그 명령/기능 자체를 지원하지 않을 때의 응답(Cisco IOS 계열)
    "Invalid input detected",
    # [영문 로케일] "reg query"가 키/값을 못 찾을 때의 실제 영문 메시지는
    # "ERROR: The system was unable to find the specified registry key or
    # value."이다 - "not found"/"Cannot find"와 문구가 달라 기존 목록(한국어 로케일
    # 문구만 있음)에 안 걸렸었다. reg query 기반 룰 다수(W-05/07/12/26/48/50,
    # PC-18 등)는 값이 없는 게 곧 안전한 기본값이라 최종 판정(SAFE) 자체는 이 신호가
    # 없어도 우연히 맞았지만, "점검했는데 문제없음"과 "애초에 해당 레지스트리 키가
    # 없어서 확인 자체가 안 됨"을 구분 못 하고 전자로 표시되는 라벨 부정확성이 있었다.
    # 이 신호를 추가하면 그런 경우 정직하게 NA(해당없음)로 분류된다.
    "unable to find the specified registry key or value",
]

# [권한 부족 감지] 계정에 su/sudo 권한이 없어 root 전용 파일(/etc/shadow 등) 접근이
# 거부된 경우의 신호. 이전엔 이 신호가 NA_SIGNALS에 없어서, 권한 부족으로 명령이
# 실패해도 "해당없음"/"수동확인"으로 안 빠지고 룰 구조(vulnerable_keyword냐
# safe_keyword냐)에 따라 우연히 SAFE 또는 VULNERABLE로 잘못 판정되는 문제가 실제로
# 있었다(예: U-13이 /etc/shadow를 못 읽으면 grep 실패를 "매치 없음"과 똑같이 취급해
# 거짓 양호로 판정). 사용자 결정: 권한 부족 시 "취약"으로 집계하되(누락 방지) 사유에
# "수동 확인 필요"를 명시해 사람이 반드시 재검토하게 한다.
PERMISSION_DENIED_SIGNALS = [
    "Permission denied", "permission denied",
    "권한이 거부되었습니다", "허가 거부", "액세스가 거부되었습니다", "Access is denied",
    "Operation not permitted",
]


# [값 부재 = 취약, 2026-09] reg query가 "그 키/값이 없다"고 답하는 문구만 따로 모은 목록(NA_SIGNALS의 부분집합).
# NA_SIGNALS는 이 문구를 "대상 기능/서비스가 없다"로 보고 해당없음(NA)으로 분류하는데, 어떤 룰은 "명시적으로 그
# 값이 설정돼 있어야 양호"라 값이 없다는 것 자체가 곧 취약(미설정)이다(예: PC-03 - 룰 설명에 "키 부재/기타 값은
# 취약"이라 명시). 그런 룰은 JSON에 "missing_is_vulnerable": true를 두면 이 문구를 NA가 아니라 취약으로 판정한다.
# (SNMP처럼 서비스가 아예 없으면 키도 없는 룰은 플래그를 두지 않아 그대로 NA)
REGISTRY_MISSING_SIGNALS = [
    "레지스트리 키 또는 값을 찾을 수 없습니다", "레지스트리 키 또는 값이 존재하지 않음",
    "unable to find the specified registry key or value",
]


def _is_registry_missing(output_stripped):
    return bool(output_stripped) and any(sig in output_stripped for sig in REGISTRY_MISSING_SIGNALS)


def _is_na(output_stripped):
    return bool(output_stripped) and any(sig in output_stripped for sig in NA_SIGNALS)


def _is_permission_denied(output_stripped):
    return bool(output_stripped) and any(sig in output_stripped for sig in PERMISSION_DENIED_SIGNALS)


def _regex_found(pattern, text):
    # 네트워크 장비 설정처럼 줄 단위 텍스트를 다루는 룰용 - 대소문자 무시, ^/$는 줄 경계
    return re.search(pattern, text or "", re.IGNORECASE | re.MULTILINE) is not None


def has_condition(item):
    return any(k in item for k in ("vulnerable_keyword", "vulnerable_regex", "safe_keyword", "safe_regex"))


def _single_condition_result(rule, full_output):
    """단일 조건 판정: vulnerable_keyword/vulnerable_regex(발견되면 취약) 또는 safe_keyword/safe_regex(없으면 취약)"""
    if "vulnerable_keyword" in rule or "vulnerable_regex" in rule:
        hit = ("vulnerable_keyword" in rule and rule["vulnerable_keyword"] in full_output) or               ("vulnerable_regex" in rule and _regex_found(rule["vulnerable_regex"], full_output))
        if hit:
            return "VULNERABLE", f"취약 설정 발견: {full_output.strip()[:40]}..."
        return "SAFE", "양호 (점검 완료)"
    elif "safe_keyword" in rule or "safe_regex" in rule:
        ok = bool(full_output) and (
            ("safe_keyword" in rule and rule["safe_keyword"] in full_output) or
            ("safe_regex" in rule and _regex_found(rule["safe_regex"], full_output)))
        if not ok:
            if "safe_keyword" in rule:
                return "VULNERABLE", f"필수 설정 미흡: {rule['safe_keyword']} 누락"
            return "VULNERABLE", f"필수 설정 미흡: 기준에 맞는 설정이 없음 (권장: {rule.get('remediation', '')})"
        return "SAFE", "양호 (점검 완료)"
    else:
        return "MANUAL", "수동 검토 필요 (증적 확인)"


_CLI_REJECTED = ("Invalid input", "Incomplete command", "Ambiguous command", "% Unknown command")


def _judge_checks(checks, execute_fn):
    tried = []
    for ck in checks:
        cmd = ck["command"]
        tried.append(cmd)
        out = execute_fn(cmd) if execute_fn else None
        if out is None:
            continue
        text = out.strip()
        if not text or any(sig in text for sig in _CLI_REJECTED) or _is_permission_denied(text):
            continue
        if "vulnerable_regex" in ck and _regex_found(ck["vulnerable_regex"], text):
            return "VULNERABLE", f"취약 설정 발견 (근거: {cmd}): {text[:40]}"
        if "safe_regex" in ck and _regex_found(ck["safe_regex"], text):
            return "SAFE", f"양호 (근거: {cmd})"
    return "MANUAL", "판정에 필요한 출력을 얻지 못해 수동 확인 필요 (다음 중 하나의 출력 필요: " + " / ".join(tried) + ")"


def judge_rule(rule, full_output, execute_fn=None):
    """
    룰 하나를 판정한다.

    - rule에 criteria(세부기준 리스트)가 있으면: 각 기준을 개별 평가해 몇 개를 충족했는지로
      양호(전부 충족)/부분만족(일부 충족)/취약(전부 미충족)을 판정한다.
      criteria의 각 항목은 자체 command를 가질 수 있고(없으면 rule의 기본 full_output 재사용),
      execute_fn(command)을 통해 실행한다.
    - criteria가 없으면 기존처럼 단일 vulnerable_keyword/safe_keyword 조건으로 판정한다.
    - 두 경우 모두, 출력에 "기능/서비스 없음" 신호가 있으면 해당없음으로 우선 분류한다.

    Returns: (status, detail) - status는 "SAFE"|"VULNERABLE"|"PARTIAL"|"MANUAL"|"NA"
    """
    # [판정 정확도] 인스펙터가 "명령/쿼리 실행 자체가 실패했다"는 뜻으로 명시적으로
    # None을 반환하는 경우(예: DatabaseInspector.execute_query()가 권한 부족 등으로
    # 예외 발생 시) - "결과가 없어서 안전"과 절대 혼동하면 안 되므로 여기서 먼저
    # 걸러 수동확인으로 돌린다. 빈 문자열("")은 "정상 실행됐지만 결과 0건"이라는
    # 뜻이라 기존처럼 그대로 판정 로직을 탄다.
    # 벤더/플랫폼이 그 기능 자체를 제공하지 않는 항목(예: Junos에는 identd가 없음)은 명령 결과와 무관하게 해당없음
    if rule.get("not_applicable_reason"):
        return "NA", f"해당없음 ({rule['not_applicable_reason']})"

    # 근거가 여러 곳인 룰(상태 명령 -> show running-config all -> running-config 명시 줄 순): 결론을 낼 수 있는
    # 첫 근거로 판정하고, 어느 근거로도 결론을 못 내면 양호로 추정하지 않고 수동확인으로 남긴다.
    if rule.get("checks"):
        return _judge_checks(rule["checks"], execute_fn)

    if full_output is None:
        return "MANUAL", "점검 명령/쿼리 실행 실패(권한 부족 또는 연결 문제로 추정) - 수동 확인 필요"

    full_output = full_output or ""
    stripped = full_output.strip()

    # 설정 조회 결과가 비어 있는 것 자체가 의미인 룰(예: SNMP 설정이 하나도 없음 = 미사용)
    empty_status = rule.get("empty_status")
    if empty_status and not stripped:
        if empty_status == "NA":
            return "NA", "해당없음 (관련 설정이 없음)"
        if empty_status == "SAFE":
            return "SAFE", "양호 (관련 설정 없음 - 해당 기능 미사용)"

    criteria = rule.get("criteria")
    if criteria and isinstance(criteria, list):
        if _is_permission_denied(stripped):
            return "VULNERABLE", "권한 부족으로 정확한 확인 불가 - 수동 확인 필요 (보수적으로 취약 처리)"
        # missing_is_vulnerable 룰은 레지스트리 값 부재가 곧 미설정(취약)이므로 NA로 조기 종료하지 않고 세부기준을 평가한다.
        miss_vuln = bool(rule.get("missing_is_vulnerable")) and _is_registry_missing(stripped)
        if not miss_vuln and _is_na(stripped):
            return "NA", "해당없음 (대상 기능/서비스 없음)"

        # [세부기준 상태 정밀화, 2026-09] 예전엔 충족/미충족 두 가지뿐이라 "값이 아예 없음(미설정)",
        # "값은 있는데 기준에 못 미침", "권한이 없어 못 읽음", "명령 자체가 실패"가 전부 똑같이
        # "미충족"으로 뭉개졌다. 판정 상태(양호/부분만족/취약)는 그대로 충족 개수로 정하되(하위호환),
        # 어떤 기준이 왜 못 채워졌는지를 사유별로 나눠 detail에 남겨서 조치 담당자가 바로 알게 한다.
        #   - 기준 미달   : 값은 확인됐으나(예: FAIL 출력) 기준에 못 미침
        #   - 미설정      : 설정값이 없음(빈 출력 또는 명령이 NOTSET을 출력)
        #   - 권한 부족   : 세부기준 명령이 권한 거부로 실패 -> 수동 확인 필요
        #   - 실행 실패   : 명령 실행 자체가 실패 -> 수동 확인 필요
        # 명령이 NOTAPPLICABLE을 출력하면(예: 대상 파일/서비스가 아예 없음) 그 기준은 분모에서 뺀다.
        passed, total = 0, 0
        unmet, unset, denied, failed = [], [], [], []
        for c in criteria:
            c_output = full_output
            c_exec_failed = False
            if c.get("command") and execute_fn:
                c_result = execute_fn(c["command"])
                # [버그 수정] 예전엔 `execute_fn(...) or ""`로 None(실행 실패)과
                # ""(정상 실행됐지만 결과 없음)를 똑같이 빈 문자열로 뭉뚱그렸다.
                # vulnerable_keyword 조건은 "빈 문자열엔 뭐가 있어도 안 걸림"이라
                # 실행 자체가 실패한 기준이 자동으로 "충족(안전)"으로 잘못 집계됐다.
                # 최상위 full_output이 None일 때 MANUAL로 보내는 것과 같은 원칙으로,
                # 여기서도 실행 실패는 절대 "충족"으로 세지 않는다.
                if c_result is None:
                    c_exec_failed = True
                    c_output = ""
                else:
                    c_output = c_result

            label = c.get("label", "세부기준")
            c_stripped = (c_output or "").strip()

            if not c_exec_failed and "NOTAPPLICABLE" in c_stripped:
                continue  # 이 기준은 대상 자체가 없어 판정 대상이 아님(분모 제외)
            total += 1

            reason = None  # None이면 충족
            if c_exec_failed:
                reason = "failed"
            elif _is_permission_denied(c_stripped):
                reason = "denied"
            elif "vulnerable_keyword" in c or "vulnerable_regex" in c:
                if ("vulnerable_keyword" in c and c["vulnerable_keyword"] in c_output) or                         ("vulnerable_regex" in c and _regex_found(c["vulnerable_regex"], c_output)):
                    reason = "unmet"
            elif "safe_keyword" in c or "safe_regex" in c:
                if not c_stripped or "NOTSET" in c_stripped or _is_registry_missing(c_stripped):
                    reason = "unset"
                elif "safe_regex" in c and "safe_keyword" not in c:
                    if not _regex_found(c["safe_regex"], c_output):
                        reason = "unmet"
                elif c["safe_keyword"] not in c_output:
                    # safe_keyword가 OK인 세부기준은 명령이 OK/FAIL을 직접 출력한다.
                    # FAIL이면 값은 있는데 기준 미달, 그 외 출력(오류 문구 등)이면 값을
                    # 확인하지 못한 것이라 "미설정/확인 불가"로 구분한다.
                    reason = "unmet" if ("FAIL" in c_stripped or c["safe_keyword"] != "OK") else "unset"
            # 판정 불가능한 기준(vulnerable/safe_keyword 둘 다 없음)은 통과로 간주(스킵)

            if reason is None:
                passed += 1
            elif reason == "failed":
                failed.append(label)
            elif reason == "denied":
                denied.append(label)
            elif reason == "unset":
                unset.append(label)
            else:
                unmet.append(label)

        if total == 0:
            return "NA", "해당없음 (모든 세부기준의 대상 기능/파일이 없음)"

        if failed and len(failed) == total:
            return "MANUAL", "세부기준 명령 실행 실패(권한 부족 또는 연결 문제로 추정) - 수동 확인 필요"

        def _reasons():
            parts = []
            if unmet:
                parts.append("기준 미달: " + ", ".join(unmet))
            if unset:
                parts.append("미설정/확인 불가: " + ", ".join(unset))
            if denied:
                parts.append("권한 부족(수동 확인 필요): " + ", ".join(denied))
            if failed:
                parts.append("실행 실패(수동 확인 필요): " + ", ".join(failed))
            return "; ".join(parts)

        if passed == total:
            return "SAFE", f"양호 (세부기준 {passed}/{total} 충족)"
        elif passed == 0:
            return "VULNERABLE", f"취약 (세부기준 {passed}/{total} 충족 - {_reasons()})"
        else:
            return "PARTIAL", f"부분만족 (세부기준 {passed}/{total} 충족, {_reasons()})"

    if _is_permission_denied(stripped):
        return "VULNERABLE", "권한 부족으로 정확한 확인 불가 - 수동 확인 필요 (보수적으로 취약 처리)"

    if rule.get("missing_is_vulnerable") and _is_registry_missing(stripped):
        return "VULNERABLE", "필수 설정 미흡: 레지스트리 키/값이 없음(미설정) - 명시적으로 설정해야 양호"

    if _is_na(stripped):
        return "NA", "해당없음 (대상 기능/서비스 없음)"

    return _single_condition_result(rule, full_output)
