# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

# 명령 실행 결과에 이런 문구가 있으면 "그 기능/서비스 자체가 대상 시스템에 없다"는 신호로 보고
# 취약/양호가 아니라 "해당없음"으로 분류한다.
NA_SIGNALS = [
    "command not found", "not found", "No such file or directory",
    "찾을 수 없습니다", "존재하지 않음", "not recognized as",
    "레지스트리 키 또는 값이 존재하지 않음", "Cannot find",
]


def _is_na(output_stripped):
    return bool(output_stripped) and any(sig in output_stripped for sig in NA_SIGNALS)


def _single_condition_result(rule, full_output):
    """기존 방식: vulnerable_keyword 또는 safe_keyword 단일 조건 판정"""
    if "vulnerable_keyword" in rule:
        if rule["vulnerable_keyword"] in full_output:
            return "VULNERABLE", f"취약 설정 발견: {full_output[:40]}..."
        return "SAFE", "양호 (점검 완료)"
    elif "safe_keyword" in rule:
        if not full_output or rule["safe_keyword"] not in full_output:
            return "VULNERABLE", f"필수 설정 미흡: {rule['safe_keyword']} 누락"
        return "SAFE", "양호 (점검 완료)"
    else:
        return "MANUAL", "수동 검토 필요 (증적 확인)"


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
    full_output = full_output or ""
    stripped = full_output.strip()

    criteria = rule.get("criteria")
    if criteria and isinstance(criteria, list):
        if _is_na(stripped):
            return "NA", "해당없음 (대상 기능/서비스 없음)"

        passed, total, unmet_labels = 0, len(criteria), []
        for c in criteria:
            c_output = full_output
            if c.get("command") and execute_fn:
                c_output = execute_fn(c["command"]) or ""

            if "vulnerable_keyword" in c:
                ok = c["vulnerable_keyword"] not in c_output
            elif "safe_keyword" in c:
                ok = bool(c_output) and c["safe_keyword"] in c_output
            else:
                ok = True  # 판정 불가능한 기준은 통과로 간주(스킵)

            if ok:
                passed += 1
            else:
                unmet_labels.append(c.get("label", "세부기준"))

        if passed == total:
            return "SAFE", f"양호 (세부기준 {passed}/{total} 충족)"
        elif passed == 0:
            return "VULNERABLE", f"취약 (세부기준 {passed}/{total} 충족)"
        else:
            return "PARTIAL", f"부분만족 (세부기준 {passed}/{total} 충족, 미충족: {', '.join(unmet_labels)})"

    if _is_na(stripped):
        return "NA", "해당없음 (대상 기능/서비스 없음)"

    return _single_condition_result(rule, full_output)
