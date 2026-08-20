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


def _is_na(output_stripped):
    return bool(output_stripped) and any(sig in output_stripped for sig in NA_SIGNALS)


def _is_permission_denied(output_stripped):
    return bool(output_stripped) and any(sig in output_stripped for sig in PERMISSION_DENIED_SIGNALS)


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
    # [판정 정확도] 인스펙터가 "명령/쿼리 실행 자체가 실패했다"는 뜻으로 명시적으로
    # None을 반환하는 경우(예: DatabaseInspector.execute_query()가 권한 부족 등으로
    # 예외 발생 시) - "결과가 없어서 안전"과 절대 혼동하면 안 되므로 여기서 먼저
    # 걸러 수동확인으로 돌린다. 빈 문자열("")은 "정상 실행됐지만 결과 0건"이라는
    # 뜻이라 기존처럼 그대로 판정 로직을 탄다.
    if full_output is None:
        return "MANUAL", "점검 명령/쿼리 실행 실패(권한 부족 또는 연결 문제로 추정) - 수동 확인 필요"

    full_output = full_output or ""
    stripped = full_output.strip()

    criteria = rule.get("criteria")
    if criteria and isinstance(criteria, list):
        if _is_permission_denied(stripped):
            return "VULNERABLE", "권한 부족으로 정확한 확인 불가 - 수동 확인 필요 (보수적으로 취약 처리)"
        if _is_na(stripped):
            return "NA", "해당없음 (대상 기능/서비스 없음)"

        passed, total, unmet_labels = 0, len(criteria), []
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

            if c_exec_failed:
                ok = False
            elif "vulnerable_keyword" in c:
                ok = c["vulnerable_keyword"] not in c_output
            elif "safe_keyword" in c:
                ok = bool(c_output) and c["safe_keyword"] in c_output
            else:
                ok = True  # 판정 불가능한 기준은 통과로 간주(스킵)

            if ok:
                passed += 1
            else:
                label = c.get("label", "세부기준")
                if c_exec_failed:
                    label += " (실행 실패 - 수동 확인 필요)"
                unmet_labels.append(label)

        if passed == total:
            return "SAFE", f"양호 (세부기준 {passed}/{total} 충족)"
        elif passed == 0:
            return "VULNERABLE", f"취약 (세부기준 {passed}/{total} 충족)"
        else:
            return "PARTIAL", f"부분만족 (세부기준 {passed}/{total} 충족, 미충족: {', '.join(unmet_labels)})"

    if _is_permission_denied(stripped):
        return "VULNERABLE", "권한 부족으로 정확한 확인 불가 - 수동 확인 필요 (보수적으로 취약 처리)"

    if _is_na(stripped):
        return "NA", "해당없음 (대상 기능/서비스 없음)"

    return _single_condition_result(rule, full_output)
