# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[교차검증 모드] 스크립트 산출 TXT(Z-VulnScan text_report.py와 동일 포맷 가정)를
파싱해 항목 단위 레코드로 변환한다.

text_report.py는 수정하지 않는다 (외부 엑셀 매크로가 그 출력 포맷에 의존하므로
변경 리스크를 피하기 위함 - text_report.py 상단 주석 참고). 여기서는 그 포맷을
역으로 읽기만 한다.
"""
import os
import re

# 호스트 구획 경계: `---------[ {host} Result - {ip} ]-------`
# ip 그룹에 숫자를 최소 1개 요구한다 - 실제 스크립트의 공통 안내문
# `---------[ ICTIS Script Result - Windows PC ]-------` (host="ICTIS Script",
# ip="Windows PC")가 이 패턴에 거짓 매칭되어 text_report.py 자체 포맷으로
# 잘못 라우팅되던 버그를 막기 위함.
HOST_HEADER_RE = re.compile(
    r'-{5,}\[\s*(?P<host>.+?)\s+Result\s*-\s*(?P<ip>.*\d.*?)\s*\]-{5,}'
)

# 카테고리 그룹 헤더: `-------------- \n {idx}. {category}  \n -------------- `
CATEGORY_RE = re.compile(
    r'^-{4,}\s*$\n^\s*\d+\.\s*(?P<category>.+?)\s*$\n^-{4,}\s*$',
    re.M
)

AUDIT_MARK_RE = re.compile(r'Audit\s*\(KISA\s*취약점\s*진단\)')
SYS_DETAIL_MARK_RE = re.compile(r'SYSTEM Detail')

# [코드] 이름 / 권고 : ... / [START] ... [END] 블록 전체
ITEM_RE = re.compile(
    r'^\[(?P<code>[^\]\n]+)\]\s*(?P<name>.+?)\s*$\n'
    r'^권고\s*:\s*(?P<remediation>.*?)\s*$\n'
    r'^\[START\]\s*$\n'
    r'(?P<body>.*?)'
    r'\n^\[END\]\s*$',
    re.M | re.S
)

# [END] 짝이 안 맞는 등, 온전히 매치되지 않은 항목이라도 코드/이름만은 베스트에포트로 회수
LOOSE_ITEM_START_RE = re.compile(r'^\[(?P<code>[^\]\n]+)\]\s*(?P<name>.+?)\s*$', re.M)

BODY_RE = re.compile(
    r'\[RESULT\]\s*(?P<result>[^\n]*)\n'
    r'\[REASON\]\s*(?P<reason>[^\n]*)\n'
    r'현황\s*\n'
    r':\s*(?P<status_text>[^\n]*)\n'
    r'-{4,}\s*\n'
    r'(?:\(CMD\)\s*(?P<command>[^\n]*)\n)?'
    r'(?P<raw_output>.*)',
    re.S
)

OS_VERSION_RE = re.compile(r'OS version is\s*"(?P<os>[^"]*)"')
FILENAME_TAG_RE = re.compile(r'^\[(?P<tag>[A-Za-z]+)\]')

# ----------------------------------------------------------------------
# [외부 스크립트 포맷] text_report.py를 그대로 흉내낸 자체 포맷과 달리, 외부에서
# 가져오는 이 형식의 파일은 호스트 구분선이 파일 안에 없고(파일당 1호스트), 파일명
# 자체에 호스트/OS/IP를 담는다: 예) [RESULT]${HOST}_${OS}_${IP}.txt
# 항목 블록도 "[SRV-xxx] 이름" + (있을 수도 없을 수도 있는) "[U-xx] 이름2" 두 줄 조합이고,
# [REASON]이 여러 줄 나올 수 있으며, [RESULT]는 양호/취약/확인 세 가지뿐이다(부분만족/N/A 없음).
# 이 포맷은 정식 text_report.py 출력과 완전히 달라서 별도 파서가 필요하다.
# ----------------------------------------------------------------------
CONSULTANT_FILENAME_RE = re.compile(r'^\[(?P<tag>[A-Za-z]+)\](?P<rest>.+)\.txt$', re.I)

# 파일명 안에서 IP를 앵커로 찾는다 - host_os_ip(UNIX, 3파트) / host_os_ip_date(PC, 4파트,
# os필드에 대괄호 포함 가능 - 예: WINDOWS[11]) / host_ip(Server, 2파트, os필드 없음) 등
# 밑줄 파트 개수가 포맷마다 달라 고정 rsplit으로는 대응 불가하므로, IP 패턴 위치를
# 기준으로 앞쪽을 host_os로, 뒤쪽(날짜 등)은 버린다.
_FILENAME_IP_RE = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}')

KISA_CODE_PREFIXES = ("U-", "W-", "D-", "WEB-", "PC-")

# 항목 하나의 [START]...[END] 블록 (제목/판단기준 영역은 별도로 preamble에서 찾는다)
# [버그 수정] 이전에는 \[START\]/\[END\] 뒤에 \s*를 썼는데, \s가 개행도 포함하다 보니
# 본문이 빈 줄만 있는 경우(예: 빈 PowerShell 명령 결과) 탐욕적 매칭이 다음 줄들까지
# 집어삼켜 [END]를 못 찾고 그다음 항목의 [END]까지 넘어가 버리는 문제가 실측으로
# 확인됐다(항목이 통째로 누락되거나, 다음 항목 코드에 엉뚱한 항목의 증적이 붙음).
# 같은 줄 안의 공백/탭/캐리지리턴만 소비하도록 [ \t\r]*로 제한해 줄 경계(\n)를 넘지
# 않게 한다 - \r을 빼면 CRLF(\r\n) 파일에서 [END]\r 형태가 안 잡히는 회귀가 생긴다
# (Windows Server 샘플에서 실측으로 확인됨).
CONSULTANT_ITEM_BODY_RE = re.compile(r'^\[START\][ \t\r]*$\n(?P<body>.*?)\n^\[END\][ \t\r]*$', re.M | re.S)

# preamble(직전 [END] ~ 이번 [START] 사이)에서 "[코드] 이름" 형태의 줄을 전부 찾는다
CONSULTANT_CODE_LINE_RE = re.compile(r'^\[(?P<code>[A-Za-z]+-\d+)\]\s*(?P<name>.+?)\s*$', re.M)

# [START]~[END] 본문 안에서 "### 실행 흔적" 구획만 추려낸다 - 실제 명령 실행 결과(증적)에
# 가장 가까운 부분이라, 서비스 상태/설정 증거의 서술형 문장보다 judge_rule() 재판정에 유리하다.
CONSULTANT_EXEC_TRACE_RE = re.compile(r'###\s*실행\s*흔적\s*\n(?P<trace>.*?)(?=\n###\s|\Z)', re.S)
CONSULTANT_REASON_RE = re.compile(r'^\[REASON\]\s*(?P<reason>.*)$', re.M)
CONSULTANT_RESULT_RE = re.compile(r'^\[RESULT\]\s*(?P<result>\S+)', re.M)

# [PC 진단 도구 전용] pc_toolkit.py가 세부기준(criteria) 중 자체 command가 있는 항목을
# 실제로 실행해 남기는 블록 - "[CRIT:0]"부터 command가 있는 criteria 등장 순서대로 번호가
# 매겨진다(command가 없는 criteria는 원래 최상위 출력을 재사용하므로 여기 안 나온다).
# 같은 [ \t\r]* 제한을 쓰는 이유는 CONSULTANT_ITEM_BODY_RE와 동일(빈 출력이 다음 블록까지
# 집어삼키는 것을 방지).
CONSULTANT_CRIT_RE = re.compile(
    r'^\[CRIT:(?P<idx>\d+)\][ \t\r]*$\n(?P<output>.*?)(?=\n^\[CRIT:\d+\][ \t\r]*$|\Z)',
    re.M | re.S,
)

# [PC 진단 도구 전용] rule.get('evidence_command')가 있으면 pc_toolkit.py가 사람이 볼
# 상세 증적(raw_output)을 여기 추가로 남긴다 - 항상 [CRIT:N] 블록들 뒤, 본문 맨 끝에
# 한 번만 나온다. 이 값은 절대 judge_rule()의 판정 입력에 섞이지 않는다(별도 필드로
# 분리해 record["evidence_output"]로만 넘김) - crosscheck_engine.import_pc_results()가
# DB의 raw_output(리포트 상세 증적) 컬럼에만 쓴다.
CONSULTANT_EVIDENCE_RE = re.compile(r'^\[EVIDENCE\][ \t\r]*$\n(?P<output>.*)\Z', re.M | re.S)


def _match_consultant_filename(filepath):
    """파일명이 '[TAG]{host}_{os}_{ip}(_{date})?.txt' 패턴이면 (host, os_field, ip)를 반환,
    아니면 None. IP 패턴을 앵커로 삼아 그 앞쪽만 host/os로 나눈다 - 밑줄 파트 개수가
    3개(UNIX: host_os_ip), 4개(PC: host_os_ip_date, os에 대괄호 포함 가능), 2개
    (Server: host_ip, os 필드 없음) 등 포맷마다 달라 고정 rsplit으로는 대응 불가하다.
    IP 뒤쪽(날짜 등)은 사용하지 않는다."""
    base = os.path.basename(filepath)
    m = CONSULTANT_FILENAME_RE.match(base)
    if not m:
        return None
    rest = m.group('rest')
    ip_m = _FILENAME_IP_RE.search(rest)
    if not ip_m:
        return None
    ip = ip_m.group(0)
    before = rest[:ip_m.start()].rstrip('_')
    if not before:
        return None
    parts = before.split('_', 1)
    host = parts[0]
    os_field = parts[1] if len(parts) > 1 else None
    return host, os_field, ip


def _infer_os_tag_from_os_field(os_field):
    f = (os_field or "").lower()
    if 'win' in f:
        return "WINDOWS"
    if any(k in f for k in ('linux', 'unix', 'aix', 'hp-ux', 'hpux', 'solaris')):
        return "UNIX"
    return "UNKNOWN"


def _parse_consultant_body(body):
    # [PC 진단 도구 전용] [EVIDENCE]가 있으면 본문 맨 끝의 사람이 볼 상세 증적 블록이므로
    # 먼저 떼어낸다 - 그래야 그 안의 텍스트가 [CRIT:N]/raw_output 파싱에 섞이지 않는다.
    evi_m = CONSULTANT_EVIDENCE_RE.search(body)
    if evi_m:
        body_wo_evidence = body[:evi_m.start()]
        evidence_output = evi_m.group('output').strip()
    else:
        body_wo_evidence = body
        evidence_output = ""

    # [PC 진단 도구 전용] [CRIT:N] 블록이 있으면 그건 세부기준별 개별 증거이지 최상위
    # raw_output이 아니므로, 첫 [CRIT:N] 마커 이전까지만 top_body로 잘라서 아래
    # raw_output/consultant_result 추출에 쓴다. 없는 파일(실제 스크립트 등)은 이전과 동일.
    crit_matches = list(CONSULTANT_CRIT_RE.finditer(body_wo_evidence))
    if crit_matches:
        top_body = body_wo_evidence[:crit_matches[0].start()]
        criteria_outputs = {int(m.group('idx')): m.group('output').strip() for m in crit_matches}
    else:
        top_body = body_wo_evidence
        criteria_outputs = {}

    trace_m = CONSULTANT_EXEC_TRACE_RE.search(top_body)
    raw_output = trace_m.group('trace').strip() if trace_m else top_body.strip()
    reasons = [m.group('reason').strip() for m in CONSULTANT_REASON_RE.finditer(top_body) if m.group('reason').strip()]
    result_m = CONSULTANT_RESULT_RE.search(top_body)
    return {
        "raw_output": raw_output,
        "consultant_reason": "; ".join(reasons) if reasons else None,
        "consultant_result": result_m.group('result') if result_m else None,
        "criteria_outputs": criteria_outputs,
        "evidence_output": evidence_output,
    }


def _parse_consultant_format(text, host, ip, os_tag, source_file):
    """실제 스크립트 출력 포맷 파서. 호스트 구분선이 없으므로 파일 전체를
    훑어서 [START]...[END] 블록마다 직전 preamble에서 코드/이름을 찾는다."""
    records = []
    prev_end = 0
    for m in CONSULTANT_ITEM_BODY_RE.finditer(text):
        preamble = text[prev_end:m.start()]
        prev_end = m.end()

        kisa_match = None
        srv_match = None
        for cl in CONSULTANT_CODE_LINE_RE.finditer(preamble):
            code = cl.group('code')
            if any(code.startswith(p) for p in KISA_CODE_PREFIXES):
                kisa_match = cl
            elif code.startswith('SRV-'):
                srv_match = cl

        if kisa_match:
            code, name = kisa_match.group('code'), kisa_match.group('name').strip()
        elif srv_match:
            code, name = None, srv_match.group('name').strip()
        else:
            code, name = None, None

        parsed = _parse_consultant_body(m.group('body'))
        line_no = text.count('\n', 0, m.start()) + 1
        records.append(_new_record(
            source_file=source_file, host=host, ip=ip, os_tag=os_tag,
            category=None, code=code, name=name, remediation=None,
            consultant_result=parsed["consultant_result"],
            consultant_reason=parsed["consultant_reason"],
            command=None, raw_output=parsed["raw_output"],
            criteria_outputs=parsed["criteria_outputs"],
            evidence_output=parsed["evidence_output"],
            parse_ok=True,
            parse_warning=None if code is not None else "KISA 코드 없음 (주통 해당사항 없음 등 - 코드 매핑 불가 항목)",
            line_no=line_no,
        ))
    return records


def _read_text(filepath):
    """UTF-8 우선, 실패 시 cp949(현장 담당자 PC에서 흔한 인코딩) fallback.

    실제 샘플 중 하나(Windows Server 포맷)는 대부분 UTF-8인데 극히 일부 명령어
    출력만 CP949/EUC-KR로 섞여 들어간 혼합 인코딩 파일이었다 - 어느 쪽으로도
    strict 디코딩이 되지 않는다. 이 경우 둘 다 errors='replace'로 디코딩해 본 뒤
    치환문자(�) 개수가 더 적은(=원문 손실이 더 적은) 쪽을 채택한다. 파일 전체가
    한쪽 인코딩인 일반적인 경우는 위 strict 시도에서 이미 걸러지므로 이 비교는
    혼합 인코딩 파일에만 영향을 준다."""
    for encoding in ("utf-8", "utf-8-sig"):
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    try:
        with open(filepath, 'r', encoding='cp949') as f:
            return f.read()
    except UnicodeDecodeError:
        pass
    with open(filepath, 'rb') as f:
        raw = f.read()
    candidates = [raw.decode(enc, errors='replace') for enc in ("utf-8", "cp949")]
    return min(candidates, key=lambda t: t.count('�'))


def _infer_os_tag(filename, section_text):
    m = FILENAME_TAG_RE.match(os.path.basename(filename))
    if m:
        tag = m.group('tag').upper()
        if tag in ("WINDOWS", "UNIX"):
            return tag
    m = OS_VERSION_RE.search(section_text)
    if m and 'windows' in m.group('os').lower():
        return "WINDOWS"
    if m:
        return "UNIX"
    return "UNKNOWN"


def _split_host_sections(text, filename):
    """파일을 호스트 구획으로 분할. 구분선이 없으면(비표준 파일) 파일 전체를
    하나의 미상 호스트 구획으로 취급한다 - 전체 실패로 처리하지 않기 위함."""
    matches = list(HOST_HEADER_RE.finditer(text))
    if not matches:
        return [{
            "host": os.path.splitext(os.path.basename(filename))[0],
            "ip": "",
            "os_tag": _infer_os_tag(filename, text),
            "text": text,
            "section_warning": "호스트 구분선을 찾지 못해 파일 전체를 단일 호스트로 처리했습니다.",
        }]

    sections = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        section_text = text[start:end]
        sections.append({
            "host": m.group('host').strip(),
            "ip": m.group('ip').strip(),
            "os_tag": _infer_os_tag(filename, section_text),
            "text": section_text,
            "section_warning": None,
        })
    return sections


def _slice_audit_block(section_text):
    """"Audit (KISA 취약점 진단)" 구분선 ~ "SYSTEM Detail" 구분선(또는 EOF) 사이만 남긴다.
    Discovery(TCP-/UDP-/INFO-00)는 판정 대상이 아니므로 여기서 자동 제외된다."""
    audit_m = AUDIT_MARK_RE.search(section_text)
    if not audit_m:
        return None
    start = audit_m.end()
    sys_m = SYS_DETAIL_MARK_RE.search(section_text, start)
    end = sys_m.start() if sys_m else len(section_text)
    return section_text[start:end]


def _split_categories(audit_text):
    """카테고리 그룹 헤더 기준으로 (category, chunk_text) 목록을 만든다.
    헤더가 하나도 없으면 category=None인 단일 청크로 취급."""
    matches = list(CATEGORY_RE.finditer(audit_text))
    if not matches:
        return [(None, audit_text)]

    chunks = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(audit_text)
        chunks.append((m.group('category').strip(), audit_text[start:end]))
    return chunks


def _parse_body(body_text):
    m = BODY_RE.search(body_text)
    if not m:
        return None
    raw_output = (m.group('raw_output') or "").strip()
    if raw_output == "-":
        raw_output = ""
    return {
        "consultant_result": (m.group('result') or "").strip(),
        "consultant_reason": (m.group('reason') or "").strip(),
        "status_text": (m.group('status_text') or "").strip(),
        "command": (m.group('command') or "").strip() or None,
        "raw_output": raw_output,
    }


def _new_record(**fields):
    base = {
        "source_file": None, "host": None, "ip": None, "os_tag": "UNKNOWN",
        "category": None, "code": None, "name": None, "remediation": None,
        "consultant_result": None, "consultant_reason": None, "status_text": None,
        "waived_hint": False, "command": None, "raw_output": "",
        "criteria_outputs": {}, "evidence_output": "",
        "parse_ok": True, "parse_warning": None, "line_no": None,
    }
    base.update(fields)
    return base


def _parse_audit_section(section_text, host, ip, os_tag, source_file):
    audit_text = _slice_audit_block(section_text)
    if audit_text is None:
        return []

    records = []
    for category, chunk_text in _split_categories(audit_text):
        matched_spans = []
        for m in ITEM_RE.finditer(chunk_text):
            matched_spans.append((m.start(), m.end()))
            parsed_body = _parse_body(m.group('body'))
            line_no = chunk_text.count('\n', 0, m.start()) + 1
            if parsed_body is None:
                records.append(_new_record(
                    source_file=source_file, host=host, ip=ip, os_tag=os_tag,
                    category=category, code=m.group('code').strip(),
                    name=m.group('name').strip(), remediation=m.group('remediation').strip(),
                    parse_ok=False, parse_warning="[RESULT]/[REASON]/현황 구획을 인식하지 못했습니다.",
                    line_no=line_no,
                ))
                continue
            records.append(_new_record(
                source_file=source_file, host=host, ip=ip, os_tag=os_tag,
                category=category, code=m.group('code').strip(), name=m.group('name').strip(),
                remediation=m.group('remediation').strip(),
                consultant_result=parsed_body["consultant_result"],
                consultant_reason=parsed_body["consultant_reason"],
                status_text=parsed_body["status_text"],
                waived_hint="(예외 처리됨)" in parsed_body["status_text"],
                command=parsed_body["command"], raw_output=parsed_body["raw_output"],
                line_no=line_no,
            ))

        # [END] 짝이 안 맞는 등, ITEM_RE에 온전히 매치되지 않은 잔여 항목을 베스트에포트로 회수
        for lm in LOOSE_ITEM_START_RE.finditer(chunk_text):
            if any(start <= lm.start() < end for start, end in matched_spans):
                continue
            line_no = chunk_text.count('\n', 0, lm.start()) + 1
            records.append(_new_record(
                source_file=source_file, host=host, ip=ip, os_tag=os_tag,
                category=category, code=lm.group('code').strip(), name=lm.group('name').strip(),
                parse_ok=False, parse_warning="[START]/[END] 블록을 완전히 인식하지 못했습니다.",
                line_no=line_no,
            ))

    return records


def parse_single_file(filepath):
    """파일 하나를 파싱해 ParsedRecord(dict) 리스트를 반환한다.

    두 포맷을 자동 판별한다:
    - text_report.py 자체 포맷: 파일 안에 '---------[ host Result - ip ]-------' 구분선이 있음
    - 외부 스크립트 포맷: 구분선이 없고, 파일명이 '[TAG]{host}_{os}_{ip}.txt' 패턴
      (호스트 구분선 없이 파일당 1호스트로 출력하는 외부 도구의 산출물)
    둘 다 아니면 기존처럼 파일 전체를 단일 미상 호스트로 취급(전체 실패 처리하지 않기 위함)."""
    text = _read_text(filepath)

    if not HOST_HEADER_RE.search(text):
        consultant_meta = _match_consultant_filename(filepath)
        if consultant_meta:
            host, os_field, ip = consultant_meta
            os_tag = _infer_os_tag_from_os_field(os_field)
            return _parse_consultant_format(text, host, ip, os_tag, filepath)

    records = []
    for section in _split_host_sections(text, filepath):
        section_records = _parse_audit_section(
            section["text"], section["host"], section["ip"], section["os_tag"], filepath
        )
        if section["section_warning"]:
            if section_records:
                for r in section_records:
                    r["parse_warning"] = r["parse_warning"] or section["section_warning"]
            else:
                records.append(_new_record(
                    source_file=filepath, host=section["host"], ip=section["ip"],
                    os_tag=section["os_tag"], parse_ok=False,
                    parse_warning=section["section_warning"],
                ))
        records.extend(section_records)
    return records


def parse_files(filepaths):
    """여러 파일을 순회 파싱한다.
    반환: (records, warning_records, failed_files)
    - records: 파싱 성공/실패 레코드 전체
    - warning_records: parse_ok=False인 레코드만 (UI 강조용)
    - failed_files: 파일 자체를 읽지 못한 경로 목록 (해당 파일만 건너뛰고 나머지는 계속 처리)
    """
    records = []
    failed_files = []
    for filepath in filepaths:
        try:
            records.extend(parse_single_file(filepath))
        except OSError:
            failed_files.append(filepath)
    warning_records = [r for r in records if not r["parse_ok"]]
    return records, warning_records, failed_files
