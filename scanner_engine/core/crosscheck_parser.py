# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[교차검증 모드] 컨설턴트 산출 TXT(Z-VulnScan text_report.py와 동일 포맷 가정)를
파싱해 항목 단위 레코드로 변환한다.

text_report.py는 수정하지 않는다 (외부 엑셀 매크로가 그 출력 포맷에 의존하므로
변경 리스크를 피하기 위함 - text_report.py 상단 주석 참고). 여기서는 그 포맷을
역으로 읽기만 한다.
"""
import os
import re

# 호스트 구획 경계: `---------[ {host} Result - {ip} ]-------`
HOST_HEADER_RE = re.compile(
    r'-{5,}\[\s*(?P<host>.+?)\s+Result\s*-\s*(?P<ip>.+?)\s*\]-{5,}'
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


def _read_text(filepath):
    """UTF-8 우선, 실패 시 cp949(현장 담당자 PC에서 흔한 인코딩) fallback."""
    for encoding in ("utf-8", "utf-8-sig"):
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    with open(filepath, 'r', encoding='cp949', errors='replace') as f:
        return f.read()


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
    """파일 하나를 파싱해 ParsedRecord(dict) 리스트를 반환한다."""
    text = _read_text(filepath)
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
