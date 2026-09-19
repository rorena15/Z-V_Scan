"""룰 명령을 대상 시스템 없이 돌리기 위한 '가짜 환경' - 테스트/시나리오/try_rule.py/rule_lab.py가 공용으로 쓴다.

WindowsEnv: 룰 명령 속 레지스트리 경로(HKLM/HKCU, reg query와 PowerShell 드라이브 표기 둘 다)를 인스턴스별 임시 키
            HKCU\\Software\\ZVulnScanTest\\<id>\\... 로 자동 치환하고, secedit 캐시 파일(C:\\zvulnscan_secpol_cache.cfg)은
            임시 파일로 치환한다. 그래서 "진짜 경로 그대로" 값을 지정할 수 있다(별도 별칭 불필요).
            인스턴스마다 키가 달라 여러 개(테스트+랩)를 동시에 돌려도 서로 안 겹친다.
LinuxEnv:   /etc /var /opt /home /root 를 임시 폴더 아래로 치환하고 그 안에 원하는 파일을 만든다.
둘 다 실제 시스템의 설정은 읽지도 쓰지도 않는다(임시 키/폴더만 사용, cleanup()에서 삭제).

[입력 검증] 화면(rule_lab)이 사용자 입력을 그대로 넘기므로, 레지스트리 경로/이름/파일 경로는 허용 문자만 통과시킨다
(PowerShell 명령 문자열에 끼워 넣기 때문에 인젝션 방지 필요, 파일 경로는 상위 폴더 탈출 방지)."""
import os
import re
import shutil
import sys
import tempfile
import uuid

import _helpers as h
from utils.rule_judge import judge_rule

SCRATCH = 'Software\\ZVulnScanTest'
SECPOL_REAL = 'C:\\zvulnscan_secpol_cache.cfg'
_REG_PREFIX = re.compile(r'HK(LM|CU)(:?)\\')
_REG_PATH_OK = re.compile(r'^HK(LM|CU):?\\[A-Za-z0-9_ .\-{}()\\]{1,300}$')
_REG_NAME_OK = re.compile(r'^[A-Za-z0-9_ .\-]{1,100}$')
_FILE_PATH_OK = re.compile(r'^(etc|var|opt|home|root)/[A-Za-z0-9_.\-/ ]{1,200}$')
MAX_TEXT = 100_000


class WindowsEnv:
    def __init__(self):
        self.ps = h.find_powershell() if sys.platform == 'win32' else None
        if not self.ps:
            raise RuntimeError("Windows PowerShell 필요")
        self.tmp = tempfile.mkdtemp(prefix='zvs_win_')
        self.secpol_path = os.path.join(self.tmp, 'secpol.cfg')
        self.scratch = f'{SCRATCH}\\{uuid.uuid4().hex[:8]}'

    def _sub(self, m):
        return f'HKCU{m.group(2)}\\{self.scratch}\\HK{m.group(1)}\\'

    def redirect(self, cmd):
        cmd = _REG_PREFIX.sub(self._sub, cmd)
        return cmd.replace(SECPOL_REAL, self.secpol_path)

    def set_reg(self, real_path, values):
        """real_path: 룰이 읽는 진짜 경로(예: HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters).
        values: {이름: int|str} - int는 DWord, str은 String으로 쓴다."""
        real_path = real_path.replace('HKLM:\\', 'HKLM\\').replace('HKCU:\\', 'HKCU\\')
        if not _REG_PATH_OK.match(real_path) or '..' in real_path:
            raise ValueError(f"허용되지 않는 레지스트리 경로: {real_path!r}")
        key = _REG_PREFIX.sub(self._sub, real_path, count=1).replace('HKCU\\', 'HKCU:\\', 1)
        lines = [f"if(-not (Test-Path '{key}')){{ New-Item -Path '{key}' -Force | Out-Null }}"]  # -Force는 기존 값을 지움
        for name, val in values.items():
            if not _REG_NAME_OK.match(str(name)):
                raise ValueError(f"허용되지 않는 값 이름: {name!r}")
            if isinstance(val, int) and not isinstance(val, bool):
                lines.append(f"New-ItemProperty -Path '{key}' -Name '{name}' -Value {val} -PropertyType DWord -Force | Out-Null")
            else:
                escaped = str(val)[:500].replace("'", "''")
                lines.append(f"New-ItemProperty -Path '{key}' -Name '{name}' -Value '{escaped}' -PropertyType String -Force | Out-Null")
        h.run_powershell(self.ps, '; '.join(lines))

    def set_secpol(self, text):
        """secedit 내보내기 형식 텍스트(예: 'LockoutBadCount = 3')를 캐시 파일로 쓴다."""
        if len(text) > MAX_TEXT:
            raise ValueError("secpol 텍스트가 너무 큼")
        with open(self.secpol_path, 'w', encoding='utf-8') as f:
            f.write(text)

    def run(self, cmd):
        return h.run_powershell(self.ps, self.redirect(cmd))

    def cleanup(self):
        h.run_powershell(self.ps, (
            f"Remove-Item -Path 'HKCU:\\{self.scratch}' -Recurse -Force -ErrorAction SilentlyContinue; "
            f"$p='HKCU:\\{SCRATCH}'; if((Test-Path $p) -and -not (Get-ChildItem $p -ErrorAction SilentlyContinue)){{ Remove-Item $p -Force }}"))
        shutil.rmtree(self.tmp, ignore_errors=True)


class LinuxEnv:
    _ABS = re.compile(r'(?<![\w.\-])/(etc|var|opt|home|root)/')

    def __init__(self):
        self.bash = h.find_bash()
        if not self.bash:
            raise RuntimeError("bash 필요(Git Bash/Linux/macOS)")
        self.tmp = tempfile.mkdtemp(prefix='zvs_lin_')

    def write(self, rel_path, text):
        """rel_path: 'etc/ssh/sshd_config'처럼 선행 / 없이. 상위 폴더는 자동 생성."""
        rel_path = rel_path.strip().lstrip('/\\')
        if not _FILE_PATH_OK.match(rel_path) or '..' in rel_path.split('/'):
            raise ValueError(f"허용되지 않는 파일 경로: {rel_path!r} (etc/ var/ opt/ home/ root/ 아래만 가능)")
        if len(text) > MAX_TEXT:
            raise ValueError("파일 내용이 너무 큼")
        full = os.path.join(self.tmp, rel_path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'w', newline='\n') as f:
            f.write(text)

    def redirect(self, cmd):
        return self._ABS.sub(r'./\1/', cmd)

    def run(self, cmd):
        return h.run_bash(self.bash, self.redirect(cmd), self.tmp)

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


LOCAL_RULESETS = {'linux_rules.json': 'linux', 'web_rules.json': 'linux',
                  'windows_rules.json': 'windows', 'pc_rules.json': 'windows'}


def env_for_rule(code):
    """룰 코드 접두어로 OS를 고른다: U-/WEB- -> Linux, W-/PC- -> Windows."""
    if code.startswith(('U-', 'WEB-')):
        return LinuxEnv(), 'linux_rules.json' if code.startswith('U-') else 'web_rules.json'
    if code.startswith(('W-', 'PC-')):
        return WindowsEnv(), 'windows_rules.json' if code.startswith('W-') else 'pc_rules.json'
    raise ValueError(f"지원하지 않는 룰 코드: {code} (U-/WEB-/W-/PC- 룰만 로컬 실행 가능, D- 룰은 DB 접속 필요)")


def judge_in_env(env, rule, trace=None):
    """룰 최상위 명령 + 세부기준 명령을 env에서 실행해 판정한다. trace(list)를 주면 각 명령 출력을 순서대로 쌓는다."""
    def run(cmd):
        out = env.run(cmd)
        if trace is not None:
            trace.append(out.strip())
        return out
    top = run(rule['command']) if rule.get('command') else ''
    return judge_rule(rule, top, execute_fn=run)


def list_local_rules():
    """로컬 실행 가능한 모든 룰의 요약(화면 목록용)."""
    out = []
    for filename, osname in LOCAL_RULESETS.items():
        for code, r in h.load_rules(filename).items():
            out.append({"code": code, "name": r['name'], "importance": r['importance'], "os": osname,
                        "category": r.get('category', ''), "has_criteria": bool(r.get('criteria')),
                        "ruleset": filename})
    return sorted(out, key=lambda x: (x['os'], x['code']))


def _all_commands(rule):
    cmds = [rule.get('command') or '']
    cmds += [c.get('command') or '' for c in rule.get('criteria') or []]
    return [c for c in cmds if c]


def suggest_env(rule, osname):
    """룰 명령 텍스트에서 '이 룰이 읽는 설정'을 추출해 입력 양식을 미리 채워 준다(힌트일 뿐 - 값은 사용자가 정함)."""
    cmds = _all_commands(rule)
    text = '\n'.join(cmds)
    if osname == 'windows':
        reg, seen = [], set()
        for path, name in re.findall(r'reg query\s+"(HK[^"$]+)"\s+/v\s+(\w+)', text):
            if (path, name) not in seen:
                seen.add((path, name)); reg.append({"path": path, "name": name})
        for path in re.findall(r"Get-ItemProperty\s+'(HK[^'$]+)'", text):
            for name in sorted(set(re.findall(r'\$p\.(\w+)', text))):
                if (path, name) not in seen:
                    seen.add((path, name)); reg.append({"path": path.replace(':', '', 1), "name": name})
        secpol = sorted(set(re.findall(r'\^([A-Za-z0-9_]+)\\s\*=', text)))
        return {"registry": reg, "secpol_keys": secpol, "files": []}
    files = sorted({p for p in re.findall(r'(?<![\w.\-])/((?:etc|var|opt|home|root)/[\w./\-]+)', text)
                    if '*' not in p and not p.endswith('/')})
    return {"registry": [], "secpol_keys": [], "files": files}


def _normalize_reg(reg):
    """reg를 [{"path","name","value"}] 로 통일. 시나리오 JSON의 {경로: {이름: 값}} 형식도 받는다."""
    if not reg:
        return []
    if isinstance(reg, dict):
        return [{"path": p, "name": n, "value": v} for p, vals in reg.items() for n, v in vals.items()]
    return list(reg)


def evaluate(code, reg=None, secpol=None, files=None):
    """룰 하나를 가짜 환경에서 실행해 결과 dict를 돌려준다.
    reg: [{"path","name","value"}] 또는 {경로:{이름:값}} (값이 빈 문자열/None이면 '미설정'으로 건너뜀)
    secpol: secedit 텍스트, files: {상대경로: 내용} 또는 [{"path","content"}]"""
    env, ruleset = env_for_rule(code)
    try:
        rules = h.load_rules(ruleset)
        if code not in rules:
            raise ValueError(f"{ruleset}에 {code} 룰이 없습니다.")
        rule = rules[code]
        if isinstance(env, WindowsEnv):
            grouped = {}
            for row in _normalize_reg(reg):
                value = row.get('value')
                if value is None or str(value).strip() == '':
                    continue                      # 빈 값 = 미설정 상태로 둠
                if isinstance(value, str) and re.fullmatch(r'-?\d+', value.strip()):
                    value = int(value.strip())
                grouped.setdefault(row['path'], {})[row['name']] = value
            for path, values in grouped.items():
                env.set_reg(path, values)
            if secpol:
                env.set_secpol(secpol)
        else:
            items = files.items() if isinstance(files, dict) else [(f['path'], f.get('content', '')) for f in (files or [])]
            for rel, content in items:
                if str(content).strip() != '':
                    env.write(rel, str(content))
        trace = []
        status, detail = judge_in_env(env, rule, trace)
        top_out = trace[0] if rule.get('command') else ''
        crit_outs = iter(trace[1:] if rule.get('command') else trace)
        criteria = []
        for c in rule.get('criteria') or []:
            out = next(crit_outs, '') if c.get('command') else top_out
            criteria.append({"label": c['label'], "output": out})
        return {"rule": code, "name": rule['name'], "importance": rule['importance'],
                "description": rule.get('description', ''), "status": status, "detail": detail,
                "top_output": top_out, "criteria": criteria}
    finally:
        env.cleanup()


def run_scenario(sc):
    """시나리오 하나 -> (통과여부, 결과 dict). expect/detail_contains를 함께 검사한다."""
    res = evaluate(sc['rule'], reg=sc.get('reg'), secpol=sc.get('secpol'), files=sc.get('files'))
    ok = res['status'] == sc.get('expect')
    missing = [n for n in sc.get('detail_contains', []) if n not in res['detail']]
    return ok and not missing, dict(res, expected=sc.get('expect'), missing_phrases=missing)
