"""테스트 공용 유틸 - 표준 라이브러리(unittest)만 쓴다(빌드/CI에 새 의존성을 추가하지 않기 위함).

실행: 저장소 루트에서  python -m unittest discover -s tests -v
"""
import glob
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, 'scanner_engine')
RULES_DIR = os.path.join(ROOT, 'rules')
if ENGINE not in sys.path:
    sys.path.insert(0, ENGINE)


def rule_files():
    return sorted(glob.glob(os.path.join(RULES_DIR, '*_rules.json')))


def load_rules(filename):
    with open(os.path.join(RULES_DIR, filename), encoding='utf-8') as f:
        return {r['code']: r for r in json.load(f)}


def find_bash():
    """Windows에서는 PATH의 bash가 WSL 런처(System32\\bash.exe)일 수 있어서 Git Bash를 먼저 찾는다."""
    if sys.platform == 'win32':
        for p in (r'C:\Program Files\Git\bin\bash.exe', r'C:\Program Files (x86)\Git\bin\bash.exe'):
            if os.path.exists(p):
                return p
    found = shutil.which('bash')
    if found and sys.platform == 'win32' and 'system32' in found.lower():
        return None  # WSL 런처는 cwd/경로 동작이 달라 쓰지 않는다
    return found


def find_powershell():
    return shutil.which('powershell') or shutil.which('pwsh')


def run_bash(bash, cmd, cwd):
    r = subprocess.run([bash, '-c', cmd], cwd=cwd, capture_output=True, text=True, timeout=60)
    return (r.stdout or '') + (r.stderr or '')


def run_powershell(ps, cmd):
    r = subprocess.run([ps, '-NoProfile', '-NonInteractive', '-Command', cmd],
                       capture_output=True, text=True, timeout=60)
    return (r.stdout or '') + (r.stderr or '')
