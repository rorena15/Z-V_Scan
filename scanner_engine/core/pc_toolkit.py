# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[PC 진단 도구] 업무용 PC는 WinRM이 기본 비활성화돼 있어 windows_inspector.py의
원격 접속 경로가 실무에서 동작하지 않는 경우가 많다. 이 모듈은 그 대안으로,
rules/pc_rules.json을 그대로 읽어 판정 로직 없이 "증거만 수집"하는 로컬 실행용
PowerShell 스크립트를 생성한다.

판정(judge_rule)은 절대 이 스크립트 안에서 재구현하지 않는다 - pc_rules.json이
바뀔 때마다 이 스크립트도 따로 고쳐야 하는 로직 이중 관리를 피하기 위함이다.
생성된 스크립트가 만드는 TXT 파일은 crosscheck_parser.py의 스크립트 포맷 파서가
그대로 읽고, crosscheck_engine.import_pc_results()가 동일한 judge_rule()로
재판정해 TBL_SCAN_RESULT에 반영한다.
"""
import os
import sys
import json

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from utils import rule_crypto

# windows_inspector.py와 동일한 공유 secedit 캐시 경로 - 로컬 스크립트도 같은 경로를
# 써야 C:\zvulnscan_secpol_cache.cfg를 참조하는 PC-01/02 등 criteria 서브커맨드가 동작한다.
SECEDIT_CACHE_PATH = r"C:\zvulnscan_secpol_cache.cfg"


def _get_pc_rules_path():
    """windows_inspector.py._get_rules_path()와 동일한 frozen/_MEIPASS 분기."""
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    external_path = os.path.join(base_dir, 'rules', 'pc_rules.json')
    if hasattr(sys, '_MEIPASS'):
        internal_path = os.path.join(sys._MEIPASS, 'rules', 'pc_rules.json')
        if not rule_crypto.ruleset_exists(external_path) and rule_crypto.ruleset_exists(internal_path):
            return internal_path
    return external_path


def load_pc_rules():
    path = _get_pc_rules_path()
    return rule_crypto.load_ruleset(path)


def generate_pc_script():
    """pc_rules.json 기반 로컬 진단 PowerShell 스크립트 문자열을 반환한다.

    각 룰의 최상위 command뿐 아니라, criteria(세부기준) 중 자체 command가 있는
    항목도 각각 실제로 실행해 [CRIT:N] 블록으로 캡처한다(criteria 등장 순서 중
    command가 있는 것만 0부터 순번). 라이브 WinRM 스캔이 세부기준마다 개별
    명령을 실행하는 것과 동일한 증거 수집 방식이다 - crosscheck_parser.py가
    이 [CRIT:N] 블록을 읽어 record["criteria_outputs"]로 넘기면,
    crosscheck_engine.rejudge_record()가 그걸로 execute_fn을 구성해 judge_rule()이
    세부기준마다 실제 증거로 개별 판정하게 한다(근사치가 아님). command가 없는
    criteria는 원래부터 최상위 raw_output을 그대로 재사용하도록 설계돼 있어
    (judge_rule 자체 동작) 여기서 별도로 실행/캡처할 필요가 없다.

    [증적 보강] pc_rules.json의 command/criteria.command는 판정용으로 이미
    OK/FAIL 등을 계산해서 내놓기 때문에(예: PC-01 top command는 값 1개만 추출),
    실제 KISA 대조검증 스크립트가 리포트에 남기는 원본 값 전체(secpol 여러 키,
    net share 목록, bcdedit 전체 등)에 비하면 사람이 볼 증적이 빈약하다. 그래서
    rule.get('evidence_command')가 있으면 그 결과를 [EVIDENCE] 블록으로 추가
    캡처한다 - 이건 오직 사람이 보는 raw_output(리포트 상세 증적)용이고,
    judge_rule()의 판정 입력(record["raw_output"])에는 절대 섞이지 않는다
    (crosscheck_parser._parse_consultant_body가 [EVIDENCE]를 판정용 raw_output과
    분리해서 파싱함) - 그래서 이 증적을 추가해도 기존 판정 로직에 회귀가 없다.
    """
    rules = load_pc_rules()

    lines = [
        "# Z-VulnScan PC 로컬 진단 스크립트 (자동 생성됨 - 수정하지 마세요)",
        "# 이 파일을 직접 실행하지 말고, 같은 폴더의 동봉된 .bat 파일을 더블클릭하세요",
        "# (관리자 권한 승인 창이 자동으로 뜹니다). 결과 TXT 파일이 이 스크립트와 같은",
        "# 폴더에 생성됩니다 - 그 파일을 Z-VulnScan의 'PC 진단 도구 > 결과 가져오기'로 불러오세요.",
        "# [버그 수정] $ErrorActionPreference를 전역으로 SilentlyContinue로 두면 reg query 등",
        "# 네이티브 명령이 '키/값 없음'을 stderr로 낼 때 2>&1로 리다이렉트해도 그 내용 자체가",
        "# 사라진다(실측 확인) - 그래서 여기서는 설정하지 않는다. 위험한 개별 cmdlet에는",
        "# 이미 각자 -ErrorAction SilentlyContinue가 붙어 있고, 룰별 실행은 모두 try/catch로",
        "# 감싸여 있어 전역 설정 없이도 스크립트가 중간에 멈추지 않는다.",
        "$hostname = $env:COMPUTERNAME",
        "$ipAddr = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | "
        "Select-Object -First 1 -ExpandProperty IPAddress)",
        "if (-not $ipAddr) { $ipAddr = '0.0.0.0' }",
        "$dateStr = Get-Date -Format 'yyyyMMdd'",
        "$outFile = Join-Path $PSScriptRoot \"[PC]${hostname}_Windows_${ipAddr}_${dateStr}.txt\"",
        "# [주의] 파일명의 대괄호를 PowerShell이 와일드카드로 해석해 -Path로는 파일 생성이",
        "# 조용히 실패한다 - 반드시 -LiteralPath를 사용한다.",
        "Set-Content -LiteralPath $outFile -Value '' -Encoding UTF8",
        "",
    ]

    # SYSTEM Detail 부록(스크립트 끝부분)이 항상 secpol 전체 덤프를 보여주므로,
    # 개별 룰이 캐시를 안 쓰더라도 이 스크립트는 항상 secedit을 내보낸다.
    lines.append(f"secedit /export /cfg '{SECEDIT_CACHE_PATH}' | Out-Null")
    lines.append("")

    # [버그 수정] 명령을 "Invoke-Expression $cmd 2>&1 | Out-String"으로 돌리면 reg query 등
    # 네이티브 명령이 "키/값이 존재하지 않음" 같은 stderr 메시지를 낼 때 그 내용이 조용히
    # 사라진다(레지스트리 키가 아예 없는, 자주 발생하는 취약 상황의 증거가 빈 문자열이 됨) -
    # 실측으로 확인됨(동일 명령을 "& ([scriptblock]::Create($cmd)) 2>&1"로 돌리면 정상 캡처됨,
    # 정상 실행 시 결과는 두 방식이 동일함). 그래서 아래 세 곳(top/criteria/evidence) 모두
    # scriptblock 방식을 쓴다.
    for i, rule in enumerate(rules):
        code = rule.get('code', f'PC-{i}')
        name = (rule.get('name', code) or code).replace('"', "'")
        command = rule.get('command', '') or ''
        var = f"cmd{i}"

        lines.append(f"${var} = @'")
        lines.append(command)
        lines.append("'@")
        lines.append(
            f"$out{i} = try {{ & ([scriptblock]::Create(${var})) 2>&1 | Out-String }} "
            f"catch {{ \"ERROR: $($_.Exception.Message)\" }}"
        )
        lines.append(f'Add-Content -LiteralPath $outFile -Value "[{code}] {name}" -Encoding UTF8')
        lines.append("Add-Content -LiteralPath $outFile -Value '[START]' -Encoding UTF8")
        lines.append(f"Add-Content -LiteralPath $outFile -Value $out{i} -Encoding UTF8")

        crit_cmds = [c for c in (rule.get('criteria') or []) if c.get('command')]
        for cidx, crit in enumerate(crit_cmds):
            cvar = f"crit{i}_{cidx}"
            lines.append(f"${cvar} = @'")
            lines.append(crit['command'])
            lines.append("'@")
            lines.append(
                f"$cout{i}_{cidx} = try {{ & ([scriptblock]::Create(${cvar})) 2>&1 | Out-String }} "
                f"catch {{ \"ERROR: $($_.Exception.Message)\" }}"
            )
            lines.append(f"Add-Content -LiteralPath $outFile -Value '[CRIT:{cidx}]' -Encoding UTF8")
            lines.append(f"Add-Content -LiteralPath $outFile -Value $cout{i}_{cidx} -Encoding UTF8")

        evidence_command = rule.get('evidence_command')
        if evidence_command:
            evar = f"evi{i}"
            lines.append(f"${evar} = @'")
            lines.append(evidence_command)
            lines.append("'@")
            lines.append(
                f"$eout{i} = try {{ & ([scriptblock]::Create(${evar})) 2>&1 | Out-String }} "
                f"catch {{ \"ERROR: $($_.Exception.Message)\" }}"
            )
            lines.append("Add-Content -LiteralPath $outFile -Value '[EVIDENCE]' -Encoding UTF8")
            lines.append(f"Add-Content -LiteralPath $outFile -Value $eout{i} -Encoding UTF8")

        lines.append("Add-Content -LiteralPath $outFile -Value '[END]' -Encoding UTF8")
        lines.append("Add-Content -LiteralPath $outFile -Value '' -Encoding UTF8")
        lines.append("")

    # [증적 보강] 실제 KISA 대조검증 스크립트(00. Script/04. PC/2026_ICTIS_PC_v0.9.bat)는 18개
    # 룰 뒤에 systeminfo/ipconfig/포트/서비스 전체/secpol 전체/설치 프로그램 목록을 "SYSTEM
    # Detail" 부록으로 덧붙인다 - 이 부분이 실제 산출물을 훨씬 충실해 보이게 하는 핵심이었다.
    # 특정 KISA 코드에 안 묶인 참고 정보라 [START]/[END]로 감싸지 않는다 - crosscheck_parser는
    # [START]/[END] 블록 밖의 텍스트는 그냥 무시하므로 파싱에 영향 없음.
    lines.append("Add-Content -LiteralPath $outFile -Value '' -Encoding UTF8")
    lines.append("Add-Content -LiteralPath $outFile -Value '----------------------------------------------------' -Encoding UTF8")
    lines.append("Add-Content -LiteralPath $outFile -Value '                     SYSTEM Detail' -Encoding UTF8")
    lines.append("Add-Content -LiteralPath $outFile -Value '----------------------------------------------------' -Encoding UTF8")
    lines.append("Add-Content -LiteralPath $outFile -Value '' -Encoding UTF8")

    detail_sections = [
        ("[시스템 정보]", "systeminfo"),
        ("[IP 정보]", "ipconfig /all"),
        ("[PORT 정보]", "netstat -abn | Select-String -NotMatch 'TIME_WAIT'"),
        ("[서비스 정보]", "Get-CimInstance Win32_Service | Select-Object DisplayName, StartMode, State | Format-Table -AutoSize"),
        ("[정책 정보]", f"Get-Content '{SECEDIT_CACHE_PATH}'"),
        ("[설치프로그램 정보]",
         "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s /v DisplayName "
         "| Select-String 'DisplayName'"),
    ]
    for idx, (label, det_command) in enumerate(detail_sections):
        dvar = f"detail{idx}"
        lines.append(f"${dvar} = @'")
        lines.append(det_command)
        lines.append("'@")
        lines.append(
            f"$dout{idx} = try {{ & ([scriptblock]::Create(${dvar})) 2>&1 | Out-String }} "
            f"catch {{ \"ERROR: $($_.Exception.Message)\" }}"
        )
        lines.append(f"Add-Content -LiteralPath $outFile -Value '{label}' -Encoding UTF8")
        lines.append("Add-Content -LiteralPath $outFile -Value '' -Encoding UTF8")
        lines.append(f"Add-Content -LiteralPath $outFile -Value $dout{idx} -Encoding UTF8")
        lines.append("Add-Content -LiteralPath $outFile -Value '' -Encoding UTF8")

    lines.append(f"Remove-Item '{SECEDIT_CACHE_PATH}' -Force -ErrorAction SilentlyContinue")
    lines.append("")
    lines.append('Write-Host "완료: $outFile"')
    return "\r\n".join(lines)


def generate_pc_launcher_bat(ps1_filename):
    """.ps1을 더블클릭만으로 실행할 수 있게 하는 동봉용 .bat 런처.

    .ps1은 Windows 탐색기 기본 동작이 "실행"이 아니라 "편집"이라 더블클릭으로
    안 돌아가고, 설령 "PowerShell로 실행"을 골라도 관리자 권한 프롬프트가 뜨지
    않아 secedit/레지스트리(HKLM) 등 PC-01/02류 점검이 조용히 실패한다. .bat은
    탐색기에서 더블클릭 시 기본 실행되므로, 여기서 관리자 권한 여부를 확인해
    아니면 UAC 승인 창을 띄워 자기 자신을 재실행한 뒤 .ps1을 돌린다.

    본문은 영문 ASCII만 쓴다 - cmd.exe는 이 .bat의 저장 인코딩(UTF-8)을 기본
    코드페이지로 잘못 해석해 한글 echo/주석이 깨지거나, 대상 PC가 비한국어
    로케일이면 더 예측 불가능해질 수 있어 인코딩 문제 자체를 피한다.
    """
    lines = [
        "@echo off",
        "setlocal",
        "",
        ":: Check for admin rights - if not elevated, relaunch via UAC prompt",
        "net session >nul 2>&1",
        "if %errorLevel% NEQ 0 (",
        "    powershell -NoProfile -Command \"Start-Process -FilePath '%~f0' -Verb RunAs\"",
        "    exit /b",
        ")",
        "",
        "cd /d \"%~dp0\"",
        f'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0{ps1_filename}"',
        "",
        "echo.",
        "echo Done. You can close this window.",
        "pause >nul",
    ]
    return "\r\n".join(lines)
