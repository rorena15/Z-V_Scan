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
        "# 이 아래는 generate_pc_script_bat()이 배치 헤더 뒤에 이어붙이는 PowerShell 본문이다.",
        "# $ZVScriptDir는 이 스크립트가 단독 .ps1로 실행될 일이 없다는 전제로(항상 배치",
        "# 헤더의 iex 경유로만 실행됨) 배치 헤더 쪽에서 미리 주입해주는 변수다 - iex로 실행된",
        "# 코드는 $PSScriptRoot가 항상 비어 있어(파일로 직접 실행할 때만 채워짐) 대신 쓴다.",
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
        "$outFile = Join-Path $ZVScriptDir \"[PC]${hostname}_Windows_${ipAddr}_${dateStr}.txt\"",
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

    # [증적 보강] 개별 룰 항목만으로는 사람이 눈으로 볼 증적이 빈약해서, systeminfo/ipconfig/
    # 포트/서비스 전체/secpol 전체/설치 프로그램 목록을 "SYSTEM Detail" 부록으로 뒤에
    # 덧붙인다 - 모두 Z-VulnScan 자체 판단으로 선택한, PC 진단에 흔히 쓰이는 표준 Windows
    # 명령이다. 특정 KISA 코드에 안 묶인 참고 정보라 [START]/[END]로 감싸지 않는다 -
    # crosscheck_parser는 [START]/[END] 블록 밖의 텍스트는 그냥 무시하므로 파싱에 영향 없음.
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


def generate_pc_script_bat():
    """generate_pc_script()의 PowerShell 진단 로직을, 대상 PC에 파일 하나만 넘기면
    되도록 배치/PowerShell "폴리글랏" 단일 .bat 파일로 감싸서 반환한다.

    예전에는 .ps1(본문) + .bat(실행기) 두 파일을 함께 넘겨야 했다 - .ps1은 탐색기
    기본 동작이 "실행"이 아니라 "편집"이라 더블클릭으로 안 돌아가고, "PowerShell로
    실행"을 골라도 관리자 권한 프롬프트가 뜨지 않아 secedit/레지스트리(HKLM) 등
    PC-01/02류 점검이 조용히 실패했기 때문이다. 두 파일을 따로 옮기다 하나를
    빠뜨리는 실수를 없애기 위해 한 파일로 합쳤다.

    동작 원리: 파일 앞부분을 PowerShell 블록 코멘트(`<# ... #>`)로 감싼 배치
    스크립트로 시작한다. cmd.exe로 실행(더블클릭)하면 `<# :`/`#>` 줄은 그냥 지나치고
    안의 배치 명령만 실행되어, 관리자 권한을 확인하고 없으면 UAC 승인 창을 띄워
    자기 자신(`%~f0`)을 재실행한다. 권한이 있으면 PowerShell을 불러 자기 자신을
    다시 텍스트로 읽어(`[IO.File]::ReadAllText`) `iex`로 실행하는데, 이번엔
    PowerShell이 파일을 파싱하므로 `<# ... #>`로 감싼 배치 부분은 코멘트로 건너뛰고
    그 아래 실제 PowerShell 본문만 실행된다.

    [주의] 반드시 CRLF(\\r\\n) 줄바꿈으로 저장해야 한다 - cmd.exe는 LF만 있는 배치
    파일에서 줄 파싱이 깨진다(각 줄 앞부분 글자가 무작위로 잘려나가는 것을 실측
    확인함). [주의] 파일 저장 인코딩과 위 ReadAllText의 인코딩이 반드시 일치해야
    한다 - 대상 PC 대부분이 한국어 Windows(cp949)이므로 cp949로 통일한다
    (호출부인 pc_toolkit_dialog.py에서 인코딩을 맞춰 저장한다).
    """
    ps1_body = generate_pc_script()

    header = [
        "<# :",
        "@echo off",
        "setlocal",
        "",
        ":: 관리자 권한 확인 - 아니면 UAC 승인 창을 띄워 자기 자신을 재실행",
        "net session >nul 2>&1",
        "if %errorLevel% NEQ 0 (",
        "    powershell -NoProfile -Command \"Start-Process -FilePath '%~f0' -Verb RunAs\"",
        "    exit /b",
        ")",
        "",
        "cd /d \"%~dp0\"",
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"$ZVScriptDir = '%~dp0'; iex ([IO.File]::ReadAllText('%~f0', "
        "[System.Text.Encoding]::GetEncoding(949)))\"",
        "",
        "echo.",
        "echo Done. You can close this window.",
        "pause >nul",
        "exit /b",
        "#>",
        "",
    ]
    return "\r\n".join(header) + ps1_body
