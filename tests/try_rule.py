"""값을 바꿔가며 룰 판정을 바로 확인하는 도구 (VM/대상 시스템 없이, 이 PC의 임시 환경에서).

사용 예 (저장소 루트에서):
  # Windows 레지스트리 룰 - 진짜 경로 그대로 값을 지정 (int는 DWord, 그 외는 문자열)
  python tests\\try_rule.py W-47 --reg "HKCU\\Control Panel\\Desktop:ScreenSaveActive=1" ^
                                 --reg "HKCU\\Control Panel\\Desktop:ScreenSaveTimeOut=300"
  # Windows secedit(보안 정책) 기반 룰 (W-04/08/09/11/40 ...)
  python tests\\try_rule.py W-04 --secpol "LockoutBadCount = 3"
  # Linux 룰 - 파일 내용 지정 (\\n 은 줄바꿈)
  python tests\\try_rule.py U-12 --file "etc/profile=TMOUT=300\\nexport TMOUT"
  python tests\\try_rule.py U-02 --file "etc/security/pwquality.conf=minlen = 10" --file "etc/login.defs=PASS_MAX_DAYS 90"
  # 아무 설정도 안 준 상태(미설정)로 보기
  python tests\\try_rule.py W-54
옵션: --show-commands 룰이 실행하는 명령도 같이 출력
"""
import argparse
import sys

import _fixture_env as fx
import _helpers as h


def parse_reg(spec):
    if ':' not in spec or '=' not in spec:
        raise SystemExit(f"--reg 형식 오류: {spec}  (예: HKLM\\SYSTEM\\...\\Parameters:SynAttackProtect=1)")
    path, rest = spec.rsplit(':', 1)
    name, value = rest.split('=', 1)
    return path, name.strip(), (int(value) if value.strip().lstrip('-').isdigit() else value)


def main():
    ap = argparse.ArgumentParser(description="룰 하나를 가짜 환경에서 실행해 판정을 확인한다.")
    ap.add_argument('code', help="룰 코드 (예: W-47, U-12)")
    ap.add_argument('--reg', action='append', default=[], help="레지스트리 값: '경로:이름=값'")
    ap.add_argument('--secpol', help="secedit 보안 정책 텍스트 (예: 'LockoutBadCount = 3')")
    ap.add_argument('--file', action='append', default=[], help="Linux 파일: '상대경로=내용' (\\n 줄바꿈)")
    ap.add_argument('--show-commands', action='store_true')
    args = ap.parse_args()

    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    reg = []
    for spec in args.reg:
        path, name, value = parse_reg(spec)
        reg.append({"path": path, "name": name, "value": value})
    files = {}
    for spec in args.file:
        rel, content = spec.split('=', 1)
        files[rel] = content.replace('\\n', '\n')
    secpol = args.secpol.replace('\\n', '\n') if args.secpol is not None else None

    res = fx.evaluate(args.code, reg=reg, secpol=secpol, files=files)
    print(f"룰: {res['rule']} {res['name']}  (중요도 {res['importance']})")
    if args.show_commands:
        rule = next(r[args.code] for r in (h.load_rules(f) for f in fx.LOCAL_RULESETS) if args.code in r)
        print("\n[최상위 명령]\n" + (rule.get('command') or '(없음)'))
        for c in rule.get('criteria') or []:
            print(f"[세부기준] {c['label']}\n  {c.get('command', '(최상위 출력 재사용)')}")
        print()
    if not res['criteria']:
        print(f"  명령 출력: {res['top_output'] or '(빈 출력)'}")
    for c in res['criteria']:
        print(f"  · {c['label']}  ->  {c['output'] or '(빈 출력)'}")
    print(f"\n판정: {res['status']}\n사유: {res['detail']}")


if __name__ == '__main__':
    main()
