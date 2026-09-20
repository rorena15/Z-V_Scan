"""배포 빌드용 비밀값을 scanner_engine/core/config.py에 주입한다(CI 러너의 작업 복사본에서만 실행 - 커밋 금지).

저장소의 config.py에는 개발 전용 더미 값만 있고, 실제 값은 환경변수(GitHub Actions 시크릿)로 받는다:
    ZVULN_LICENSE_SALT   라이선스 키 검증용 salt (16자 이상)
    ZVULN_RULE_KEY       룰셋 암호화용 Fernet 키 (ci/gen_release_secrets.py가 만든 값)
    ZVULN_ENGINE_TOKEN   엔진 내부 토큰 (16자 이상)

사용:  python ci/inject_release_secrets.py [--config 경로]
- 셋 중 하나라도 없거나 형식이 틀리면 실패한다(더미 값으로 릴리즈가 만들어지는 일을 막는다).
- 이 스크립트는 값 자체를 출력하지 않는다.
"""
import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG = os.path.join(ROOT, "scanner_engine", "core", "config.py")

# (config.py 상수 이름, 환경변수 이름)
SECRETS = (
    ("LICENSE_SALT", "ZVULN_LICENSE_SALT"),
    ("RULE_ENCRYPTION_KEY", "ZVULN_RULE_KEY"),
    ("ENGINE_ACCESS_TOKEN", "ZVULN_ENGINE_TOKEN"),
)


def validate(const, value):
    if not value or not value.strip():
        return "비어 있음"
    if value != value.strip() or any(c in value for c in "\"'\\\n\r"):
        return "공백/따옴표/역슬래시/줄바꿈을 포함할 수 없음"
    if value.upper().startswith("DEV-ONLY"):
        return "개발 전용 더미 값임"
    if const == "RULE_ENCRYPTION_KEY":
        try:
            from cryptography.fernet import Fernet
            Fernet(value.encode())
        except Exception:
            return "올바른 Fernet 키가 아님(ci/gen_release_secrets.py로 생성)"
    elif len(value) < 16:
        return "16자 미만"
    return None


def inject(config_path, env):
    with open(config_path, encoding="utf-8") as f:
        text = f.read()
    problems = []
    for const, var in SECRETS:
        value = env.get(var)
        err = validate(const, value)
        if err:
            problems.append(f"{var}: {err}")
            continue
        pattern = re.compile(rf'^(\s*{const}\s*=\s*)"[^"\n]*"', re.MULTILINE)
        if not pattern.search(text):
            problems.append(f"{const}: config.py에서 대입 줄을 찾지 못함")
            continue
        text = pattern.sub(lambda m: f'{m.group(1)}"{value}"', text, count=1)
    if problems:
        raise SystemExit("릴리즈 비밀값 주입 실패:\n  - " + "\n  - ".join(problems))
    with open(config_path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    args = ap.parse_args()
    inject(args.config, os.environ)
    print(f"릴리즈 비밀값 {len(SECRETS)}개 주입 완료 ({os.path.basename(args.config)}) - 이 변경은 커밋하지 마세요")


if __name__ == "__main__":
    main()
