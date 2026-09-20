"""릴리즈용 비밀값 3개를 새로 만들어 화면에 한 번 출력한다(로컬에서 직접 실행).

    python ci/gen_release_secrets.py

출력된 값을 GitHub 저장소 Settings > Secrets and variables > Actions에 아래 이름으로 등록한다:
    ZVULN_LICENSE_SALT, ZVULN_RULE_KEY, ZVULN_ENGINE_TOKEN
그리고 같은 값을 **안전한 곳(비밀번호 관리자 등)에 따로 보관**한다 - 분실하면 이미 발급한 라이선스 키와
이미 배포한 룰셋 업데이트를 검증/복호화할 수 없다. 저장소, 채팅, 이슈, 로그에 붙여넣지 않는다.

라이선스 키를 실제 salt로 발급할 때는 keygen을 같은 값으로 실행한다:
    set ZVULN_LICENSE_SALT=<값>   (PowerShell: $env:ZVULN_LICENSE_SALT="<값>")
    python scanner_engine/keygen.py ...
"""
import secrets

from cryptography.fernet import Fernet


def main():
    print("아래 3줄을 GitHub Actions 시크릿으로 등록하고 안전한 곳에 따로 보관하세요.\n")
    print("ZVULN_LICENSE_SALT=" + secrets.token_urlsafe(32))
    print("ZVULN_RULE_KEY=" + Fernet.generate_key().decode())
    print("ZVULN_ENGINE_TOKEN=" + secrets.token_urlsafe(32))


if __name__ == "__main__":
    main()
