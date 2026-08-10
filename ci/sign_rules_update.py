# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[개발자 전용 - 로컬 서명, CI에서 절대 실행하지 않음] 릴리즈마다 로컬 PC에서
수동으로 실행한다. ci/encrypt_rules.py가 만든 rules_staged/ 폴더 전체를
rules_update.zip으로 묶고, Ed25519 개인키로 서명해 rules_update.zip.sig(서명,
base64 텍스트)를 만든다. 이 두 파일을 GitHub Release 자산으로 첨부하면
utils/rule_update.py가 config/rule_update_config.json의 공개키로 검증한다.

개인키를 CI 시크릿에 올리지 않는 이유는 utils/rule_update.py 모듈 docstring
참고 - GitHub 계정 탈취가 곧 서명 위조로 이어지는 걸 막기 위함이다. 이
스크립트도 같은 이유로 로컬 전용이며, <private_key_path>에 평문 키 파일을
오래 두지 않는 걸 권장한다(하드웨어 보안키에서 서명 시점에만 꺼내 쓰고
직후 삭제하는 운영 절차 - 이 스크립트 자체가 강제하지는 않는다).

사용법:
    python ci/sign_rules_update.py <rules_staged_dir> <output_dir> <private_key_path>

<private_key_path>는 base64 인코딩된 32바이트 Ed25519 개인키가 담긴 텍스트 파일.
"""
import sys
import os
import io
import base64
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_ZIP_NAME = "rules_update.zip"
_SIG_NAME = "rules_update.zip.sig"


def _build_zip_bytes(rules_staged_dir):
    """rules_staged_dir 안의 파일들을 서브폴더 없이 압축 최상위에 그대로 담는다 -
    utils/rule_update.py가 zf.extractall(rules_dir)로 그대로 풀기 때문에,
    여기서 폴더 구조가 어긋나면 exe 옆 rules/ 폴더 구조도 같이 어긋난다."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filename in sorted(os.listdir(rules_staged_dir)):
            src_path = os.path.join(rules_staged_dir, filename)
            if os.path.isfile(src_path):
                zf.write(src_path, arcname=filename)
    return buf.getvalue()


def _load_private_key(private_key_path):
    with open(private_key_path, 'r', encoding='utf-8') as f:
        key_bytes = base64.b64decode(f.read().strip())
    return Ed25519PrivateKey.from_private_bytes(key_bytes)


def main():
    if len(sys.argv) != 4:
        print("사용법: python ci/sign_rules_update.py <rules_staged_dir> <output_dir> <private_key_path>")
        sys.exit(1)

    rules_staged_dir, output_dir, private_key_path = sys.argv[1:4]

    if not os.path.isdir(rules_staged_dir):
        print(f"오류: rules_staged_dir가 없습니다 - 먼저 ci/encrypt_rules.py를 실행하세요: {rules_staged_dir}")
        sys.exit(1)
    if 'ruleset_manifest.json' not in os.listdir(rules_staged_dir):
        print("오류: rules_staged_dir에 ruleset_manifest.json이 없습니다 - "
              "버전 비교가 불가능해 클라이언트가 이 업데이트를 절대 적용하지 않습니다.")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)
    zip_bytes = _build_zip_bytes(rules_staged_dir)

    private_key = _load_private_key(private_key_path)
    signature = private_key.sign(zip_bytes)
    sig_b64 = base64.b64encode(signature).decode()

    zip_path = os.path.join(output_dir, _ZIP_NAME)
    sig_path = os.path.join(output_dir, _SIG_NAME)
    with open(zip_path, 'wb') as f:
        f.write(zip_bytes)
    with open(sig_path, 'w', encoding='utf-8') as f:
        f.write(sig_b64)

    print(f"완료: {zip_path}")
    print(f"완료: {sig_path}")
    print("\n이 두 파일을 GitHub Release 자산으로 첨부하세요.")
    print(f"({private_key_path}의 개인키는 이제 안전한 곳(하드웨어 보안키)으로만 남기고 이 PC에서는 삭제를 권장합니다.)")


if __name__ == "__main__":
    main()
