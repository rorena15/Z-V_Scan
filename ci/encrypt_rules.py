# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[빌드 전용] rules/*_rules.json(KISA 판정 로직·조치방안 - 이 제품의 핵심 IP)을
암호화해서 별도 스테이징 폴더에 담는다. PyInstaller의 --add-data는 이 스테이징
폴더를 "rules"라는 이름으로 배포판에 넣도록 build_final_v3.ps1에서 바뀐다 -
평문 rules/*.json 자체는 절대 배포판에 포함시키지 않는 게 이 스크립트의 핵심 목적.

- *_rules.json  -> {name}.json.enc (암호화, utils/rule_crypto.py가 실행 중 복호화)
- 그 외 파일(ruleset_manifest.json, oui_database.txt, signatures.json 등)
  -> 그대로 복사 (판정 로직 자체가 아니거나 공개 데이터라 보호 대상 아님)

git 추적되는 rules/*.json 원본은 절대 건드리지 않는다(읽기만 함) - 개발자가
평소처럼 그 파일을 직접 열어 수정하는 흐름과 완전히 분리돼 있다.

사용법: python ci/encrypt_rules.py <rules_src_dir> <staged_dst_dir>
"""
import os
import sys
import shutil

_CI_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_CI_DIR)
_SCANNER_ENGINE = os.path.join(_PROJECT_ROOT, "scanner_engine")
if _SCANNER_ENGINE not in sys.path:
    sys.path.insert(0, _SCANNER_ENGINE)

from utils import rule_crypto  # noqa: E402


def stage_rules(src_dir, dst_dir):
    if os.path.isdir(dst_dir):
        shutil.rmtree(dst_dir)
    os.makedirs(dst_dir, exist_ok=True)

    encrypted, copied = 0, 0
    for filename in sorted(os.listdir(src_dir)):
        src_path = os.path.join(src_dir, filename)
        if not os.path.isfile(src_path):
            continue

        if filename.endswith("_rules.json"):
            enc_path = os.path.join(dst_dir, filename + ".enc")
            rule_crypto.encrypt_ruleset_file(src_path, enc_path)
            print(f"[encrypt] {filename} -> {os.path.basename(enc_path)}")
            encrypted += 1
        elif filename.endswith(".json") or filename.endswith(".txt"):
            # ruleset_manifest.json / oui_database.txt / signatures.json 등 -
            # 판정 로직 데이터가 아니거나 공개 데이터라 암호화 대상 아님.
            shutil.copy2(src_path, os.path.join(dst_dir, filename))
            print(f"[copy]    {filename}")
            copied += 1
        else:
            # HANDOVER_U-01_판정로직_검토.md 같은 개발용 문서 등 - 배포판에
            # 넣을 이유가 없는 파일은 조용히 건너뛴다.
            print(f"[skip]    {filename}")

    print(f"\nDone: {encrypted} ruleset(s) encrypted, {copied} file(s) copied as-is.")
    if encrypted == 0:
        print("WARNING: *_rules.json 파일을 하나도 못 찾았습니다 - 경로를 확인하세요.")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python ci/encrypt_rules.py <rules_src_dir> <staged_dst_dir>")
        sys.exit(1)
    stage_rules(sys.argv[1], sys.argv[2])
