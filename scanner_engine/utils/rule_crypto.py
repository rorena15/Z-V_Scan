# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[rules/*_rules.json 보호] PyArmor는 .py 코드만 보호하고 데이터 파일은 손대지
않아서, rules/*_rules.json(KISA 판정 로직·조치방안 전체)이 지금까지 배포판에
평문 그대로 담겨 있었다. onedir 빌드로 바꾸면 설치 폴더에서 그냥 열어볼 수
있게 되므로, 빌드 시점에 이 파일들을 암호화해서 배포하고 실행 중에만
메모리에서 복호화한다(디스크에 평문을 쓰지 않음).

db_crypto.py와 달리 키를 OS 자격증명 관리자(keyring)에 두지 않는다 - db_crypto는
"사용자 PC에서 실행 중 생성된 데이터"를 그 PC만 다시 열 수 있으면 되지만, 이
모듈은 "개발자가 빌드 시점에 암호화한 파일을 모든 고객의 PC에서 복호화"해야
하므로 키가 배포되는 실행파일 자체에 포함돼 있어야 한다(AppConfig.RULE_ENCRYPTION_KEY,
LICENSE_SALT/ENGINE_ACCESS_TOKEN과 동일한 신뢰 모델 - PyArmor 보호에 기대는
수준이며 완벽한 DRM은 아니다).

load_ruleset()은 "{path}.enc"가 있으면 그걸 복호화하고, 없으면 개발 중
편의를 위해 평문 {path}를 그대로 읽는다 - 로컬에서 rules/*.json을 직접
수정하며 바로 실행/테스트하는 기존 개발 흐름은 전혀 안 바뀐다. .enc는
오직 ci/encrypt_rules.py가 빌드 스테이징 단계에서만 만든다.
"""
import json
import os
from cryptography.fernet import Fernet, InvalidToken
from core.config import AppConfig


def get_enc_path(plain_path):
    return plain_path + ".enc"


def ruleset_exists(plain_path):
    """각 inspector의 `_get_rules_path()`류가 external(exe 옆)/internal(_MEIPASS
    번들) 경로 중 어느 쪽을 쓸지 os.path.exists()로 고르는데, 배포판에서는
    plain_path 자체가 아니라 plain_path+".enc"만 존재한다. 그 판단에 이 헬퍼를
    쓰면 평문/암호화 두 경우 모두 올바르게 "이 경로에 룰셋이 있다"고 인식한다."""
    return os.path.exists(plain_path) or os.path.exists(get_enc_path(plain_path))


def _get_fernet():
    return Fernet(AppConfig.RULE_ENCRYPTION_KEY.encode())


def encrypt_ruleset_file(plain_path, enc_path=None):
    """빌드 스테이징 전용(ci/encrypt_rules.py에서 호출). 평문 JSON을 읽어
    유효성만 확인하고(깨진 JSON을 암호화해서 나중에야 발견하는 사고 방지)
    Fernet으로 암호화해 enc_path에 쓴다."""
    if enc_path is None:
        enc_path = get_enc_path(plain_path)

    with open(plain_path, 'r', encoding='utf-8') as f:
        raw = f.read()
    json.loads(raw)  # 유효성 검증 - 여기서 바로 실패시키는 게 낫다

    blob = _get_fernet().encrypt(raw.encode('utf-8'))
    with open(enc_path, 'wb') as f:
        f.write(blob)


def load_ruleset(plain_path):
    """반환: json.loads()한 파이썬 객체(list/dict). 기존 호출부들의
    `with open(path) as f: json.load(f)` 두 줄을 대체하는 1:1 교체용이라,
    호출부의 try/except나 os.path.exists() 사전 체크는 그대로 둬도 된다
    (파일이 아예 없으면 이 함수도 FileNotFoundError를 그대로 던진다)."""
    enc_path = get_enc_path(plain_path)
    try:
        with open(enc_path, 'rb') as f:
            blob = f.read()
    except FileNotFoundError:
        # 배포판이 아니라 개발 환경(소스에서 직접 실행) - 평문 폴백
        with open(plain_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    try:
        raw = _get_fernet().decrypt(blob)
    except InvalidToken as e:
        raise ValueError(
            f"룰셋 복호화 실패 - 키가 안 맞거나 파일이 손상됨: {enc_path}"
        ) from e

    return json.loads(raw)
