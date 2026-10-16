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
import sys
from cryptography.fernet import Fernet, InvalidToken
from core.config import AppConfig

# [버그 수정 - 중복 제거] db_connector.py/text_report.py/excel_report.py 세 곳에
# RULE_FILES/IMPORTANCE_WEIGHT가 각각 복사돼 있었다 - 이 모듈로 통합.
# [빌드 제약] 원래는 별도 파일(utils/rule_constants.py)로 뽑았었는데, PyArmor
# 트라이얼 라이선스가 난독화 가능한 파일 개수에 상한이 있어 새 .py 파일을 하나
# 늘리는 것만으로 "out of license" 빌드 실패가 났다 - 이미 존재하는(그리고
# 룰셋을 다루는 성격이 같은) 이 파일에 합쳐서 전체 파일 수를 세션 시작 시점과
# 동일하게 유지한다.
RULE_FILES = {
    "linux_rules.json": "",
    "windows_rules.json": "",
    "pc_rules.json": "",
    "mysql_rules.json": "MYSQL-",
    "postgresql_rules.json": "POSTGRESQL-",
    "mssql_rules.json": "MSSQL-",
    "oracle_rules.json": "ORACLE-",
    "web_rules.json": "",
    "network_cisco_rules.json": "",
    "network_juniper_rules.json": "",
}

IMPORTANCE_WEIGHT = {"상": 10, "중": 8, "하": 6}


def get_enc_path(plain_path):
    return plain_path + ".enc"


def resolve_rules_path(filename):
    """[버그 수정 - 중복 제거] ssh_inspector.py/windows_inspector.py/
    database_inspector.py 세 클래스가 이 로직(exe 옆 external_path 우선, 없으면
    _MEIPASS 번들 internal_path로 폴백)을 각자 거의 동일하게(database_inspector만
    파일명 조합 방식이 다름) 재구현하고 있었다 - 경로 해석을 바꿀 때마다 세 곳을
    같이 고쳐야 했다. 필요한 건 최종 rules_path뿐이므로, 파일명만 각 클래스가
    넘기고 해석 자체는 여기 한 곳으로 모은다."""
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    external_path = os.path.join(base_dir, 'rules', filename)

    internal_path = None
    if hasattr(sys, '_MEIPASS'):
        internal_path = os.path.join(sys._MEIPASS, 'rules', filename)
    else:
        internal_path = external_path

    if ruleset_exists(external_path):
        return external_path
    elif internal_path and ruleset_exists(internal_path):
        return internal_path
    return external_path


def ruleset_exists(plain_path):
    """각 inspector의 `_get_rules_path()`류가 external(exe 옆)/internal(_MEIPASS
    번들) 경로 중 어느 쪽을 쓸지 os.path.exists()로 고르는데, 배포판에서는
    plain_path 자체가 아니라 plain_path+".enc"만 존재한다. 그 판단에 이 헬퍼를
    쓰면 평문/암호화 두 경우 모두 올바르게 "이 경로에 룰셋이 있다"고 인식한다."""
    # [변조 방지] 배포판에서는 .enc만 인정한다(load_ruleset과 동일 기준).
    if getattr(sys, 'frozen', False):
        return os.path.exists(get_enc_path(plain_path))
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


def resolve_rules_data_path(filename):
    """[룰 폴더 보조 파일 - ruleset_manifest.json 등 암호화 대상이 아닌 평문 파일]
    exe 옆 rules/에 있으면 그것, 없으면 번들(_MEIPASS) rules/. 판정 룰셋은
    resolve_rules_path()를 쓴다(.enc 기준 존재 판정)."""
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    external_path = os.path.join(base_dir, 'rules', filename)
    if os.path.exists(external_path) or not hasattr(sys, '_MEIPASS'):
        return external_path
    return os.path.join(sys._MEIPASS, 'rules', filename)


def load_ruleset(plain_path):
    """반환: json.loads()한 파이썬 객체(list/dict). 기존 호출부들의
    `with open(path) as f: json.load(f)` 두 줄을 대체하는 1:1 교체용이라,
    호출부의 try/except나 os.path.exists() 사전 체크는 그대로 둬도 된다
    (파일이 아예 없으면 이 함수도 FileNotFoundError를 그대로 던진다).

    [2026-10 폴백] 배포판에서 exe 옆 rules/의 룰셋이 복호화/파싱에 실패하면(다른 키로
    만든 .enc, 깨진 파일 등) 번들 내부의 같은 룰셋으로 돌아간다 - 예전엔 그 진단 유형
    전체가 오류로 죽었다. 모든 호출부가 이 함수를 거치므로 여기 한 곳에서 처리한다."""
    try:
        return _load_ruleset_at(plain_path)
    except (ValueError, FileNotFoundError) as e:
        meipass = getattr(sys, '_MEIPASS', None)
        if not (getattr(sys, 'frozen', False) and meipass):
            raise
        bundled = os.path.join(meipass, 'rules', os.path.basename(plain_path))
        if os.path.normcase(os.path.abspath(bundled)) == os.path.normcase(os.path.abspath(plain_path)):
            raise
        if not ruleset_exists(bundled):
            raise
        try:
            from utils.logger import AppLogger
            AppLogger.log_error(f"[RuleCrypto] 외부 룰셋 로드 실패 - 번들 룰셋으로 대체: {plain_path}", e)
        except Exception:
            pass
        return _load_ruleset_at(bundled)


def _load_ruleset_at(plain_path):
    enc_path = get_enc_path(plain_path)
    try:
        with open(enc_path, 'rb') as f:
            blob = f.read()
    except FileNotFoundError:
        # [변조 방지] 배포판에서는 평문 폴백 금지 - .enc를 지우고 평문 룰을 넣는
        # 것만으로 판정 로직/실행 명령을 바꿀 수 있게 된다(룰셋 업데이트 zip도
        # .enc만 담으므로 정상 흐름에는 영향 없음).
        if getattr(sys, 'frozen', False):
            raise
        # 개발 환경(소스에서 직접 실행) - 평문 폴백
        with open(plain_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    try:
        raw = _get_fernet().decrypt(blob)
    except InvalidToken as e:
        raise ValueError(
            f"룰셋 복호화 실패 - 키가 안 맞거나 파일이 손상됨: {enc_path}"
        ) from e

    return json.loads(raw)


# ----------------------------------------------------------------------
# [config/*.json 보호, 2026-10] 배포판(onedir)에서 설정 파일을 고객이 메모장으로
# 열어 고치지 못하게, 룰셋과 같은 키로 Fernet 암호화해서 "{name}.enc"로만 둔다.
# Fernet은 인증 암호라 한 바이트라도 고치면 복호화 자체가 실패한다(=변조 감지).
#
# 배포판에서는 평문 파일을 아예 읽지 않는다 - 평문 폴백을 두면 .enc를 지우고
# 직접 만든 평문을 넣는 것만으로 우회된다. 개발 환경(비frozen)은 지금처럼
# 평문으로 읽고 쓴다(소스 실행 중 설정 파일을 직접 열어보는 기존 흐름 유지).
# 변조/손상/파일 없음은 호출부에서 전부 "기본값"으로 처리된다 - 통째로 삭제해서
# 초기화하는 건 원래 막을 수 없으므로 그보다 더 열리는 구멍은 없다.
# [빌드 제약] PyArmor 트라이얼 파일 개수 상한 때문에 별도 모듈로 빼지 않고
# 같은 Fernet 키를 쓰는 이 파일에 둔다(RULE_FILES 통합과 같은 이유).
# ----------------------------------------------------------------------
def _is_frozen():
    return bool(getattr(sys, 'frozen', False))


def _write_atomic(path, data_bytes):
    tmp_path = path + ".tmp"
    with open(tmp_path, 'wb') as f:
        f.write(data_bytes)
    os.replace(tmp_path, path)


def _decrypt_json_file(enc_path):
    with open(enc_path, 'rb') as f:
        blob = f.read()
    try:
        raw = _get_fernet().decrypt(blob)
    except InvalidToken as e:
        raise ValueError(f"설정 파일 복호화 실패 - 변조됐거나 손상됨: {enc_path}") from e
    return json.loads(raw)


def save_user_json(plain_path, obj):
    """[실행 중 저장되는 설정 - exe 옆 config/] 배포판이면 암호화본({plain_path}.enc)만
    쓰고, 남아있는 평문은 지운다. 실패 시 예외를 그대로 던진다(호출부의 기존
    try/except가 False 반환 처리)."""
    raw = json.dumps(obj, ensure_ascii=False, indent=2).encode('utf-8')
    if not _is_frozen():
        _write_atomic(plain_path, raw)
        return
    _write_atomic(get_enc_path(plain_path), _get_fernet().encrypt(raw))
    if os.path.exists(plain_path):
        try:
            os.remove(plain_path)
        except OSError:
            pass


def load_user_json(plain_path):
    """배포판: {plain_path}.enc만 읽는다. 개발 환경: 평문만 읽는다.
    없으면 FileNotFoundError, 변조/키 불일치면 ValueError."""
    if _is_frozen():
        return _decrypt_json_file(get_enc_path(plain_path))
    with open(plain_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def user_json_exists(plain_path):
    return os.path.exists(get_enc_path(plain_path) if _is_frozen() else plain_path)


def load_bundled_json(filename):
    """[배포 시점에 고정되는 설정 - revoked_licenses/rule_update_config]
    배포판: 번들 내부(_MEIPASS = onedir의 _internal/config)의 .enc만 읽는다
    (빌드 때 ci/encrypt_rules.py --config가 만든 것). exe 옆 config/나 평문은
    절대 보지 않는다 - 그 위치/형식은 고객이 파일을 새로 만들어 넣을 수 있다.
    개발 환경: 저장소 config/의 평문."""
    if _is_frozen():
        base = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        return _decrypt_json_file(get_enc_path(os.path.join(base, 'config', filename)))
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    with open(os.path.join(base_dir, 'config', filename), 'r', encoding='utf-8') as f:
        return json.load(f)
