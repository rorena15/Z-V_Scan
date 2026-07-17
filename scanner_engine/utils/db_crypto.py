# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[DB 파일 접근통제/암호화] 실제 감사 결과(취약점 상세, 자산 정보 등)가 담긴
zvuln_scan.db가 평문 SQLite 파일 그대로 디스크에 남아있으면, 노트북을 분실하거나
파일이 유출됐을 때 고객사 보안 진단 결과가 그대로 노출된다.

이 모듈은 SQLite 자체를 암호화 빌드로 바꾸는 대신(SQLCipher는 하이브리드
빌드 파이프라인에 새 네이티브 의존성을 추가해야 해서 위험 부담이 큼), 앱이
꺼져있는 동안("at rest")만 파일 전체를 Fernet으로 암호화해두는 방식을 쓴다:

- 실행 중에는 지금까지와 동일하게 평문 SQLite 파일(zvuln_scan.db)을 그대로 쓴다
  (DBConnector나 리포트 생성기 등 기존 코드는 전혀 손댈 필요 없음).
- 정상 종료 시에만 그 파일을 암호화해서 zvuln_scan.db.enc로 저장한다.
- 다음 실행 시작 시, .enc가 있으면 그걸 복호화해서 평문 zvuln_scan.db를 만든다.

암호화 키는 OS 자격증명 관리자(keyring)에 보관한다 - 소스코드나 평문 파일
어디에도 키 자체는 남지 않는다. 다만 이 키를 잃어버리면(OS 재설치, 다른
사용자 계정 등) DB를 복구할 방법이 없으므로, 키를 처음 만드는 시점에 한 번
로컬 백업 파일에도 남겨서 사용자가 안전한 곳에 별도 보관하도록 안내한다.
"""
import os
import sys
import keyring
from cryptography.fernet import Fernet, InvalidToken
from utils.logger import AppLogger

_SERVICE_NAME = "Z-VulnScan_DB_Encryption"
_KEY_NAME = "db_master_key"

# SQLite 파일은 항상 이 매직 헤더로 시작한다 - 이미 평문이면(예: 이번에
# 처음 암호화 기능을 켜는 경우, 기존 실제 감사 데이터가 든 파일) 헤더로
# 구분해서 실수로 두 번 암호화하거나 잘못 복호화하지 않게 한다.
_SQLITE_MAGIC = b"SQLite format 3\x00"


def _get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    current_file = os.path.abspath(__file__)
    return os.path.dirname(os.path.dirname(os.path.dirname(current_file)))


def get_default_db_path():
    """DBConnector.__init__()과 동일한 경로 규칙 - main.py가 DBConnector를
    만들기도 전에 미리 암호화 여부를 확인해야 해서 별도로 계산한다."""
    return os.path.join(_get_base_dir(), 'zvuln_scan.db')


def get_enc_path(plain_path):
    return plain_path + ".enc"


def get_recovery_backup_path():
    return os.path.join(_get_base_dir(), "DB_RECOVERY_KEY_BACKUP.txt")


def get_or_create_key():
    """반환: (key_bytes, is_new). is_new면 방금 처음 생성된 키라는 뜻이므로
    호출부가 사용자에게 백업을 안내해야 한다."""
    existing = keyring.get_password(_SERVICE_NAME, _KEY_NAME)
    if existing:
        return existing.encode(), False

    new_key = Fernet.generate_key()
    keyring.set_password(_SERVICE_NAME, _KEY_NAME, new_key.decode())
    return new_key, True


def _write_recovery_backup(key_bytes):
    try:
        with open(get_recovery_backup_path(), 'w', encoding='utf-8') as f:
            f.write(
                "Z-Vuln Scan DB 암호화 복구 키\n"
                "================================\n"
                "이 키를 잃어버리면 zvuln_scan.db.enc를 복호화할 방법이 없습니다.\n"
                "(Windows 재설치, 다른 사용자 계정으로 로그인 등으로 OS 자격증명\n"
                "관리자에 저장된 키에 접근할 수 없게 되는 경우를 대비해, 이 파일을\n"
                "USB 등 안전한 별도 위치에 백업해두세요.)\n\n"
                f"{key_bytes.decode()}\n"
            )
    except OSError as e:
        AppLogger.log_error("[DB Crypto] Failed to write recovery key backup", e)


def ensure_decrypted(plain_path):
    """앱 시작 시 1회 호출. .enc가 있으면 복호화해서 평문 파일을 만든다.
    반환: is_new_key (처음 키를 생성했으면 True - 호출부가 백업 안내를 띄워야 함)"""
    key, is_new = get_or_create_key()
    if is_new:
        _write_recovery_backup(key)

    enc_path = get_enc_path(plain_path)
    if not os.path.exists(enc_path):
        # 암호화된 스냅샷이 아직 없음 - 최초 실행이거나, 이번에 처음 암호화
        # 기능을 켜는 경우(기존 평문 DB는 그대로 두고 다음 정상 종료 때 암호화됨)
        return is_new

    with open(enc_path, 'rb') as f:
        blob = f.read()

    try:
        data = Fernet(key).decrypt(blob)
    except InvalidToken as e:
        # 키가 안 맞거나 파일이 손상됨 - 기존 평문 파일이 남아있다면(비정상
        # 종료 등으로) 그걸 그대로 쓰는 게 최신 데이터일 수 있으므로 덮어쓰지 않는다.
        AppLogger.log_error(
            "[DB Crypto] Failed to decrypt zvuln_scan.db.enc (key mismatch or corrupted). "
            "Keeping existing plaintext file if present, not overwriting.", e
        )
        return is_new

    with open(plain_path, 'wb') as f:
        f.write(data)
    return is_new


def encrypt_on_exit(plain_path):
    """앱 정상 종료 시 호출. 평문 파일을 암호화해서 .enc로 저장한다.
    (비정상 종료/강제 종료 시에는 호출되지 않으며, 그 경우 평문 파일이 그대로
    남아있어 다음 실행에서도 데이터 유실은 없다 - 다만 그 세션 동안은 "at rest"
    보호가 적용되지 않은 상태로 남는다는 트레이드오프를 감수한다.)"""
    if not os.path.exists(plain_path):
        return

    with open(plain_path, 'rb') as f:
        data = f.read()

    if data[:len(_SQLITE_MAGIC)] != _SQLITE_MAGIC:
        # 이미 암호화된 내용을 실수로 다시 암호화하는 사고 방지
        return

    key, _ = get_or_create_key()
    blob = Fernet(key).encrypt(data)

    enc_path = get_enc_path(plain_path)
    tmp_path = enc_path + ".tmp"
    with open(tmp_path, 'wb') as f:
        f.write(blob)
    os.replace(tmp_path, enc_path)
