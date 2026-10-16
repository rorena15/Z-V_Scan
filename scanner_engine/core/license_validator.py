# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import hashlib
import os
import sys
import json
import base64
from datetime import datetime, date, timedelta
from core.config import AppConfig

class LicenseValidator:
    LICENSE_FILE = "license.dat"

    # [접두어 난독화] "ZV3-..."처럼 접두어가 제품명 이니셜+버전으로 읽혀서, 등급/만료일을
    # 감춰도 이 문자열이 "Z-VulnScan 라이선스 키"라는 것 자체는 누구나 바로 알 수 있었다.
    # salt로 만든 고정 3자리 hex 태그로 바꿔서 키의 5개 구간 중 어디에도 사람이 읽어서
    # 뜻을 알 수 있는 조각이 남지 않게 한다(대시로 나뉜 형태 자체는 가독성을 위해 유지 -
    # 윈도우/오피스 키처럼 구간 구분은 정보 노출이 아니라 단순 서식임).
    @staticmethod
    def key_prefix():
        return hashlib.sha256((AppConfig.LICENSE_SALT + "MAGIC").encode()).hexdigest()[:3].upper()

    # [만료일 난독화] 키에 만료일을 "20270717" 같은 평문으로 그대로 넣으면 키만 봐도
    # 발급/만료 패턴이 바로 드러난다. salt로 만든 마스크로 XOR해서 4자리 hex 토큰으로
    # 바꿔 넣고, 검증할 때만 같은 salt로 역산해서 실제 날짜를 복원한다(서버 조회 없이
    # 오프라인으로 그대로 검증 가능하며, salt를 모르면 토큰만 봐서는 날짜를 알 수 없다).
    _EXPIRY_EPOCH = date(2025, 1, 1)

    @staticmethod
    def _expiry_mask():
        return int(hashlib.sha256((AppConfig.LICENSE_SALT + "EXP").encode()).hexdigest()[:4], 16)

    @staticmethod
    def encode_expiry_token(expiry_date):
        """만료일(date) -> 난독화된 4자리 hex 토큰 (keygen.py에서 사용)"""
        days = (expiry_date - LicenseValidator._EXPIRY_EPOCH).days
        days_u16 = days & 0xFFFF
        token_val = days_u16 ^ LicenseValidator._expiry_mask()
        return format(token_val, '04X')

    @staticmethod
    def _decode_expiry_token(token):
        """난독화된 4자리 hex 토큰 -> 만료일(date). 형식이 잘못되면 None."""
        token_val = int(token, 16)
        days_u16 = token_val ^ LicenseValidator._expiry_mask()
        days = days_u16 if days_u16 < 0x8000 else days_u16 - 0x10000
        return LicenseValidator._EXPIRY_EPOCH + timedelta(days=days)

    # [등급 난독화] 예전엔 키 안에 등급이 "ZV3-ENT-...."처럼 평문(STD/PRO/ENT)으로 그대로
    # 들어가 있어서 키 문자열만 봐도 무슨 등급인지 바로 유추됐다. 만료일 토큰과 같은
    # 방식(salt로 XOR한 hex 토큰)으로 등급도 감춘다 - 체크섬이 이미 위변조를 막고
    # 있으므로 이건 보안 강도가 아니라 "봐도 못 알아보게"하는 눈가림 목적.
    _TIER_CODES = ["STD", "PRO", "ENT"]

    @staticmethod
    def _tier_mask():
        return int(hashlib.sha256((AppConfig.LICENSE_SALT + "TIER").encode()).hexdigest()[:2], 16)

    # [등록일 기준 키, 2026-10] 데모/PoC 납품처럼 "고객이 등록한 날부터 N일"로 쓰는 키.
    # 키 형식(5구간)은 그대로 두고 등급 토큰 하나에 기간 코드를 같이 싣는다:
    #   idx = 등급 인덱스(0~2) + 3 * 기간코드
    #   기간코드 0 = 기존 발급일 기준 키(만료일 토큰 = 실제 만료일) - 이미 발급된 키 전부 그대로 유효
    #   기간코드 k(1~) = 등록일 기준 키, 기간 = _ACTIVATION_DAYS[k-1], 만료일 토큰 = "등록 마감일"
    # 만료일 = min(최초 등록일, 등록 마감일) + 기간. 오프라인 검증이라 등록일 기록(config/
    # license_activation.json, 배포판은 암호화)을 지우고 재등록하면 시계가 다시 돌지만,
    # 마감일이 지나면 재등록 자체가 거부되므로 어떤 경우에도 "마감일 + 기간"을 넘지 못한다
    # (keygen.py _cmd_generate 주석의 "재설치하면 기간 초기화" 문제에 대한 상한선).
    # 목록 순서를 바꾸면 이미 발급한 키의 기간이 바뀌므로 뒤에 추가만 할 것.
    _ACTIVATION_DAYS = (7, 14, 30, 45, 60, 90, 120, 180, 365)

    @staticmethod
    def encode_tier_token(tier_code, activation_days=None):
        """등급 코드(STD/PRO/ENT) -> 난독화된 2자리 hex 토큰 (keygen.py에서 사용).
        activation_days를 주면 등록일 기준 키(_ACTIVATION_DAYS 중 하나여야 함)."""
        idx = LicenseValidator._TIER_CODES.index(tier_code)
        if activation_days is not None:
            idx += 3 * (LicenseValidator._ACTIVATION_DAYS.index(activation_days) + 1)
        token_val = idx ^ LicenseValidator._tier_mask()
        return format(token_val, '02X')

    @staticmethod
    def _decode_tier_field(token):
        """난독화된 등급 토큰 -> (등급 코드, 등록일 기준 기간(일) 또는 None). 실패 시 None."""
        try:
            token_val = int(token, 16)
        except ValueError:
            return None
        idx = token_val ^ LicenseValidator._tier_mask()
        tier_idx, duration_code = idx % 3, idx // 3
        if duration_code == 0:
            return LicenseValidator._TIER_CODES[tier_idx], None
        if duration_code <= len(LicenseValidator._ACTIVATION_DAYS):
            return LicenseValidator._TIER_CODES[tier_idx], LicenseValidator._ACTIVATION_DAYS[duration_code - 1]
        return None

    @staticmethod
    def _decode_tier_token(token):
        """난독화된 2자리 hex 토큰 -> 등급 코드. 형식이 잘못되면 None(예외를 던지지
        않음 - 예전 평문 형식(STD 등)이 들어오면 hex 파싱에 실패하는데, 그 경우
        validate_key()가 하위 호환 경로로 넘어가야 하므로 여기서 죽으면 안 된다)."""
        try:
            token_val = int(token, 16)
        except ValueError:
            return None
        idx = token_val ^ LicenseValidator._tier_mask()
        if 0 <= idx < len(LicenseValidator._TIER_CODES):
            return LicenseValidator._TIER_CODES[idx]
        return None

    # ------------------------------------------------------------------
    # [라이선스 발급 체계: 로컬 취소(revoke) 목록]
    # 실시간 서버 조회 없이 오프라인으로 동작하는 구조라 "원격 회수"는 불가능하지만,
    # 발급자(본인)가 특정 키를 문제가 생겨 무효화하고 싶을 때, 그 키의 식별값(random_val)을
    # 이 목록에 추가해두면 이후 재빌드/재배포되는 프로그램에서는 그 키가 거부된다.
    # known_hosts와 같은 위치 규칙(<base_dir>/config/)을 써서 exe 옆에 둔다.
    # ------------------------------------------------------------------
    @staticmethod
    def _get_revoked_list_path():
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        config_dir = os.path.join(base_dir, 'config')
        try:
            os.makedirs(config_dir, exist_ok=True)
        except OSError:
            pass
        return os.path.join(config_dir, 'revoked_licenses.json')

    @staticmethod
    def _load_revoked_set():
        # [2026-10 버그 수정] 배포판은 예전엔 exe 옆 config/를 읽었는데, 빌드는
        # 이 파일을 번들 내부(_internal/config)에만 넣어서 폐기한 키가 배포판에서
        # 전혀 거부되지 않았다. 이제 배포판은 빌드 때 암호화된 번들 내부 사본만
        # 읽는다 - 고객이 exe 옆에 빈 목록을 만들어 넣거나 고쳐서 폐기 키를
        # 되살리는 것도 같이 막힌다. 키 폐기 등록(keygen.py)은 개발 PC에서 소스로만
        # 하므로 아래 평문 경로/_save_revoked_set은 그대로 둔다.
        if getattr(sys, 'frozen', False):
            from utils import rule_crypto
            try:
                return set(rule_crypto.load_bundled_json('revoked_licenses.json').get('revoked', []))
            except Exception:
                return set()
        path = LicenseValidator._get_revoked_list_path()
        if not os.path.exists(path):
            return set()
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return set(data.get('revoked', []))
        except Exception:
            return set()

    @staticmethod
    def _save_revoked_set(revoked_set):
        path = LicenseValidator._get_revoked_list_path()
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({"revoked": sorted(revoked_set)}, f, ensure_ascii=False, indent=2)

    @staticmethod
    def revoke_key(license_key):
        """발급된 키 하나를 취소 목록에 추가한다 (발급자용 관리 기능)."""
        parts = license_key.strip().upper().split('-')
        if len(parts) != 5:
            return False
        random_val = parts[3]
        revoked = LicenseValidator._load_revoked_set()
        revoked.add(random_val)
        LicenseValidator._save_revoked_set(revoked)
        return True

    @staticmethod
    def unrevoke_key(random_val):
        """취소 목록에서 제거한다 (실수로 취소했을 때 되돌리는 용도)."""
        revoked = LicenseValidator._load_revoked_set()
        revoked.discard(random_val.strip().upper())
        LicenseValidator._save_revoked_set(revoked)

    @staticmethod
    def list_revoked():
        return sorted(LicenseValidator._load_revoked_set())

    @staticmethod
    def validate_key(license_key):
        #입력된 키를 검증하고 유효하면 (True, Tier, 만료일(date))를 반환합니다.
        #위변조/형식오류/만료된 키는 모두 (False, None, None)으로 처리합니다
        #(만료된 키는 "라이선스 없음"과 동일하게 취급되어, 호출부가 기본 등급(Standard)으로 폴백함).

        try:
            parts = license_key.strip().upper().split('-')
            if len(parts) != 5:
                return False, None, None

            prefix, tier_field, expiry_token, random_val, checksum = parts

            # 1. 접두어 확인 - 새 형식(난독화된 태그) 또는 예전 평문 "ZV3"(하위 호환) 허용
            if prefix != LicenseValidator.key_prefix() and prefix != "ZV3":
                return False, None, None

            # 2. 등급 코드 매핑
            tier_map = {
                "STD": "STANDARD",
                "PRO": "PROFESSIONAL",
                "ENT": "ENTERPRISE"
            }

            # [등급 난독화 - 하위 호환] keygen.py는 이제 평문 STD/PRO/ENT 대신 난독화된
            # hex 토큰을 tier_field 자리에 넣는다(_decode_tier_token). 예전 형식으로
            # 이미 발급된 키(평문 tier)도 계속 동작해야 하므로, 새 형식으로 먼저
            # 시도하고 실패하면 예전 평문 형식으로 재시도한다.
            tier_code = None
            raw_str = None
            activation_days = None

            decoded = LicenseValidator._decode_tier_field(tier_field)
            if decoded is not None:
                candidate_raw = f"{tier_field}{expiry_token}{random_val}{AppConfig.LICENSE_SALT}"
                if hashlib.md5(candidate_raw.encode()).hexdigest()[:4].upper() == checksum:
                    tier_code, activation_days = decoded
                    raw_str = candidate_raw

            if tier_code is None and tier_field in tier_map:
                candidate_raw = f"{tier_field}{expiry_token}{random_val}{AppConfig.LICENSE_SALT}"
                if hashlib.md5(candidate_raw.encode()).hexdigest()[:4].upper() == checksum:
                    tier_code = tier_field
                    raw_str = candidate_raw

            # 3. 해시(Checksum) 무결성 검증 - 위 두 시도 중 하나도 통과 못 했으면 위변조/알 수 없는 형식
            if tier_code is None:
                return False, None, None

            # 3.5 취소(revoke) 목록 확인 - 발급자가 이 키를 무효화해뒀는지
            if random_val in LicenseValidator._load_revoked_set():
                return False, None, None # 취소된 키

            # 4. 유효기간(만료일) 확인 - 난독화 토큰을 복원
            try:
                token_date = LicenseValidator._decode_expiry_token(expiry_token)
            except (ValueError, OverflowError):
                return False, None, None # 만료일 토큰 형식 자체가 잘못됨

            today = datetime.now().date()
            if activation_days is None:
                expiry_date = token_date
            else:
                # 등록일 기준 키 - token_date는 "등록 마감일"
                activated = LicenseValidator._get_activation_date(random_val, checksum)
                if activated is None:
                    if today > token_date:
                        return False, None, None # 등록 마감일이 지난 미등록 키
                    activated = today  # 아직 등록 전 - 지금 등록하면 오늘부터
                expiry_date = min(activated, token_date) + timedelta(days=activation_days)

            if today > expiry_date:
                return False, None, None # 만료된 키

            return True, tier_map[tier_code], expiry_date

        except Exception:
            return False, None, None

    # ------------------------------------------------------------------
    # [등록일 기준 키 - 최초 등록일 기록] license.dat와 별도로, 두 군데에 남긴다:
    #   1) exe 옆 config/<salt 해시 12자>.dat  (Fernet 암호화 - 이름/내용 모두 용도를 드러내지 않음)
    #   2) OS 자격증명 관리자(keyring, db_crypto.py와 같은 저장소) - 서비스/항목명도 해시
    # 둘 중 "더 이른" 등록일을 쓰고, 한쪽이 없거나 더 늦으면 다른 쪽 값으로 되살린다 - 파일만
    # 지우거나 재설치(폴더 통째 삭제)해도 기간이 초기화되지 않는다. 두 곳을 모두 찾아 지우는
    # 것까지는 오프라인 검증 구조상 못 막는다(등록 마감일 상한이 그 경우의 최종 방어선).
    # [2026-10 변경] 예전엔 config/license_activation.json(.enc) 한 곳뿐이라 파일명만 봐도
    # "이걸 지우면 기간 리셋"이 드러났다 - 그 구버전 파일도 읽어서(이미 등록한 PC 호환) 합친다.
    # ------------------------------------------------------------------
    @staticmethod
    def _activation_tag():
        return hashlib.sha256((AppConfig.LICENSE_SALT + "ACT").encode()).hexdigest()

    @staticmethod
    def _config_dir():
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        config_dir = os.path.join(base_dir, 'config')
        try:
            os.makedirs(config_dir, exist_ok=True)
        except OSError:
            pass
        return config_dir

    @staticmethod
    def _get_activation_path():
        return os.path.join(LicenseValidator._config_dir(), LicenseValidator._activation_tag()[:12] + ".dat")

    @staticmethod
    def _record_key(random_val, checksum):
        return hashlib.sha256(f"{random_val}-{checksum}{AppConfig.LICENSE_SALT}".encode()).hexdigest()[:16]

    @staticmethod
    def _keyring_service():
        return LicenseValidator._activation_tag()[12:28]

    @staticmethod
    def _parse_date(value):
        try:
            return date.fromisoformat(value) if value else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _load_file_records():
        from utils import rule_crypto
        try:
            with open(LicenseValidator._get_activation_path(), 'rb') as f:
                return json.loads(rule_crypto._get_fernet().decrypt(f.read()))
        except Exception:
            return {}

    @staticmethod
    def _save_file_records(records):
        from utils import rule_crypto
        blob = rule_crypto._get_fernet().encrypt(json.dumps(records).encode('utf-8'))
        rule_crypto._write_atomic(LicenseValidator._get_activation_path(), blob)

    @staticmethod
    def _keyring_get(record_key):
        from utils import rule_crypto
        try:
            import keyring
            value = keyring.get_password(LicenseValidator._keyring_service(), record_key)
            return rule_crypto._get_fernet().decrypt(value.encode()).decode() if value else None
        except Exception:
            return None

    @staticmethod
    def _keyring_set(record_key, iso_date):
        from utils import rule_crypto
        try:
            import keyring
            token = rule_crypto._get_fernet().encrypt(iso_date.encode()).decode()
            keyring.set_password(LicenseValidator._keyring_service(), record_key, token)
            return True
        except Exception:
            return False  # 자격증명 저장소를 못 쓰는 환경 - 파일 기록만으로 동작

    @staticmethod
    def _legacy_activation_date(random_val, checksum):
        from utils import rule_crypto
        try:
            legacy = rule_crypto.load_user_json(os.path.join(LicenseValidator._config_dir(), 'license_activation.json'))
            return LicenseValidator._parse_date(legacy.get('activations', {}).get(f"{random_val}-{checksum}"))
        except Exception:
            return None

    @staticmethod
    def _get_activation_date(random_val, checksum):
        record_key = LicenseValidator._record_key(random_val, checksum)
        records = LicenseValidator._load_file_records()
        file_date = LicenseValidator._parse_date(records.get(record_key))
        vault_date = LicenseValidator._parse_date(LicenseValidator._keyring_get(record_key))
        legacy_date = LicenseValidator._legacy_activation_date(random_val, checksum)

        candidates = [d for d in (file_date, vault_date, legacy_date) if d is not None]
        if not candidates:
            return None
        earliest = min(candidates)

        # 한쪽이 지워졌거나 더 늦은 날짜면 가장 이른 값으로 되살린다(best effort)
        if file_date != earliest:
            records[record_key] = earliest.isoformat()
            try:
                LicenseValidator._save_file_records(records)
            except Exception:
                pass
        if vault_date != earliest:
            LicenseValidator._keyring_set(record_key, earliest.isoformat())
        return earliest

    @staticmethod
    def _record_activation_if_needed(key):
        """등록일 기준 키면 최초 등록일을 기록한다(이미 있으면 그대로). 반환: 성공 여부."""
        parts = key.strip().upper().split('-')
        if len(parts) != 5:
            return False
        decoded = LicenseValidator._decode_tier_field(parts[1])
        if decoded is None or decoded[1] is None:
            return True  # 발급일 기준 키 - 기록할 것 없음
        random_val, checksum = parts[3], parts[4]
        if LicenseValidator._get_activation_date(random_val, checksum) is not None:
            return True
        today_iso = datetime.now().date().isoformat()
        record_key = LicenseValidator._record_key(random_val, checksum)
        records = LicenseValidator._load_file_records()
        records[record_key] = today_iso
        try:
            LicenseValidator._save_file_records(records)
        except Exception:
            return False  # 파일 기록은 필수 - 실패하면 등록 자체를 실패시킨다(save_license 주석)
        LicenseValidator._keyring_set(record_key, today_iso)
        return True

    @staticmethod
    def save_license(key):
        #인증 성공한 키를 파일에 암호화(Base64)하여 저장
        try:
            # 등록일 기록이 실패하면 등록 자체를 실패시킨다 - 기록 없이 등록되면
            # 실행할 때마다 "오늘 등록"으로 계산돼 마감일까지 기간이 계속 밀린다.
            if not LicenseValidator._record_activation_if_needed(key):
                return False
            encoded = base64.b64encode(key.encode()).decode()
            with open(LicenseValidator.LICENSE_FILE, 'w') as f:
                f.write(encoded)
            return True
        except:
            return False

    @staticmethod
    def load_license():
        #프로그램 시작 시 저장된 라이선스 로드
        if not os.path.exists(LicenseValidator.LICENSE_FILE):
            return None
        try:
            with open(LicenseValidator.LICENSE_FILE, 'r') as f:
                encoded = f.read().strip()
            return base64.b64decode(encoded).decode()
        except:
            return None