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
        #(만료된 키는 "라이선스 없음"과 동일하게 취급되어, 호출부가 기본 등급(Enterprise)으로 폴백함).

        try:
            parts = license_key.strip().upper().split('-')
            if len(parts) != 5:
                return False, None, None

            prefix, tier_code, expiry_token, random_val, checksum = parts

            # 1. 접두어 확인
            if prefix != "ZV3":
                return False, None, None

            # 2. 등급 코드 매핑
            tier_map = {
                "STD": "STANDARD",
                "PRO": "PROFESSIONAL",
                "ENT": "ENTERPRISE"
            }
            if tier_code not in tier_map:
                return False, None, None

            # 3. 해시(Checksum) 무결성 검증
            # 키 생성기와 동일한 로직으로 해시를 다시 계산해서 비교
            raw_str = f"{tier_code}{expiry_token}{random_val}{AppConfig.LICENSE_SALT}"
            calculated_hash = hashlib.md5(raw_str.encode()).hexdigest()[:4].upper()

            if checksum != calculated_hash:
                return False, None, None # 위변조된 키

            # 3.5 취소(revoke) 목록 확인 - 발급자가 이 키를 무효화해뒀는지
            if random_val in LicenseValidator._load_revoked_set():
                return False, None, None # 취소된 키

            # 4. 유효기간(만료일) 확인 - 난독화 토큰을 복원
            try:
                expiry_date = LicenseValidator._decode_expiry_token(expiry_token)
            except (ValueError, OverflowError):
                return False, None, None # 만료일 토큰 형식 자체가 잘못됨

            if datetime.now().date() > expiry_date:
                return False, None, None # 만료된 키

            return True, tier_map[tier_code], expiry_date

        except Exception:
            return False, None, None

    @staticmethod
    def save_license(key):
        #인증 성공한 키를 파일에 암호화(Base64)하여 저장
        try:
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