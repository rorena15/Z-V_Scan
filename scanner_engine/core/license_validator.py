# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import hashlib
import os
import base64

class LicenseValidator:
    """
    [라이선스 키 구조]
    Format: ZV3-[TIER]-[RANDOM]-[HASH]
    Example: ZV3-ENT-X9A2-B7F1
    """
    # 해커가 절대 알면 안 되는 비밀 소금(Salt)
    SECRET_SALT = "Z-Vuln-Secret-Salt-2026-DoNotShare" 
    LICENSE_FILE = "license.dat"

    @staticmethod
    def validate_key(license_key):
        """
        입력된 키를 검증하고 유효하면 (True, Tier)를 반환합니다.
        """
        try:
            parts = license_key.strip().upper().split('-')
            if len(parts) != 4:
                return False, None
            
            prefix, tier_code, random_val, checksum = parts
            
            # 1. 접두어 확인
            if prefix != "ZV3":
                return False, None

            # 2. 등급 코드 매핑
            tier_map = {
                "STD": "STANDARD",
                "PRO": "PROFESSIONAL",
                "ENT": "ENTERPRISE"
            }
            if tier_code not in tier_map:
                return False, None

            # 3. 해시(Checksum) 무결성 검증
            # 키 생성기와 동일한 로직으로 해시를 다시 계산해서 비교
            raw_str = f"{tier_code}{random_val}{LicenseValidator.SECRET_SALT}"
            calculated_hash = hashlib.md5(raw_str.encode()).hexdigest()[:4].upper()
            
            if checksum == calculated_hash:
                return True, tier_map[tier_code]
            else:
                return False, None # 위변조된 키
                
        except Exception:
            return False, None

    @staticmethod
    def save_license(key):
        """인증 성공한 키를 파일에 암호화(Base64)하여 저장"""
        try:
            encoded = base64.b64encode(key.encode()).decode()
            with open(LicenseValidator.LICENSE_FILE, 'w') as f:
                f.write(encoded)
            return True
        except:
            return False

    @staticmethod
    def load_license():
        """프로그램 시작 시 저장된 라이선스 로드"""
        if not os.path.exists(LicenseValidator.LICENSE_FILE):
            return None
        try:
            with open(LicenseValidator.LICENSE_FILE, 'r') as f:
                encoded = f.read().strip()
            return base64.b64decode(encoded).decode()
        except:
            return None