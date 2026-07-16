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
from datetime import datetime
from core.config import AppConfig

class LicenseValidator:
    LICENSE_FILE = "license.dat"

    @staticmethod
    def validate_key(license_key):
        #입력된 키를 검증하고 유효하면 (True, Tier, 만료일(date))를 반환합니다.
        #위변조/형식오류/만료된 키는 모두 (False, None, None)으로 처리합니다
        #(만료된 키는 "라이선스 없음"과 동일하게 취급되어, 호출부가 기본 등급(Enterprise)으로 폴백함).

        try:
            parts = license_key.strip().upper().split('-')
            if len(parts) != 5:
                return False, None, None

            prefix, tier_code, expiry_str, random_val, checksum = parts

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
            raw_str = f"{tier_code}{expiry_str}{random_val}{AppConfig.LICENSE_SALT}"
            calculated_hash = hashlib.md5(raw_str.encode()).hexdigest()[:4].upper()

            if checksum != calculated_hash:
                return False, None, None # 위변조된 키

            # 4. 유효기간(만료일) 확인
            try:
                expiry_date = datetime.strptime(expiry_str, "%Y%m%d").date()
            except ValueError:
                return False, None, None # 만료일 형식 자체가 잘못됨

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