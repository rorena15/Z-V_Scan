# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import hashlib
import random
import string
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.config import AppConfig

def generate_key(tier_code):
    """
    지정된 등급(STD, PRO, ENT)의 정품 라이선스 키를 생성합니다.
    """
    # 1. 4자리 랜덤 문자열 (A-Z, 0-9)
    random_val = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    
    # 2. 해시 계산 (Tier + Random + Salt)
    raw_str = f"{tier_code}{random_val}{AppConfig.LICENSE_SALT}"
    checksum = hashlib.md5(raw_str.encode()).hexdigest()[:4].upper()
    
    # 3. 키 조합
    return f"ZV3-{tier_code}-{random_val}-{checksum}"

if __name__ == "__main__":
    print("="*40)
    print(" 🛡️  Z-VulnScan License Generator")
    print("="*40)
    print(f" [Standard]    : {generate_key('STD')}")
    print(f" [Professional]: {generate_key('PRO')}")
    print(f" [Enterprise]  : {generate_key('ENT')}")
    print("="*40)