# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
class AppConfig:
    # [1] 프로그램 버전
    VERSION = "v3.0"
    
    # [2] 라이선스 검증용 비밀 소금 (해커 절대 공유 금지)
    # LicenseValidator와 KeyGen이 공유함
    LICENSE_SALT = "Z-Vuln-Secret-Salt-2026-DoNotShare"

    # [3] 엔진 내부 인증 토큰 (GUI <-> Engine 통신 보안)
    # auth_token.py가 사용함
    ENGINE_ACCESS_TOKEN = "ZVulnScan_V3_Pro_Secure_Engine_Key_2026_!@#"