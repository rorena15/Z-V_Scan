# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
class AppConfig:
    # [1] 프로그램 버전 관리
    # 이 값을 바꾸면 윈도우 제목, 헤더 라벨, 라이선스 정보가 일괄 변경됩니다.
    VERSION = "v3.0"
    
    # ----------------------------------------------------------------------
    # [2] 라이선스 키 생성 정책 (License Policy)
    # ----------------------------------------------------------------------
    # 구조: ZV3-{TIER}-{RANDOM}-{HASH}
    # 예시: ZV3-ENT-X9A2-B7F1
    #
    # [TIER 코드 목록]
    # - STD : Standard (개인용, PDF Only)
    # - PRO : Professional (기업용, Excel Export, Update)
    # - ENT : Enterprise (확장용, SaaS/AI 기능 활성화)
    #
    # [보안 주의]
    # 이 SALT 값은 해커가 절대 알면 안 됩니다. 
    # 키 유출이 의심되면 이 값을 변경하고 새 키를 발급하세요.
    LICENSE_SALT = "Z-Vuln-Secret-Salt-2026-DoNotShare"

    # ----------------------------------------------------------------------
    # [3] 엔진 내부 인증 토큰 (Internal Engine Token)
    # ----------------------------------------------------------------------
    # GUI(main_window)와 Engine(worker) 간의 통신을 검증하는 내부 키입니다.
    # 해커가 엔진 모듈만 따로 떼어내서 악용하는 것을 방지합니다.
    ENGINE_ACCESS_TOKEN = "ZVulnScan_V3_Pro_Secure_Engine_Key_2026_!@#"