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
    # 구조: ZV3-{TIER}-{EXPIRY:YYYYMMDD}-{RANDOM}-{HASH}
    # 예시: ZV3-ENT-20270717-X9A2-B7F1
    #
    # [TIER 코드 목록 및 리포트 노출 범위]
    # - STD : Standard     - PDF만 가능(Excel 불가) / 증적(raw_output)은 취약·부분만족 항목만 / 조치방안 없음
    # - PRO : Professional - Excel+PDF 가능 / 증적 전체 제공 / 조치방안은 중요도 상·중 항목만
    # - ENT : Enterprise   - 모든 기능(전문가 모드 포함) / 증적 전체 / 조치방안 전체(중요도 무관)
    #
    # [실구현 상태 및 기본 동작]
    # 등급별 차등 로직(LicenseManager, ExcelGenerator, PDFGenerator)은 실제로 항상 적용된다
    # (별도 on/off 스위치 없음). 다만 `license.dat`에 유효한 키가 없으면(본인 자체 사용 단계
    # 기본값) LicenseManager가 ENTERPRISE로 시작하므로 지금 당장은 아무것도 제한되지 않는다.
    # 나중에 고객사에 STD/PRO 키를 발급하면, 그 키가 검증되는 순간부터 해당 등급 제한이
    # 실제로 적용된다. 등급별 화면을 미리 확인하고 싶으면 숨겨진 개발자 단축키(Ctrl+Shift+L,
    # main_window.py의 action_license_switch)로 STD->PRO->ENT 순으로 순환 전환할 수 있다
    # (메모리에만 반영되며, 재시작하면 license.dat 기준으로 다시 초기화됨).
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