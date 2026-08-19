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
    # 구조: {PREFIX_TOKEN}-{TIER_TOKEN}-{EXPIRY_TOKEN}-{RANDOM}-{HASH}
    # 예시: A4F-EC-1D51-X9A2-B7F1
    # [2026-08-06] PREFIX/TIER 모두 평문(예전엔 "ZV3"/"STD"/"PRO"/"ENT")이 아니라
    # salt로 XOR 난독화한 토큰이다 - 키의 5개 구간 중 어디를 봐도 사람이 읽어서 뜻을
    # 알 수 있는 조각이 없다(`LicenseValidator.key_prefix`/`encode_tier_token`/
    # `_decode_tier_token`). EXPIRY_TOKEN도 만료일(YYYYMMDD)을 그대로 넣지 않고
    # 같은 방식으로 XOR 난독화한 4자리 hex 토큰이다(`encode_expiry_token`/
    # `_decode_expiry_token`). 키만 봐서는 제품·등급·발급/만료 패턴 어느 것도
    # 드러나지 않으며, salt를 아는 코드만 오프라인으로 실제 값을 복원할 수 있다.
    # 예전 평문 형식(ZV3-STD/PRO/ENT-...)으로 이미 발급된 키도 하위 호환으로
    # 계속 검증된다.
    #
    # [TIER 코드 목록 및 리포트 노출 범위]
    # - STD : Standard     - PDF만 가능(Excel 불가) / 증적(raw_output)은 취약·부분만족 항목만 / 조치방안 없음
    # - PRO : Professional - Excel+PDF 가능 / 증적 전체 제공 / 조치방안은 중요도 상·중 항목만
    # - ENT : Enterprise   - 모든 기능(전문가 모드 포함) / 증적 전체 / 조치방안 전체(중요도 무관)
    #
    # [실구현 상태 및 기본 동작 - 2026-08-19 정식 출시 대비 변경]
    # 등급별 차등 로직(LicenseManager, ExcelGenerator, PDFGenerator)은 실제로 항상 적용된다
    # (별도 on/off 스위치 없음). `license.dat`에 유효한 키가 없으면 LicenseManager가 가장
    # 제한적인 STANDARD로 시작한다 - 예전엔 본인 자체 사용 편의를 위해 ENTERPRISE로
    # 시작했지만, 그 상태로는 라이선스 없이 받은 사람도 전체 기능을 무제한으로 쓸 수 있어
    # 정식 출시와 맞지 않아 변경함. 고객사에 STD/PRO/ENT 키를 발급하면, 그 키가 검증되는
    # 순간부터 해당 등급 기능이 실제로 열린다. 등급별 화면을 미리 확인하고 싶으면 숨겨진
    # 개발자 단축키(Ctrl+Shift+L, main_window.py의 action_license_switch)로
    # STD->PRO->ENT 순으로 순환 전환할 수 있다(메모리에만 반영되며, 재시작하면
    # license.dat 기준으로 다시 초기화됨 - 키가 없으면 STANDARD로).
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

    # ----------------------------------------------------------------------
    # [4] 버전 업데이트 확인 (Update Check) - GitHub Releases 기반
    # ----------------------------------------------------------------------
    # 배포 경로로 GitHub Releases(공개 저장소 rorena15/Z-V_Scan)를 사용한다.
    # 이 URL은 GitHub REST API의 "최신 릴리즈 조회" 엔드포인트이며, 저장소가
    # public이므로 인증 토큰 없이도 호출 가능하다(비공개 저장소였다면 배포된
    # 실행파일에 토큰을 심어야 해서 이 방식을 못 썼을 것).
    # utils/update_checker.py가 이 URL을 호출해 tag_name을 VERSION과 비교하고,
    # 더 최신이면 release assets의 다운로드 링크를 사용자에게 안내한다.
    # 빈 문자열로 되돌리면 예전처럼 완전히 비활성화된다.
    UPDATE_CHECK_URL = "https://api.github.com/repos/rorena15/Z-V_Scan/releases/latest"

    # ----------------------------------------------------------------------
    # [5] 룰셋 파일 암호화 키 (rules/*_rules.json 보호)
    # ----------------------------------------------------------------------
    # PyArmor는 .py 코드만 보호하고 rules/*.json 같은 데이터 파일은 손대지
    # 않는다 - onedir 빌드로 바꾸면 이 파일들이 설치 폴더에 평문 그대로 노출돼
    # KISA 판정 로직/조치방안 전체를 누구나 열어볼 수 있게 된다.
    #
    # 그래서 빌드 시점에(ci/encrypt_rules.py) rules/*_rules.json을 이 키로
    # Fernet 암호화해서 {name}_rules.json.enc로 바꿔 그것만 배포판에 담고,
    # 실행 중에는 utils/rule_crypto.py가 이 키로 메모리에서만 복호화한다(디스크에
    # 평문으로 풀어놓지 않음). LICENSE_SALT/ENGINE_ACCESS_TOKEN과 마찬가지로
    # 이 키 자체도 PyArmor로 보호된 코드 안에 있다는 점에 기대는 방식이라, 완벽한
    # DRM이 아니라 "진입장벽을 높이는" 수준의 보호라는 한계는 동일하게 적용된다.
    #
    # 개발 중에는 rules/*.json 평문을 그대로 쓸 수 있어야 하므로(빌드 없이
    # 바로 룰 수정/테스트), rule_crypto.load_ruleset()은 .enc가 없으면 평문
    # 파일로 자동 폴백한다 - 이 키는 오직 "빌드된 배포판"에서만 실제로 쓰인다.
    RULE_ENCRYPTION_KEY = "8gUHbl7QOUhhyeZyK_6wrTMxJbrwWJnufELuYQTk_YQ="

    # ----------------------------------------------------------------------
    # [6] 룰셋 증분 업데이트 서명 검증 (Ed25519)
    # ----------------------------------------------------------------------
    # 공개키 자체는 노출돼도 안전한 값(서명 위조 불가, 검증만 가능)이지만,
    # [GS 인증 대비] 하드코딩 배제 원칙에 따라 소스에 상수로 박아두지 않고
    # config/rule_update_config.json(레포에 커밋됨, 비밀 아님)에서 읽는다
    # - utils/rule_update.py._load_update_config() 참고. 키 교체 시에도
    # 재컴파일 없이 이 파일만 갱신하면 되는 부수 효과도 있다.
    #
    # 개인키는 절대 이 저장소/exe/CI 어디에도 두지 않는다 - 개발자 하드웨어
    # 보안키(YubiKey류)에만 보관하고, 릴리즈마다 로컬에서 수동 서명한다
    # (ci/sign_rules_update.py). 룰의 command 필드는 SSH/WinRM으로 대상
    # 호스트에서 실제 실행되므로(privileged: true면 sudo까지), 조작된 룰셋은
    # 단순 오탐이 아니라 진단 대상 전체에 대한 RCE 공급망 공격이 될 수 있어
    # 이 서명 검증은 선택이 아니라 필수다.

    # ----------------------------------------------------------------------
    # [7] 데모/시뮬레이션 모드 대상 IP 허용 목록
    # ----------------------------------------------------------------------
    # [버그 수정] worker.py와 3개 inspector(ssh/windows/database)가 각자 이
    # 목록을 따로 하드코딩하고 있었는데, 이미 서로 어긋나 있었다(windows_inspector는
    # 127.0.0.1 누락, ssh/database_inspector는 127.0.0.2 누락) - worker.py는 특정
    # IP를 데모 대상으로 인식해 가짜 데이터를 주입하는데 정작 그 IP를 받는
    # inspector가 데모 모드로 인식 못 하면(또는 반대) 동작이 클래스마다 제각각으로
    # 갈렸다. 하나의 목록만 두고 전부 여기를 참조한다.
    DEMO_SIMULATION_IPS = ["0.0.0.0", "localhost", "127.0.0.1", "127.0.0.2"]