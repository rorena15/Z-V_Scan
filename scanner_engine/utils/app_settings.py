# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[Phase 3: 설정 페이지] 앱 전역 설정(로그 보관 기간, 테마, 리포트 출력 경로, 기본 계정 등)을
JSON 파일 하나에 저장/로드한다. Expert Mode 프로필(utils/expert_profile.py)과 같은
base_dir 해석 방식을 공유한다.
"""
import os
import sys
import json
import threading

_lock = threading.Lock()

DEFAULTS = {
    "log_retention_days": 90,
    "theme": "light",             # "dark" 또는 "light" (2026-07-15: 기본 테마를 라이트로 전환)
    "report_output_dir": "",      # 비어있으면 기존 기본값(<base_dir>/reports) 사용
    "default_username": "",
    "show_log_panel": False,      # 메인 창에 임베드된 System Log 패널 표시 여부 (기본 숨김)
    # [룰셋 증분 업데이트] 기본 OFF - OT/에어갭 환경에서 프로그램이 시작하자마자
    # 인터넷에 나가려 하면 그 자체로 현장 보안팀에 의심스러워 보일 수 있어,
    # 명시적으로 켜야만 업데이트 확인을 시도한다 (update_checker.py의 URL 미설정 시
    # 완전 비활성 철학과 동일).
    "ruleset_auto_update": False,
    # [리포트 탭 - 커스터마이징] PDF/Excel에만 적용(TXT는 고객사 매크로 호환 형식이라
    # 파일명 패턴이 고정돼야 해서 제외 - output/text_report.py 참고).
    "report_company_name": "",
    "report_title": "",
    "report_filename": "",
    # [PC 진단 도구] 비어있으면 report_output_dir과 동일하게 <base_dir>/reports 사용.
    # 파일명은 저장 대화상자의 기본 제안값일 뿐 - 결과 TXT 자체의 이름([PC]{host}_
    # {os}_{ip}.txt)은 crosscheck_parser.py가 host/os/ip를 파싱하는 데 그 구조를
    # 그대로 쓰기 때문에 여기서 자유롭게 바꿀 수 없다(설정 대상은 스크립트 파일명뿐).
    "pc_check_output_dir": "",
    "pc_check_script_filename": "Z-VulnScan_PC_Check.bat",
}


def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _get_settings_path():
    config_dir = os.path.join(get_base_dir(), 'config')
    try:
        os.makedirs(config_dir, exist_ok=True)
    except OSError:
        pass
    return os.path.join(config_dir, 'app_settings.json')


def load_settings():
    path = _get_settings_path()
    settings = dict(DEFAULTS)
    if os.path.exists(path):
        try:
            with _lock:
                with open(path, 'r', encoding='utf-8') as f:
                    settings.update(json.load(f))
        except Exception:
            pass
    return settings


def save_settings(settings):
    path = _get_settings_path()
    try:
        merged = dict(DEFAULTS)
        merged.update(settings)
        with _lock:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(merged, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def get_report_output_dir():
    """설정된 리포트 출력 경로가 있으면 그것을, 없으면 기존 기본 경로(<base_dir>/reports)를 반환"""
    settings = load_settings()
    custom = settings.get("report_output_dir", "").strip()
    if custom and os.path.isdir(custom):
        return custom
    return os.path.join(get_base_dir(), 'reports')


def get_pc_check_output_dir():
    """PC 진단 스크립트 저장 시 기본 제안 경로. 별도로 지정 안 했으면 리포트 출력
    경로(get_report_output_dir)와 동일한 기본값을 공유한다."""
    settings = load_settings()
    custom = settings.get("pc_check_output_dir", "").strip()
    if custom and os.path.isdir(custom):
        return custom
    return get_report_output_dir()
