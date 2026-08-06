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
