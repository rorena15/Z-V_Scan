# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[Phase 3: 전문가 모드] 룰 카테고리/개별 코드별 include-exclude 설정을 관리한다.
점검 명령어·중요도 등 룰 자체의 내용은 KISA 신뢰성을 위해 절대 수정하지 않고,
"이번 진단에서 이 코드를 뺄지 말지"만 저장한다.
"""
import os
import sys
import json
import threading

_lock = threading.Lock()


def _get_profile_path():
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    config_dir = os.path.join(base_dir, 'config')
    try:
        os.makedirs(config_dir, exist_ok=True)
    except OSError:
        pass
    return os.path.join(config_dir, 'expert_profile.json')


def load_profile():
    """{ruleset_filename: [excluded_code, ...]} 형태로 반환.

    이 프로필은 "이번 스캔 범위에 이 코드를 아예 넣을지 말지"만 결정한다 (사전 배제).
    이미 스캔된 결과를 사후에 예외 처리하는 것은 별개 기능인 Waiver(TBL_SCAN_RESULT의
    waiver_status/waiver_reason/waiver_approver, gui/waiver_dialog.py)가 담당하며,
    거기서는 판정 결과가 리포트에 "예외처리됨"으로 남고 사유가 함께 보존된다.
    """
    path = _get_profile_path()
    if not os.path.exists(path):
        return {}
    try:
        with _lock:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        return {}


def save_profile(profile):
    path = _get_profile_path()
    try:
        with _lock:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(profile, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def get_excluded_codes(ruleset_filename):
    """특정 룰셋 파일에서 스캔 범위 자체에서 제외된 코드 집합 (없으면 빈 집합)"""
    profile = load_profile()
    return set(profile.get(ruleset_filename, []))
