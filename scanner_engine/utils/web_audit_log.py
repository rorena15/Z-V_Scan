# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[웹 대시보드 관리자 작업 감사로그] 웹 대시보드는 취약점 진단 결과를 감사(audit)
추적성 있게 남기는 도구인데, 정작 그 도구 자신의 운영 행위(로그인, 계정 생성/삭제,
설정 변경, 라이선스 조작, 서버 종료 등)는 아무 기록도 안 남으면 이율배반적이다.
config/web_audit.log에 JSON Lines(한 줄에 이벤트 하나) 형식으로 append-only 기록한다 -
DB(zvuln_scan.db)와 분리해서, DB 암복호화 타이밍이나 스키마 마이그레이션과 무관하게
독립적으로 남는다.

이 파일도 dashboard_accounts.json과 마찬가지로 로컬 전용 운영 기록이라 .gitignore에
등록돼 있다.
"""
import os
import sys
import json
import threading
from datetime import datetime

_lock = threading.Lock()
MAX_ENTRIES = 5000  # 무한정 커지는 것 방지 - 넘으면 오래된 것부터 잘라낸다


def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _get_log_path():
    config_dir = os.path.join(get_base_dir(), 'config')
    try:
        os.makedirs(config_dir, exist_ok=True)
    except OSError:
        pass
    return os.path.join(config_dir, 'web_audit.log')


def log_event(actor, role, action, detail="", ip=""):
    """actor: 사용자명(로그인 실패 시에도 입력한 아이디를 그대로 남김) - '(익명)'
    등으로 뭉개지 않는다, 누가 시도했는지가 감사로그의 핵심이기 때문."""
    entry = {
        "ts": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "actor": actor or "",
        "role": role or "",
        "action": action,
        "detail": detail or "",
        "ip": ip or "",
    }
    line = json.dumps(entry, ensure_ascii=False)
    path = _get_log_path()
    try:
        with _lock:
            with open(path, 'a', encoding='utf-8') as f:
                f.write(line + "\n")
    except OSError:
        pass


def read_recent(limit=200):
    """최신 항목이 먼저 오도록 반환한다."""
    path = _get_log_path()
    if not os.path.exists(path):
        return []
    try:
        with _lock:
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
    except OSError:
        return []

    entries = []
    for line in lines[-MAX_ENTRIES:]:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except ValueError:
            continue
    entries.reverse()
    return entries[:limit]
