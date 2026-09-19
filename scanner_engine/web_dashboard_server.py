# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[웹 대시보드 모드] gui/web/dashboard.html·dashboard.js(원래 QWebEngineView에
file://로 로드되던 "보고서형" 대시보드)를 그대로 재사용해서 브라우저로 띄우는
로컬 서버. main.py가 시작 시 "앱으로 열지 / 웹으로 열지" 고른 결과가 웹일 때만
뜨며, 데스크톱 앱(ScannerApp)과 동시에 실행되는 경우는 없다 - 그래서 zvuln_scan.db
동시 접근이나 db_crypto의 시작/종료 시 암복호화 타이밍을 별도로 신경 쓸 필요가
없다(main.py의 기존 ensure_decrypted/encrypt_on_exit 훅을 그대로 공유).

[엔진 구동, 2026-09 확장] 처음엔 대시보드 조회 전용이었는데("GUI 껍데기만"),
"엔진 그대로 구동 기능은 전부 웹으로 쓰고 싶다"는 요청으로 Network Scan/Audit
실행 + 실시간 로그/진행률 + 리포트(PDF/Excel/TXT) 생성·다운로드까지 넓혔다.
core/worker.py의 ScanWorker(QThread)를 데스크톱과 완전히 동일하게 재사용한다 -
엔진 코드는 한 줄도 복제하지 않는다. 서버 프로세스 전체에서 스캔은 항상 하나만
실행되게 막는다(ScanJobManager) - 여러 관리자 계정이 동시에 로그인해 있어도 같은
대상/DB에 스캔이 겹쳐서 부하를 주는 상황을 방지하기 위함.

[범위 밖 - 데스크톱 전용으로 남겨둠] Expert Mode 프로파일 관리, Cross-check 모드,
PC 진단 툴킷, 자산 Excel/CSV 일괄 임포트, "기본 계정/자격증명"(OS keyring 저장).
각자 파일 업로드 처리나 스캔 엔진과의 별도 연결고리가 필요해서 제외했다 - 그 외
스캔 실행/자산·Waiver 관리/리포트/설정/계정 관리는 전부 웹에서도 가능하다.

인증: utils/dashboard_accounts.py의 다중 계정(각자 admin/operator/viewer 역할을
가짐) + Flask 세션 쿠키. 로그인 실패가 쌓이면 (요청 IP, 시도한 아이디) 조합
기준으로 잠깐 잠근다.

[권한 분리, 2026-09 확장] 계정마다 역할이 있다 - admin(전부 가능, 설정/계정
관리 포함) / operator(스캔 실행, 자산·Waiver 편집, 리포트 생성까지 - 설정/계정
관리 제외) / viewer(조회만, 쓰기 동작 전부 불가). 라우트 데코레이터
(_login_required=viewer 이상, _operator_required, _admin_required)가 실제
차단선이고, 프런트엔드(topbar.js 등)의 메뉴 숨김은 UX 편의일 뿐이다.

[브라우저가 꺼지면 서버도 같이 종료] topbar.js가 모든 페이지에서 주기적으로
/api/heartbeat를 호출한다. HeartbeatWatchdog이 일정 시간(기본 180초) 이상
하트비트가 끊기면 - 탭을 닫았거나 브라우저가 죽었다고 판단해 - "서버 종료"
버튼을 누른 것과 동일하게 shutdown_event를 set()한다(main.py의 QTimer가
받아서 앱을 종료).

[추가 보강, 2026-09]
- 본인 비밀번호 변경(/account) - 지금까지는 admin이 계정을 지웠다 새로
  만드는 것 말고 비밀번호를 바꿀 방법이 없었다. 역할 제한 없이 누구나 자기
  것만 바꿀 수 있다(현재 비밀번호 재확인 필수).
- 관리자 작업 감사로그(utils/web_audit_log.py) - 로그인 성공/실패, 계정
  생성/삭제, 설정·라이선스 변경, 자산 편집/삭제, Waiver, 스캔 시작/중지,
  리포트 생성, 서버 종료를 config/web_audit.log(JSON Lines)에 남기고
  /api/audit-log(admin 전용)로 조회한다.
- 생성된 리포트 목록(/api/reports/list) - 리포트 생성 직후에만 보이던
  다운로드 링크를, reports/ 폴더를 훑어 다시 볼 수 있게 했다.
- CSRF 토큰(synchronizer token 패턴) - 로그인 시 세션에 발급한 토큰을
  모든 /api/* 상태변경 요청(X-CSRF-Token 헤더)에서 검증한다.
"""
import csv
import hmac
import io
import json
import os
import secrets
import threading
import time
import zipfile
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for, jsonify, g, Response,
    send_from_directory, send_file, render_template_string
)
from werkzeug.serving import make_server
from PySide6.QtCore import Qt

from utils import dashboard_accounts, web_audit_log
from utils.app_settings import load_settings, save_settings, get_report_output_dir
from utils.secure_storage import SecureStorage
from utils.logger import AppLogger
from gui.dashboard_widgets import COLORS, STATUS_STYLE, set_theme
from gui.help_dialog import CATEGORY_ORDER as HELP_CATEGORY_ORDER, _format_detail_html as format_help_html
from gui.help_texts import HELP_TEXTS
from core.config import AppConfig
from core.license_validator import LicenseValidator
# [부팅 속도] core.worker(paramiko/pywinrm)·ssh_inspector·리포트 생성기(openpyxl/reportlab)는 스캔/
# 리포트/호스트키 화면에서만 필요해서 사용처 함수 안에서 import한다 - 서버가 뜨고 브라우저가 열리기까지
# ~1초를 줄인다(main.py가 서버 기동 직후 백그라운드 스레드로 미리 로드해 두므로 첫 사용 지연도 작다).

_WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gui', 'web')

# [무차별 대입 방어] 메모리 한정 카운터라 서버 재시작 시 초기화된다 - 로컬 전용
# 도구의 로그인 화면 수준에서는 충분하고, 별도 영속 저장소까지는 과하다고 판단.
_MAX_ATTEMPTS = 5
_LOCK_MINUTES = 5
_login_attempts = {}  # "{ip}:{username}" -> (fail_count, locked_until|None)
_attempts_lock = threading.Lock()

_LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8"><title>Z-VulnScan 웹 대시보드 로그인</title>
<link rel="manifest" href="/manifest.webmanifest"><link rel="icon" href="/icon.svg" type="image/svg+xml">
<style>
  html,body{margin:0;height:100%;display:flex;align-items:center;justify-content:center;
    background:#F5F7FA;font-family:'Malgun Gothic','Segoe UI',sans-serif;}
  .box{background:#fff;border:1px solid #E3E7EE;border-radius:12px;padding:32px 28px;
    width:300px;box-shadow:0 3px 22px rgba(0,0,0,0.08);}
  h1{font-size:15px;margin:0 0 18px;color:#1B2430;}
  input{width:100%;box-sizing:border-box;padding:10px 12px;margin-bottom:10px;
    border:1px solid #E3E7EE;border-radius:8px;font-size:13px;}
  button{width:100%;padding:10px;border:none;border-radius:8px;background:#2E6BE6;
    color:#fff;font-weight:600;font-size:13px;cursor:pointer;}
  button:hover{background:#2860D6;}
  .err{color:#C0271F;font-size:12px;margin-bottom:10px;}
</style></head>
<body>
  <form class="box" method="post">
    <h1>Z-VulnScan 웹 대시보드</h1>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <input type="text" name="username" placeholder="아이디" autofocus required>
    <input type="password" name="password" placeholder="비밀번호" required>
    <button type="submit">로그인</button>
  </form>
</body></html>
"""


def _client_key():
    username = request.form.get('username', '') if request.method == 'POST' else request.args.get('username', '')
    return f"{request.remote_addr}:{username.strip().lower()}"


def _is_locked(key):
    with _attempts_lock:
        entry = _login_attempts.get(key)
        if not entry:
            return False
        count, locked_until = entry
        if locked_until and datetime.now() < locked_until:
            return True
        if locked_until and datetime.now() >= locked_until:
            _login_attempts.pop(key, None)
        return False


def _register_failure(key):
    with _attempts_lock:
        count, _ = _login_attempts.get(key, (0, None))
        count += 1
        locked_until = datetime.now() + timedelta(minutes=_LOCK_MINUTES) if count >= _MAX_ATTEMPTS else None
        _login_attempts[key] = (count, locked_until)


def _clear_failures(key):
    with _attempts_lock:
        _login_attempts.pop(key, None)


_FORBIDDEN_PAGE = """
<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8"><title>접근 제한</title></head>
<body style="font-family:'Malgun Gothic','Segoe UI',sans-serif;padding:60px;text-align:center;color:#5B6675;">
  <h2 style="color:#1B2430;">접근 권한이 없습니다</h2>
  <p>{{ message }}</p>
  <p><a href="/" style="color:#2E6BE6;">대시보드로 돌아가기</a></p>
</body></html>
"""


class SessionRegistry:
    """[세션 관리] Flask 기본 세션은 서명된 쿠키라 서버가 "지금 누가 접속해 있는지"
    알 수도, 특정 세션을 끊을 수도 없다. 쿠키에는 무작위 sid만 담고 실제 세션 정보는
    이 서버 메모리 레지스트리에 둬서, 관리자가 접속 중인 세션을 보고 강제로 끊을 수 있게
    한다(레지스트리에서 지우면 그 쿠키는 즉시 무효). 서버 재시작 시 전부 사라지는 건
    기존 동작(secret_key가 매번 새로 만들어짐)과 동일하다."""

    IDLE_TIMEOUT_SECONDS = 12 * 3600

    def __init__(self):
        self._lock = threading.Lock()
        self._by_sid = {}

    def create(self, username, role, ip, user_agent):
        sid = secrets.token_urlsafe(24)
        now = datetime.now()
        with self._lock:
            self._by_sid[sid] = {
                "public_id": secrets.token_hex(4), "username": username, "role": role,
                "ip": ip, "user_agent": (user_agent or '')[:120], "login_at": now, "last_seen": now,
            }
        return sid

    def touch(self, sid):
        now = datetime.now()
        with self._lock:
            rec = self._by_sid.get(sid)
            if rec is None:
                return None
            if (now - rec["last_seen"]).total_seconds() > self.IDLE_TIMEOUT_SECONDS:
                del self._by_sid[sid]
                return None
            rec["last_seen"] = now
            return dict(rec)

    def remove(self, sid):
        with self._lock:
            self._by_sid.pop(sid, None)

    def remove_user(self, username, except_sid=None):
        with self._lock:
            victims = [sid for sid, r in self._by_sid.items()
                       if r["username"].lower() == (username or '').lower() and sid != except_sid]
            for sid in victims:
                del self._by_sid[sid]
            return len(victims)

    def remove_by_public_id(self, public_id):
        with self._lock:
            for sid, r in list(self._by_sid.items()):
                if r["public_id"] == public_id:
                    del self._by_sid[sid]
                    return r["username"]
        return None

    def list(self):
        with self._lock:
            return [dict(r, sid=sid) for sid, r in self._by_sid.items()]


_sessions = SessionRegistry()


def _current_identity():
    """요청 하나당 한 번 계산해 g에 캐시한다. 브라우저 세션(쿠키의 sid가 레지스트리에
    살아있음) 또는 Authorization: Bearer API 토큰 중 하나로 인증된 신원을 돌려주고,
    둘 다 아니면 None. via 값으로 세션/토큰을 구분한다 - CSRF 검사와 자격증명 관련 동작
    (비밀번호/토큰 발급)은 via=='session'일 때만 허용하는 데 쓴다."""
    if hasattr(g, 'identity'):
        return g.identity
    ident = None
    sid = session.get('sid')
    if sid:
        rec = _sessions.touch(sid)
        if rec:
            ident = {"username": rec["username"], "role": rec["role"], "via": "session", "sid": sid}
    if ident is None:
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            verified = dashboard_accounts.verify_api_token(auth[7:].strip())
            if verified:
                ident = {"username": verified["username"], "role": verified["role"], "via": "token",
                         "token_id": verified["token_id"], "token_name": verified["token_name"]}
    g.identity = ident
    return ident


def _require_role(min_role):
    """[권한 분리] 로그인 여부뿐 아니라 계정의 role(admin/operator/viewer)이
    min_role 이상인지까지 확인한다. API 라우트(/api/*)는 JSON 403을, 페이지
    라우트는 안내 페이지를 돌려준다 - 어느 쪽이든 서버가 실제 차단선이고,
    프런트엔드(topbar.js 등)의 메뉴 숨김은 UX 편의일 뿐 보안 경계가 아니다."""
    min_rank = dashboard_accounts.ROLE_RANK[min_role]

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            ident = _current_identity()
            if not ident:
                if request.path.startswith('/api/'):
                    return jsonify({"error": "로그인이 필요합니다."}), 401
                return redirect(url_for('login'))
            role = ident['role']
            if dashboard_accounts.ROLE_RANK.get(role, 0) < min_rank:
                message = f"이 작업은 {dashboard_accounts.ROLE_LABELS[min_role]} 이상 권한이 필요합니다. (현재: {dashboard_accounts.ROLE_LABELS.get(role, role)})"
                if request.path.startswith('/api/'):
                    return jsonify({"error": message}), 403
                return render_template_string(_FORBIDDEN_PAGE, message=message), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def _session_only():
    """비밀번호 변경·API 토큰 발급/폐기처럼 '자격증명' 성격의 동작은 API 토큰으로는
    못 하게 막는다(토큰이 유출돼도 계정 탈취로 번지지 않도록). 세션이 아니면 403 응답."""
    ident = _current_identity()
    if not ident or ident['via'] != 'session':
        return jsonify({"error": "이 작업은 브라우저 로그인 세션에서만 할 수 있습니다(API 토큰 불가)."}), 403
    return None


# 로그인만 되어 있으면 통과(조회자 이상 - 사실상 모든 로그인 계정) - 기존
# @_login_required 호출부를 그대로 두기 위한 별칭.
_login_required = _require_role('viewer')
_operator_required = _require_role('operator')
_admin_required = _require_role('admin')

# [CSRF 방지] 상태를 바꾸는 요청(POST/PUT/PATCH/DELETE)은 로그인 시 세션에
# 발급한 토큰을 X-CSRF-Token 헤더로 그대로 돌려받아야 통과한다(synchronizer
# token 패턴). JSON 바디 요구 + SESSION_COOKIE_SAMESITE=Lax만으로도 고전적인
# <form> 자동제출 CSRF는 대부분 막히지만, "제대로" 막으려면 서버가 발급한
# 토큰을 확인하는 게 표준이라 추가했다. /login은 로그인 자체가 토큰을 발급받는
# 시점이라 예외.
_CSRF_EXEMPT_PATHS = {'/login'}


def _audit(action, detail=""):
    """현재 신원(세션/토큰)에서 actor/role을 모아 web_audit_log에 한 줄 남긴다. API 토큰으로
    한 동작은 actor에 "소유자 [API:토큰이름]"으로 남겨 세션 동작과 구분되게 한다."""
    ident = _current_identity()
    actor, role = '', ''
    if ident:
        actor = ident['username'] + (f" [API:{ident['token_name']}]" if ident['via'] == 'token' else '')
        role = ident['role']
    web_audit_log.log_event(actor=actor, role=role, action=action, detail=detail, ip=request.remote_addr or '')


class HeartbeatTracker:
    """[웹 대시보드가 꺼지면 서버도 같이 종료] 브라우저가 열려있는 동안
    topbar.js가 주기적으로 /api/heartbeat를 호출해 여기에 '마지막으로 살아있는
    걸 확인한 시각'을 기록한다. 탭을 닫거나 브라우저가 죽으면 더 이상 호출이
    안 오므로, HeartbeatWatchdog이 일정 시간(기본 90초) 이상 조용하면 서버를
    끈다. 페이지 이동(대시보드->스캔 등)은 새 페이지도 곧바로 topbar.js를
    로드해 하트비트를 이어가므로 오작동하지 않는다."""

    def __init__(self):
        self._lock = threading.Lock()
        self.last_seen = None

    def touch(self):
        with self._lock:
            self.last_seen = datetime.now()

    def seconds_since_last_seen(self):
        with self._lock:
            if self.last_seen is None:
                return None
            return (datetime.now() - self.last_seen).total_seconds()


class HeartbeatWatchdog(threading.Thread):
    """[웹 대시보드가 꺼지면 서버도 같이 종료] 아무도 로그인하기 전(하트비트가
    한 번도 안 온 상태)에는 절대 스스로 끄지 않는다 - 그렇지 않으면 서버가
    뜨자마자 아무도 접속하기 전에 죽어버린다. 최소 한 번 하트비트가 온 뒤,
    그 이후로 timeout_seconds 이상 조용하면(=탭이 닫혔거나 브라우저가 죽었다고
    판단) '서버 종료' 버튼을 누른 것과 동일하게 shutdown_event를 set()한다.

    [타임아웃 180초로 여유를 둔 이유] topbar.js는 20초마다 하트비트를 보내지만,
    브라우저가 백그라운드 탭의 setInterval을 강하게 스로틀링하면(Chrome은 오래
    비활성 상태인 탭에서 최대 1분 간격까지 늦출 수 있음) 실제 탭은 열려있는데도
    하트비트가 늦게 도착할 수 있다. 스캔 실행 중에 사용자가 잠깐 다른 창을 보는
    것만으로 서버가 꺼져버리면 안 되므로, 정상적인 스로틀링을 충분히 흡수할 수
    있는 여유(스로틀 간격의 3배 이상)를 뒀다 - 종료가 몇 분 늦어지는 것보다
    실행 중인 작업이 실수로 끊기는 쪽이 훨씬 나쁘다고 판단."""

    def __init__(self, heartbeat, shutdown_event, timeout_seconds=180, check_interval=5):
        super().__init__(daemon=True)
        self._heartbeat = heartbeat
        self._shutdown_event = shutdown_event
        self._timeout = timeout_seconds
        self._interval = check_interval

    def run(self):
        while not self._shutdown_event.is_set():
            if self._shutdown_event.wait(self._interval):
                return
            elapsed = self._heartbeat.seconds_since_last_seen()
            if elapsed is not None and elapsed > self._timeout:
                AppLogger.log_error(
                    "[Web Dashboard] No heartbeat for %.0fs - assuming browser closed, shutting down." % elapsed,
                    None
                )
                self._shutdown_event.set()
                return


def _build_license_manager():
    """gui/main_window.py의 ScannerApp.__init__()이 하는 것과 동일한 절차(license.dat
    로드 -> 검증 -> 등급 반영)를 웹 프로세스에서도 반복한다 - 리포트 등급 제한(Excel은
    Professional+, 증적/조치방안 노출 범위)을 데스크톱과 동일하게 지키기 위함."""
    from gui.main_window import LicenseManager
    mgr = LicenseManager()
    saved_key = LicenseValidator.load_license()
    if saved_key:
        is_valid, tier, expiry_date = LicenseValidator.validate_key(saved_key)
        if is_valid:
            mgr.current_tier = tier
            mgr.expiry_date = expiry_date
    return mgr


def _safe_report_path(filename):
    """다운로드 요청 파일명이 리포트 출력 폴더 밖을 가리키지 않는지 확인한다
    (path traversal 방지) - 파일명이 사용자 요청 쿼리스트링으로 들어오기 때문."""
    base = os.path.realpath(get_report_output_dir())
    target = os.path.realpath(os.path.join(base, filename))
    if target != base and not target.startswith(base + os.sep):
        return None
    return target


class ScanJobManager:
    """[웹 대시보드 - 엔진 구동] 데스크톱의 ScanWorker(QThread)를 그대로 재사용해서
    웹에서도 스캔/점검을 실행한다. Flask 요청 스레드에는 Qt 이벤트 루프가 없으므로,
    ScanWorker의 시그널을 Qt.DirectConnection으로 연결한다 - 이러면 이벤트 루프 유무와
    무관하게 emit()한 바로 그 스레드(ScanWorker 자신의 QThread)에서 콜백이 동기
    실행된다. 실측으로 확인함: 기본 AutoConnection은 이 프로세스처럼 이벤트 루프를
    돌리지 않는 상태에서는 콜백이 전혀 호출되지 않았다(큐에만 쌓이고 아무도 안 뺌).
    콜백은 순수 파이썬 dict/list를 락으로 보호하며 갱신할 뿐이라 Qt 위젯을 건드리지
    않는 이 상황에서 스레드 안전하다.

    서버 프로세스 전체에서 스캔은 한 번에 하나만 실행한다 - 여러 관리자 계정이
    로그인해 있어도 공유되는 하나의 Job 상태를 본다."""

    MAX_LOG_LINES = 5000

    def __init__(self):
        self._lock = threading.Lock()
        self.worker = None
        self.state = self._idle_state()
        self.log_lines = []

    def _idle_state(self):
        return {
            "running": False, "mode": None, "target": None,
            "total": 0, "current": 0, "percent": 0,
            "finished_reason": None, "started_at": None, "assets_found": 0,
        }

    def is_running(self):
        with self._lock:
            return self.state["running"]

    def start(self, worker, mode, target):
        with self._lock:
            if self.state["running"]:
                return False
            self.worker = worker
            self.log_lines = []
            self.state = self._idle_state()
            self.state.update({
                "running": True, "mode": mode, "target": target,
                "started_at": datetime.now().strftime('%H:%M:%S'),
            })

        # [락 밖에서 연결] connect() 자체는 스레드 안전하지만, 아래 콜백들이 각자
        # self._lock을 다시 잡으므로 여기서 락을 쥔 채로 두면 안 된다.
        worker.log_signal.connect(self._on_log, Qt.DirectConnection)
        worker.progress_signal.connect(self._on_progress, Qt.DirectConnection)
        worker.started_signal.connect(self._on_started, Qt.DirectConnection)
        worker.asset_found_signal.connect(self._on_asset_found, Qt.DirectConnection)
        worker.finish_signal.connect(self._on_finish, Qt.DirectConnection)
        worker.start()
        return True

    def stop(self):
        # [데드락 방지] worker.stop()이 log_signal.emit()을 동기 호출하고, 그 콜백
        # (_on_log)이 다시 self._lock을 잡는다 - 락을 쥔 채로 worker.stop()을 부르면
        # 같은 스레드에서 non-reentrant 락을 두 번 잡아 멈춘다. 그래서 worker 참조만
        # 락 안에서 꺼내고, 실제 stop() 호출은 락 밖에서 한다.
        with self._lock:
            worker = self.worker if self.state["running"] else None
        if worker:
            worker.stop()

    def _on_log(self, msg):
        with self._lock:
            self.log_lines.append(msg)
            if len(self.log_lines) > self.MAX_LOG_LINES:
                self.log_lines = self.log_lines[-self.MAX_LOG_LINES:]

    def _on_progress(self, percent, current):
        with self._lock:
            self.state["percent"] = percent
            self.state["current"] = current

    def _on_started(self, total):
        with self._lock:
            self.state["total"] = total
        self._on_log(f"[Info] Scanning Start. Targets: {total}")

    def _on_asset_found(self, ip, hostname, os_type, mac_addr, vendor, hostname_source):
        with self._lock:
            self.state["assets_found"] += 1

    def _on_finish(self, reason):
        with self._lock:
            self.state["running"] = False
            self.state["finished_reason"] = reason
        self._on_log(f"[Finish] {reason}")

    def snapshot(self, since=0):
        with self._lock:
            since = max(0, since)
            return dict(self.state), list(self.log_lines[since:]), len(self.log_lines)


def create_app(db, shutdown_event=None, heartbeat=None):
    app = Flask(__name__)
    app.secret_key = secrets.token_bytes(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')

    job_manager = ScanJobManager()
    if heartbeat is None:
        heartbeat = HeartbeatTracker()

    try:
        set_theme(load_settings().get('theme', 'light'))
    except Exception:
        pass

    @app.before_request
    def _enforce_csrf():
        if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
            return None
        if not request.path.startswith('/api/') or request.path in _CSRF_EXEMPT_PATHS:
            return None
        ident = _current_identity()
        if not ident or ident['via'] != 'session':
            # 미인증은 아래 _require_role이 401로 막는다(여기서 먼저 "CSRF 무효"로
            # 답하면 원인이 헷갈림). API 토큰(Authorization 헤더) 요청은 브라우저가
            # 쿠키를 자동으로 얹는 CSRF 공격 대상이 아니므로 검사하지 않는다.
            return None
        token = session.get('csrf_token')
        header_token = request.headers.get('X-CSRF-Token', '')
        if not token or not hmac.compare_digest(header_token, token):
            return jsonify({"error": "CSRF 토큰이 유효하지 않습니다. 페이지를 새로고침한 뒤 다시 시도하세요."}), 403
        return None

    # ------------------------------------------------------------------
    # 로그인/로그아웃
    # ------------------------------------------------------------------
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            key = _client_key()
            if _is_locked(key):
                error = f"로그인 시도가 너무 많습니다. {_LOCK_MINUTES}분 후 다시 시도하세요."
            else:
                ok, role = dashboard_accounts.verify_login(username, password)
                if ok:
                    _clear_failures(key)
                    session.clear()
                    session['sid'] = _sessions.create(
                        username.strip(), role, request.remote_addr or '', request.headers.get('User-Agent', ''))
                    session['csrf_token'] = secrets.token_hex(16)
                    g.identity = {"username": username.strip(), "role": role, "via": "session", "sid": session['sid']}
                    heartbeat.touch()
                    _audit("login_success")
                    return redirect(url_for('index'))
                else:
                    _register_failure(key)
                    error = "아이디 또는 비밀번호가 올바르지 않습니다."
                    web_audit_log.log_event(
                        actor=username.strip(), role="", action="login_failed",
                        detail="", ip=request.remote_addr or ''
                    )
        return render_template_string(_LOGIN_PAGE, error=error)

    @app.route('/logout')
    def logout():
        if _current_identity():
            _audit("logout")
        _sessions.remove(session.get('sid'))
        session.clear()
        return redirect(url_for('login'))

    @app.route('/api/server/shutdown', methods=['POST'])
    @_admin_required
    def api_server_shutdown():
        """[데스크톱 창 없이 백그라운드 실행] main.py가 넘겨준 shutdown_event만
        set()한다 - 실제 QApplication.quit()/서버 정지는 main.py의 메인 스레드
        QTimer가 이 이벤트를 보고 자기 스레드에서 처리한다(create_app() docstring
        참고). 실행 중인 스캔이 있으면 먼저 멈춘다. 모든 로그인 사용자를 강제로
        끊는 행동이라 관리자만 허용한다."""
        _audit("server_shutdown")
        if job_manager.is_running():
            job_manager.stop()
        if shutdown_event is not None:
            shutdown_event.set()
        return jsonify({"ok": True})

    @app.route('/api/whoami')
    @_login_required
    def api_whoami():
        ident = _current_identity()
        return jsonify({
            "username": ident['username'],
            "role": ident['role'],
            "csrf_token": session.get('csrf_token', '') if ident['via'] == 'session' else '',
        })

    @app.route('/api/heartbeat', methods=['POST'])
    @_login_required
    def api_heartbeat():
        heartbeat.touch()
        return jsonify({"ok": True})

    @app.route('/topbar.js')
    @_login_required
    def topbar_js():
        return send_from_directory(_WEB_DIR, 'topbar.js')

    # ------------------------------------------------------------------
    # 내 계정 (본인 비밀번호 변경) - /accounts(다른 계정 추가/삭제)는 admin
    # 전용이라, 그와 별개로 "로그인한 누구나 자기 비밀번호는 바꿀 수 있어야
    # 한다"는 요구를 채우려고 역할 제한 없이(viewer 포함) 열어뒀다. 지금까지는
    # admin이 계정을 지웠다 새로 만드는 것 말고는 비밀번호를 바꿀 방법이 없었다.
    # ------------------------------------------------------------------
    @app.route('/account')
    @_login_required
    def account_page():
        return send_from_directory(_WEB_DIR, 'account.html')

    @app.route('/account.js')
    @_login_required
    def account_js():
        return send_from_directory(_WEB_DIR, 'account.js')

    @app.route('/api/account/password', methods=['POST'])
    @_login_required
    def api_account_password():
        data = request.get_json(silent=True) or {}
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm = data.get('confirm', '')
        if new_password != confirm:
            return jsonify({"error": "새 비밀번호가 서로 일치하지 않습니다."}), 400
        blocked = _session_only()
        if blocked:
            return blocked
        ident = _current_identity()
        ok, error = dashboard_accounts.change_password(ident['username'], current_password, new_password)
        if not ok:
            return jsonify({"error": error}), 400
        # 비밀번호가 바뀌면 이 계정의 '다른' 로그인 세션은 전부 끊는다 - 탈취된 세션이
        # 있었다면 비밀번호를 바꾼 뒤에도 계속 살아있는 걸 막는다(현재 세션은 유지).
        revoked = _sessions.remove_user(ident['username'], except_sid=ident['sid'])
        _audit("password_change_self", detail=f"other_sessions_revoked={revoked}")
        return jsonify({"ok": True})

    # ------------------------------------------------------------------
    # 대시보드
    # ------------------------------------------------------------------
    @app.route('/')
    @_login_required
    def index():
        return send_from_directory(_WEB_DIR, 'dashboard.html')

    @app.route('/dashboard.js')
    @_login_required
    def dashboard_js():
        return send_from_directory(_WEB_DIR, 'dashboard.js')

    @app.route('/vendor/<path:filename>')
    @_login_required
    def vendor(filename):
        return send_from_directory(os.path.join(_WEB_DIR, 'vendor'), filename)

    @app.route('/api/dashboard-data')
    @_login_required
    def dashboard_data():
        try:
            payload = {
                "colors": dict(COLORS),
                "status_colors": {k: v[1] for k, v in STATUS_STYLE.items()},
                "status_labels": {k: v[2] for k, v in STATUS_STYLE.items()},
                "findings": db.get_latest_findings(),
                "security_history": db.get_security_level_history(),
                "logged_in_as": _current_identity()['username'],
            }
        except Exception as e:
            AppLogger.log_error("[Web Dashboard] Data query failed", e)
            return jsonify({"error": str(e)}), 500
        return jsonify(payload)

    # ------------------------------------------------------------------
    # 스캔 실행 (엔진 구동)
    # ------------------------------------------------------------------
    @app.route('/scan')
    @_login_required
    def scan_page():
        return send_from_directory(_WEB_DIR, 'scan.html')

    @app.route('/scan.js')
    @_login_required
    def scan_js():
        return send_from_directory(_WEB_DIR, 'scan.js')

    @app.route('/api/scan/start', methods=['POST'])
    @_operator_required
    def api_scan_start():
        data = request.get_json(silent=True) or {}
        mode = data.get('mode')
        target = (data.get('target') or '').strip()
        ident = _current_identity()
        default_operator = ident['username'] + ('' if ident['via'] == 'session' else f" [API:{ident['token_name']}]")
        operator = (data.get('operator') or default_operator).strip()
        ot_mode = bool(data.get('ot_mode'))
        demo_mode = bool(data.get('demo_mode'))

        max_workers = data.get('max_workers')
        try:
            max_workers = int(max_workers) if max_workers not in (None, '') else None
        except (TypeError, ValueError):
            max_workers = None

        if not target:
            return jsonify({"error": "대상을 입력하세요."}), 400
        if mode not in ("NETWORK_SCAN", "AUDIT_VULN"):
            return jsonify({"error": "잘못된 모드입니다."}), 400
        if mode == "AUDIT_VULN" and "/" in target:
            return jsonify({"error": "정밀 진단(Audit)은 단일 IP만 지원합니다."}), 400
        if job_manager.is_running():
            return jsonify({"error": "이미 실행 중인 스캔이 있습니다."}), 409

        from core.worker import ScanWorker
        from core.advanced_scanner import AdvancedScanner
        try:
            if mode == "NETWORK_SCAN":
                port_mode = data.get('port_mode', 'quick')
                target_ports = None
                if port_mode == 'custom':
                    p_str = (data.get('custom_ports') or '').strip()
                    if not p_str:
                        return jsonify({"error": "Custom 포트를 입력하세요."}), 400
                    target_ports = AdvancedScanner.parse_ports(p_str)
                    if not target_ports:
                        return jsonify({"error": "포트 형식이 올바르지 않습니다."}), 400
                elif port_mode == 'full':
                    target_ports = list(range(1, 65536))

                worker = ScanWorker(
                    "NETWORK_SCAN", target, ports=target_ports,
                    ot_mode=ot_mode, demo_mode=demo_mode, operator=operator,
                    max_workers=max_workers, engine_token=AppConfig.ENGINE_ACCESS_TOKEN,
                )
            elif (data.get('device_type') or '') == 'configfile':
                config_text = data.get('config_text') or ''
                if not config_text.strip():
                    return jsonify({"error": "설정 파일 내용을 입력하거나 파일을 선택하세요."}), 400
                if len(config_text) > 2 * 1024 * 1024:
                    return jsonify({"error": "설정 파일이 너무 큽니다(최대 2MB)."}), 400
                from utils.os_utils import OSUtils
                if not OSUtils.is_safe_host(target):
                    return jsonify({"error": "대상 칸에는 자산 이름을 영문/숫자/. : - 로만 입력하세요."}), 400
                worker = ScanWorker(
                    "AUDIT_VULN", target, operator=operator, demo_mode=False,
                    engine_token=AppConfig.ENGINE_ACCESS_TOKEN, config_text=config_text,
                )
            else:
                is_sim = target in ("127.0.0.1", "localhost", "0.0.0.0")
                user = (data.get('username') or '').strip()
                pw = data.get('password') or ''
                if not is_sim and (not user or not pw):
                    return jsonify({"error": "SSH/WinRM 계정 정보가 필요합니다."}), 400
                if not is_sim and not SecureStorage.save_credential(target, user, pw):
                    return jsonify({"error": "자격증명 저장 실패"}), 500

                db_user = (data.get('db_username') or '').strip()
                if db_user:
                    db_pw = data.get('db_password') or ''
                    if not is_sim and not db_pw:
                        return jsonify({"error": "DB 전용 계정을 사용하려면 DB 비밀번호도 입력하세요."}), 400
                    if not is_sim and not SecureStorage.save_credential(target, db_user, db_pw):
                        return jsonify({"error": "DB 자격증명 저장 실패"}), 500

                connect_timeout = data.get('connect_timeout')
                try:
                    connect_timeout = int(connect_timeout) if connect_timeout not in (None, '') else None
                except (TypeError, ValueError):
                    connect_timeout = None

                oracle_service = (data.get('oracle_service') or '').strip()
                device_type = (data.get('device_type') or '').strip() or None

                worker = ScanWorker(
                    "AUDIT_VULN", target, user, db_user=db_user or None,
                    ot_mode=ot_mode, demo_mode=demo_mode, operator=operator,
                    max_workers=max_workers, oracle_service_name=oracle_service or None,
                    engine_token=AppConfig.ENGINE_ACCESS_TOKEN, connect_timeout=connect_timeout,
                    device_type=device_type,
                )
        except Exception as e:
            AppLogger.log_error("[Web Dashboard] Scan worker construction failed", e)
            return jsonify({"error": f"스캔 시작 실패: {e}"}), 500

        if not job_manager.start(worker, mode, target):
            return jsonify({"error": "이미 실행 중인 스캔이 있습니다."}), 409
        _audit("scan_start", detail=f"mode={mode} target={target}")
        return jsonify({"ok": True})

    @app.route('/api/scan/stop', methods=['POST'])
    @_operator_required
    def api_scan_stop():
        _audit("scan_stop")
        job_manager.stop()
        return jsonify({"ok": True})

    @app.route('/api/scan/status')
    @_login_required
    def api_scan_status():
        try:
            since = int(request.args.get('since', 0))
        except (TypeError, ValueError):
            since = 0
        state, new_lines, total_lines = job_manager.snapshot(since)
        return jsonify({"state": state, "log_lines": new_lines, "log_total": total_lines})

    # ------------------------------------------------------------------
    # 자산 관리 (DB Manager + Waiver, 2026-09 확장) - gui/db_manager.py·
    # gui/waiver_dialog.py와 동일한 DBConnector 메서드를 그대로 재사용한다.
    # ------------------------------------------------------------------
    _ASSET_EDITABLE_FIELDS = {"hostname", "os_type", "mac_addr", "description", "zone_tag"}

    @app.route('/assets')
    @_login_required
    def assets_page():
        return send_from_directory(_WEB_DIR, 'assets.html')

    @app.route('/assets.js')
    @_login_required
    def assets_js():
        return send_from_directory(_WEB_DIR, 'assets.js')

    @app.route('/api/assets')
    @_login_required
    def api_assets_list():
        try:
            rows = db.get_assets_for_manager()
        except Exception as e:
            AppLogger.log_error("[Web Dashboard] Asset list failed", e)
            return jsonify({"error": str(e)}), 500
        keys = ["id", "ip", "hostname", "os_type", "mac_addr", "open_ports", "last_seen", "description", "zone_tag"]
        return jsonify([dict(zip(keys, row)) for row in rows])

    @app.route('/api/assets/<int:asset_id>', methods=['PATCH'])
    @_operator_required
    def api_assets_update(asset_id):
        data = request.get_json(silent=True) or {}
        field = data.get('field')
        value = data.get('value', '')
        if field not in _ASSET_EDITABLE_FIELDS:
            return jsonify({"error": "수정할 수 없는 필드입니다."}), 400
        if not db.update_asset_field(asset_id, field, value):
            return jsonify({"error": "수정에 실패했습니다."}), 500
        _audit("asset_update", detail=f"asset_id={asset_id} field={field}")
        return jsonify({"ok": True})

    @app.route('/api/assets/<int:asset_id>', methods=['DELETE'])
    @_operator_required
    def api_assets_delete(asset_id):
        if not db.delete_asset_by_id(asset_id):
            return jsonify({"error": "삭제에 실패했습니다."}), 500
        _audit("asset_delete", detail=f"asset_id={asset_id}")
        return jsonify({"ok": True})

    @app.route('/api/assets/<int:asset_id>/results')
    @_login_required
    def api_assets_results(asset_id):
        try:
            rows = db.get_latest_results_for_asset(asset_id)
        except Exception as e:
            AppLogger.log_error("[Web Dashboard] Asset results failed", e)
            return jsonify({"error": str(e)}), 500
        keys = ["result_id", "code", "kisa_code", "name", "risk", "status", "waived", "reason", "approver", "waiver_date"]
        return jsonify([dict(zip(keys, row)) for row in rows])

    @app.route('/api/assets/<int:asset_id>/waiver', methods=['POST'])
    @_operator_required
    def api_assets_waiver(asset_id):
        data = request.get_json(silent=True) or {}
        result_id = data.get('result_id')
        waived = bool(data.get('waived'))
        reason = (data.get('reason') or '').strip()
        approver = (data.get('approver') or '').strip()
        if not result_id:
            return jsonify({"error": "result_id가 필요합니다."}), 400
        if waived and (not reason or not approver):
            return jsonify({"error": "예외처리는 사유와 승인자가 모두 필요합니다."}), 400
        if not db.set_waiver(result_id, waived, reason=reason, approver=approver):
            return jsonify({"error": "예외처리 저장에 실패했습니다."}), 500
        _audit("waiver_set" if waived else "waiver_clear", detail=f"asset_id={asset_id} result_id={result_id}")
        return jsonify({"ok": True})

    # ------------------------------------------------------------------
    # 리포트 생성/다운로드
    # ------------------------------------------------------------------
    @app.route('/api/reports/generate', methods=['POST'])
    @_operator_required
    def api_reports_generate():
        data = request.get_json(silent=True) or {}
        report_type = data.get('type')
        license_mgr = _build_license_manager()
        from output.pdf_report import PDFGenerator
        from output.excel_report import ExcelGenerator
        from output.text_report import TextReportGenerator

        try:
            if report_type == 'pdf':
                generator = PDFGenerator(remediation_level=license_mgr.remediation_level())
                filepaths = [generator.generate()]
            elif report_type == 'excel':
                if not license_mgr.can_export_excel():
                    return jsonify({"error": "Excel 내보내기는 Professional 이상 라이선스가 필요합니다."}), 403
                generator = ExcelGenerator(
                    evidence_level=license_mgr.evidence_level(),
                    remediation_level=license_mgr.remediation_level(),
                )
                filepaths = [generator.generate()]
            elif report_type == 'txt':
                generator = TextReportGenerator(
                    evidence_level=license_mgr.evidence_level(),
                    remediation_level=license_mgr.remediation_level(),
                )
                filepaths = generator.generate()
            else:
                return jsonify({"error": "잘못된 리포트 유형입니다."}), 400
        except Exception as e:
            AppLogger.log_error("[Web Dashboard] Report generation failed", e)
            return jsonify({"error": f"리포트 생성 실패: {e}"}), 500

        if not filepaths:
            return jsonify({"error": "생성된 파일이 없습니다(점검 데이터가 없을 수 있습니다)."}), 500

        if len(filepaths) == 1:
            rel_name = os.path.basename(filepaths[0])
        else:
            # [TXT - 호스트별 다중 파일] 하나의 다운로드로 받을 수 있도록 zip으로 묶는다.
            rel_name = f"Z-VulnScan_TXT_Reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            zip_path = os.path.join(get_report_output_dir(), rel_name)
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for fp in filepaths:
                    zf.write(fp, arcname=os.path.basename(fp))

        _audit("report_generate", detail=f"type={report_type} files={len(filepaths)}")
        return jsonify({
            "ok": True,
            "download_url": url_for('api_reports_download', file=rel_name),
            "filename": rel_name,
            "file_count": len(filepaths),
        })

    @app.route('/api/reports/list')
    @_login_required
    def api_reports_list():
        """[생성된 리포트 목록] 리포트 생성 직후에만 다운로드 링크가 보이고 그
        화면을 벗어나면(탭을 닫거나 새로고침) 링크를 잃어버리던 문제 - reports/
        폴더를 직접 훑어서 이미 만들어진 파일들도 다시 다운로드할 수 있게 한다."""
        out_dir = get_report_output_dir()
        entries = []
        try:
            if os.path.isdir(out_dir):
                for name in os.listdir(out_dir):
                    if not name.lower().endswith(('.pdf', '.xlsx', '.zip', '.txt')):
                        continue
                    path = os.path.join(out_dir, name)
                    if not os.path.isfile(path):
                        continue
                    stat = os.stat(path)
                    entries.append({
                        "filename": name,
                        "size_bytes": stat.st_size,
                        "modified_at": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        "download_url": url_for('api_reports_download', file=name),
                    })
        except OSError as e:
            AppLogger.log_error("[Web Dashboard] Report list failed", e)
            return jsonify({"error": str(e)}), 500
        entries.sort(key=lambda e: e['modified_at'], reverse=True)
        return jsonify(entries)

    @app.route('/api/reports/download')
    @_login_required
    def api_reports_download():
        filename = request.args.get('file', '')
        target = _safe_report_path(filename)
        if not target or not os.path.isfile(target):
            return jsonify({"error": "파일을 찾을 수 없습니다."}), 404
        return send_file(target, as_attachment=True, download_name=os.path.basename(target))

    # ------------------------------------------------------------------
    # 설정 (2026-09 확장) - gui/settings_dialog.py 중 웹에서도 안전하게 다룰 수
    # 있는 부분만 옮겼다: 로그/이력 보관, 테마, 리포트 출력 경로, 호스트 키,
    # 라이선스, 웹 대시보드 계정. "기본 계정/자격증명"(keyring 저장)과
    # "룰셋/전문가 프로필"은 Expert Mode와 함께 데스크톱 전용으로 남겨뒀다.
    # ------------------------------------------------------------------
    @app.route('/settings')
    @_admin_required
    def settings_page():
        return send_from_directory(_WEB_DIR, 'settings.html')

    @app.route('/settings.js')
    @_admin_required
    def settings_js():
        return send_from_directory(_WEB_DIR, 'settings.js')

    @app.route('/api/settings')
    @_admin_required
    def api_settings_get():
        app_settings = load_settings()
        license_mgr = _build_license_manager()
        from core.ssh_inspector import SSHInspector
        known_hosts = [{"hostname": h, "key_types": kt} for h, kt in SSHInspector.list_known_hosts()]
        return jsonify({
            "log_retention_days": app_settings.get("log_retention_days", 90),
            "theme": app_settings.get("theme", "light"),
            "report_output_dir": app_settings.get("report_output_dir", ""),
            "report_output_dir_effective": get_report_output_dir(),
            "license": {
                "tier": license_mgr.effective_tier(),
                "expiry_date": license_mgr.expiry_date,
                "can_export_excel": license_mgr.can_export_excel(),
            },
            "known_hosts": known_hosts,
        })

    @app.route('/api/settings/general', methods=['POST'])
    @_admin_required
    def api_settings_general():
        data = request.get_json(silent=True) or {}
        settings = load_settings()

        if 'log_retention_days' in data:
            try:
                settings['log_retention_days'] = int(data['log_retention_days'])
            except (TypeError, ValueError):
                return jsonify({"error": "보관 기간은 숫자여야 합니다."}), 400
        if 'theme' in data and data['theme'] in ('light', 'dark'):
            settings['theme'] = data['theme']
        if 'report_output_dir' in data:
            settings['report_output_dir'] = (data['report_output_dir'] or '').strip()

        if not save_settings(settings):
            return jsonify({"error": "설정 저장에 실패했습니다."}), 500

        try:
            set_theme(settings.get('theme', 'light'))
        except Exception:
            pass
        _audit("settings_update", detail=f"retention={settings.get('log_retention_days')} theme={settings.get('theme')}")
        return jsonify({"ok": True})

    @app.route('/api/settings/purge-history', methods=['POST'])
    @_admin_required
    def api_settings_purge_history():
        data = request.get_json(silent=True) or {}
        try:
            days = int(data.get('days'))
        except (TypeError, ValueError):
            return jsonify({"error": "days는 숫자여야 합니다."}), 400
        deleted = db.purge_old_results(days)
        if deleted < 0:
            return jsonify({"error": "정리에 실패했습니다."}), 500
        _audit("purge_history", detail=f"days={days} deleted={deleted}")
        return jsonify({"ok": True, "deleted": deleted})

    @app.route('/api/settings/known-hosts/<hostname>', methods=['DELETE'])
    @_admin_required
    def api_settings_known_host_delete(hostname):
        from core.ssh_inspector import SSHInspector
        if not SSHInspector.remove_known_host(hostname):
            return jsonify({"error": "삭제에 실패했습니다(존재하지 않을 수 있습니다)."}), 400
        _audit("known_host_remove", detail=hostname)
        return jsonify({"ok": True})

    @app.route('/api/settings/known-hosts', methods=['DELETE'])
    @_admin_required
    def api_settings_known_hosts_clear():
        from core.ssh_inspector import SSHInspector
        if not SSHInspector.clear_known_hosts():
            return jsonify({"error": "초기화에 실패했습니다."}), 500
        _audit("known_hosts_clear")
        return jsonify({"ok": True})

    @app.route('/api/settings/license/activate', methods=['POST'])
    @_admin_required
    def api_settings_license_activate():
        data = request.get_json(silent=True) or {}
        key = (data.get('key') or '').strip()
        is_valid, tier, expiry_date = LicenseValidator.validate_key(key)
        if not is_valid:
            return jsonify({"error": "유효하지 않거나 만료된 라이선스 키입니다."}), 400
        if not LicenseValidator.save_license(key):
            return jsonify({"error": "라이선스 파일을 저장할 수 없습니다."}), 500
        # [민감정보] 키 원문은 감사로그에도 남기지 않는다 - 등급/만료일만 기록.
        _audit("license_activate", detail=f"tier={tier} expiry={expiry_date}")
        return jsonify({"ok": True, "tier": tier, "expiry_date": expiry_date})

    @app.route('/api/settings/license', methods=['DELETE'])
    @_admin_required
    def api_settings_license_delete():
        try:
            if os.path.exists(LicenseValidator.LICENSE_FILE):
                os.remove(LicenseValidator.LICENSE_FILE)
        except OSError as e:
            AppLogger.log_error("[Web Dashboard] License delete failed", e)
            return jsonify({"error": "라이선스 파일 삭제에 실패했습니다."}), 500
        _audit("license_delete")
        return jsonify({"ok": True})

    # ------------------------------------------------------------------
    # 계정 관리 (웹 대시보드 로그인 계정 전용 탭, 2026-09 분리, 이후 역할 분리
    # 추가) - 계정 생성/삭제와 역할(admin/operator/viewer) 배정은 admin만
    # 할 수 있다. 본인 계정은 스스로 삭제할 수 없게 막아 "관리자 전원이 실수로
    # 잠기는" 상황을 방지하고(세션 인지 가드), dashboard_accounts.delete_account()가
    # 별도로 "마지막 admin은 삭제 불가"까지 강제한다 - 두 가드가 겹치는 게 아니라
    # 서로 다른 잠금 시나리오(본인 실수 / 마지막 관리자 소실)를 막는다.
    # ------------------------------------------------------------------
    @app.route('/accounts')
    @_admin_required
    def accounts_page():
        return send_from_directory(_WEB_DIR, 'accounts.html')

    @app.route('/accounts.js')
    @_admin_required
    def accounts_js():
        return send_from_directory(_WEB_DIR, 'accounts.js')

    @app.route('/api/accounts')
    @_admin_required
    def api_accounts_list():
        accounts = [{"username": a["username"], "role": a["role"], "created_at": a.get("created_at", "-")}
                    for a in dashboard_accounts.load_accounts()]
        return jsonify({
            "accounts": accounts,
            "current_user": _current_identity()['username'],
            "roles": [{"value": r, "label": dashboard_accounts.ROLE_LABELS[r]} for r in dashboard_accounts.ROLES],
        })

    @app.route('/api/accounts', methods=['POST'])
    @_admin_required
    def api_accounts_create():
        data = request.get_json(silent=True) or {}
        role = data.get('role', dashboard_accounts.DEFAULT_ROLE)
        if role not in dashboard_accounts.ROLES:
            return jsonify({"error": "알 수 없는 역할입니다."}), 400
        username = data.get('username', '')
        ok, error = dashboard_accounts.create_account(username, data.get('password', ''), role=role)
        if not ok:
            return jsonify({"error": error}), 400
        _audit("account_create", detail=f"username={username.strip()} role={role}")
        return jsonify({"ok": True})

    @app.route('/api/accounts/<username>', methods=['DELETE'])
    @_admin_required
    def api_accounts_delete(username):
        if username.strip().lower() == _current_identity()['username'].strip().lower():
            return jsonify({"error": "로그인 중인 본인 계정은 삭제할 수 없습니다. 다른 관리자 계정으로 삭제하세요."}), 400
        ok, error = dashboard_accounts.delete_account(username)
        if not ok:
            return jsonify({"error": error}), 400
        revoked = _sessions.remove_user(username)
        _audit("account_delete", detail=f"username={username} sessions_revoked={revoked}")
        return jsonify({"ok": True})

    @app.route('/api/audit-log')
    @_admin_required
    def api_audit_log():
        try:
            limit = int(request.args.get('limit', 200))
        except (TypeError, ValueError):
            limit = 200
        return jsonify(web_audit_log.read_recent(limit=min(limit, 1000)))

    # ------------------------------------------------------------------
    # 도움말 - gui/help_dialog.py의 카테고리 순서/HTML 변환 로직(■/★/· 서식,
    # 표 정렬 보존)과 gui/help_texts.py의 원문을 그대로 재사용한다. 내용을
    # 다시 쓰거나 요약하지 않는다 - 데스크톱과 완전히 같은 설명을 그대로 보여준다.
    # ------------------------------------------------------------------
    @app.route('/help')
    @_login_required
    def help_page():
        return send_from_directory(_WEB_DIR, 'help.html')

    @app.route('/help.js')
    @_login_required
    def help_js():
        return send_from_directory(_WEB_DIR, 'help.js')

    @app.route('/api/help')
    @_login_required
    def api_help():
        categories = []
        for key, _ in HELP_CATEGORY_ORDER:
            entry = HELP_TEXTS[key]
            categories.append({
                "key": key,
                "title": entry["title"],
                "detail_html": format_help_html(entry["detail"]),
            })
        return jsonify(categories)

    # ------------------------------------------------------------------
    # 실시간 스캔 스트림(SSE) / 전 페이지 공용 요약 - scan.js는 1초 폴링 대신 이
    # 스트림을 쓰고(실패 시 폴링 폴백), topbar.js는 가벼운 요약을 주기적으로 받아
    # 탭 제목/파비콘 진행률과 완료 알림을 모든 페이지에서 처리한다.
    # ------------------------------------------------------------------
    @app.route('/api/scan/stream')
    @_login_required
    def api_scan_stream():
        try:
            start_index = int(request.args.get('since', 0))
        except (TypeError, ValueError):
            start_index = 0
        sid = _current_identity().get('sid')

        def generate():
            idx = start_index
            last_sig = None
            ticks = 0
            while not (shutdown_event is not None and shutdown_event.is_set()):
                # 스트림이 열려있는 동안 관리자가 세션을 강제로 끊으면 바로 종료한다.
                if sid and ticks % 10 == 0 and _sessions.touch(sid) is None:
                    return
                state, lines, total = job_manager.snapshot(idx)
                if total < idx:  # 새 스캔이 시작돼 로그가 초기화됨
                    idx = 0
                    continue
                sig = json.dumps(state, sort_keys=True)
                if lines or sig != last_sig:
                    idx = total
                    last_sig = sig
                    yield "data: " + json.dumps({"state": state, "log_lines": lines, "log_total": total}, ensure_ascii=False) + "\n\n"
                elif ticks % 50 == 0:
                    yield ": keepalive\n\n"
                ticks += 1
                time.sleep(0.3)

        return Response(generate(), mimetype='text/event-stream',
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route('/api/scan/summary')
    @_login_required
    def api_scan_summary():
        state, _, _ = job_manager.snapshot(10 ** 9)
        if _current_identity()['via'] == 'session':
            heartbeat.touch()
        return jsonify({k: state[k] for k in ("running", "percent", "current", "total", "target", "mode", "finished_reason")})

    # ------------------------------------------------------------------
    # 원본 findings CSV 내보내기 - 정식 리포트(PDF/Excel)와 별개로 스프레드시트에서
    # 바로 피벗해보는 용도. Excel이 수식으로 해석하는 셀(=,+,-,@ 시작)은 앞에 '를 붙여
    # CSV 인젝션을 막는다(리포트 생성기들이 이미 하는 방어와 같은 취지).
    # ------------------------------------------------------------------
    def _csv_safe(value):
        text = '' if value is None else str(value)
        return ("'" + text) if text[:1] in ('=', '+', '-', '@', '\t', '\r') else text

    @app.route('/api/export/findings.csv')
    @_login_required
    def api_export_findings_csv():
        try:
            findings = db.get_latest_findings()
        except Exception as e:
            AppLogger.log_error("[Web Dashboard] CSV export failed", e)
            return jsonify({"error": str(e)}), 500
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["IP", "호스트명", "OS", "코드", "항목명", "카테고리", "중요도", "상태", "위험도"])
        for f in findings:
            writer.writerow([_csv_safe(f.get(k)) for k in
                             ("ip", "hostname", "os_type", "code", "name", "category", "importance", "status", "risk")])
        _audit("export_findings_csv", detail=f"rows={len(findings)}")
        filename = f"Z-VulnScan_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return Response("﻿" + buf.getvalue(), mimetype='text/csv; charset=utf-8',
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    # ------------------------------------------------------------------
    # 회차 비교(Diff) - db_connector.get_round_comparison()(자산별 직전 회차 대비
    # 점수 변화, 예전 ROADMAP Phase 5 항목)은 DB 계층에 이미 있었는데 화면이 없었다.
    # ------------------------------------------------------------------
    @app.route('/compare')
    @_login_required
    def compare_page():
        return send_from_directory(_WEB_DIR, 'compare.html')

    @app.route('/compare.js')
    @_login_required
    def compare_js():
        return send_from_directory(_WEB_DIR, 'compare.js')

    @app.route('/api/compare')
    @_login_required
    def api_compare():
        return jsonify(db.get_round_comparison())

    @app.route('/api/compare/<int:asset_id>')
    @_login_required
    def api_compare_detail(asset_id):
        return jsonify(db.get_code_changes_for_asset(asset_id))

    # ------------------------------------------------------------------
    # API 토큰 관리 - 발급/폐기는 브라우저 세션에서만(토큰으로 토큰을 만들 수 없음).
    # 일반 사용자는 본인 토큰만, 관리자는 전체를 보고 폐기할 수 있다.
    # ------------------------------------------------------------------
    @app.route('/api/tokens')
    @_login_required
    def api_tokens_list():
        blocked = _session_only()
        if blocked:
            return blocked
        ident = _current_identity()
        owner = None if ident['role'] == 'admin' else ident['username']
        allowed_roles = [r for r in ("viewer", "operator")
                         if dashboard_accounts.ROLE_RANK[r] <= dashboard_accounts.ROLE_RANK[ident['role']]]
        return jsonify({
            "tokens": dashboard_accounts.list_api_tokens(owner),
            "current_user": ident['username'],
            "allowed_roles": [{"value": r, "label": dashboard_accounts.ROLE_LABELS[r]} for r in allowed_roles],
        })

    @app.route('/api/tokens', methods=['POST'])
    @_login_required
    def api_tokens_create():
        blocked = _session_only()
        if blocked:
            return blocked
        data = request.get_json(silent=True) or {}
        ident = _current_identity()
        ok, error, plaintext, meta = dashboard_accounts.create_api_token(
            ident['username'], data.get('name', ''), data.get('role', 'viewer'))
        if not ok:
            return jsonify({"error": error}), 400
        _audit("api_token_create", detail=f"name={meta['name']} role={meta['role']} id={meta['id']}")
        return jsonify({"ok": True, "token": plaintext, "meta": meta})

    @app.route('/api/tokens/<token_id>', methods=['DELETE'])
    @_login_required
    def api_tokens_revoke(token_id):
        blocked = _session_only()
        if blocked:
            return blocked
        ident = _current_identity()
        ok, error = dashboard_accounts.revoke_api_token(token_id, ident['username'], is_admin=(ident['role'] == 'admin'))
        if not ok:
            return jsonify({"error": error}), 400
        _audit("api_token_revoke", detail=f"id={token_id}")
        return jsonify({"ok": True})

    # ------------------------------------------------------------------
    # 세션 관리(관리자) - 접속 중인 브라우저 세션 목록과 강제 로그아웃.
    # ------------------------------------------------------------------
    @app.route('/api/sessions')
    @_admin_required
    def api_sessions_list():
        current_sid = _current_identity().get('sid')
        rows = []
        for r in sorted(_sessions.list(), key=lambda r: r["last_seen"], reverse=True):
            rows.append({
                "public_id": r["public_id"], "username": r["username"], "role": r["role"],
                "ip": r["ip"], "user_agent": r["user_agent"],
                "login_at": r["login_at"].strftime('%Y-%m-%d %H:%M:%S'),
                "last_seen": r["last_seen"].strftime('%Y-%m-%d %H:%M:%S'),
                "is_current": r["sid"] == current_sid,
            })
        return jsonify(rows)

    @app.route('/api/sessions/<public_id>', methods=['DELETE'])
    @_admin_required
    def api_sessions_revoke(public_id):
        current_sid = _current_identity().get('sid')
        for r in _sessions.list():
            if r["public_id"] == public_id and r["sid"] == current_sid:
                return jsonify({"error": "현재 사용 중인 세션은 여기서 끊을 수 없습니다. 로그아웃을 사용하세요."}), 400
        username = _sessions.remove_by_public_id(public_id)
        if username is None:
            return jsonify({"error": "세션을 찾을 수 없습니다(이미 종료됐을 수 있습니다)."}), 404
        _audit("session_revoke", detail=f"user={username}")
        return jsonify({"ok": True})

    # ------------------------------------------------------------------
    # PWA - 인증 없이 받아야 브라우저가 설치 가능 여부를 판단한다(로그인 페이지에서도
    # manifest를 참조). 서비스 워커는 캐시를 전혀 하지 않는 no-op이라(설치 가능 조건만
    # 만족) 화면/데이터가 오래된 버전으로 남을 위험이 없다.
    # ------------------------------------------------------------------
    @app.route('/manifest.webmanifest')
    def pwa_manifest():
        return send_from_directory(_WEB_DIR, 'manifest.webmanifest', mimetype='application/manifest+json')

    @app.route('/icon.svg')
    def pwa_icon():
        return send_from_directory(_WEB_DIR, 'icon.svg', mimetype='image/svg+xml')

    @app.route('/sw.js')
    def pwa_service_worker():
        resp = send_from_directory(_WEB_DIR, 'sw.js', mimetype='application/javascript')
        resp.headers['Service-Worker-Allowed'] = '/'
        resp.headers['Cache-Control'] = 'no-cache'
        return resp

    return app


class DashboardServerThread(threading.Thread):
    """werkzeug의 make_server를 직접 써서 Flask 기본 개발 서버(run())로는 깔끔하게
    안 되는 종료(shutdown())를 지원한다 - 웹 대시보드 상태 창을 닫을 때 이 스레드를
    멈추고 main.py의 기존 aboutToQuit 훅(DB 재암호화)으로 자연스럽게 이어지게 하기
    위함."""

    def __init__(self, app, host='127.0.0.1', port=8642):
        super().__init__(daemon=True)
        self._srv = make_server(host, port, app, threaded=True)
        self.host = host
        self.port = self._srv.server_port

    def run(self):
        self._srv.serve_forever()

    def stop(self):
        self._srv.shutdown()


def start_server(db, host='127.0.0.1', port=8642, shutdown_event=None):
    """[웹 대시보드가 꺼지면 서버도 같이 종료] shutdown_event는 main.py가 만들어서
    넘겨준다(메인 스레드 QTimer가 이 이벤트를 감시). 여기서는 그와 별개로
    HeartbeatTracker/HeartbeatWatchdog을 붙여서, 브라우저 쪽에서 하트비트가
    끊기면(탭/브라우저를 닫음) 동일한 shutdown_event를 자동으로 set()하게 한다 -
    "서버 종료" 버튼을 수동으로 누르는 경로와 브라우저가 그냥 닫히는 경로 둘 다
    결국 같은 종료 절차로 합류한다."""
    if shutdown_event is None:
        shutdown_event = threading.Event()
    heartbeat = HeartbeatTracker()
    app = create_app(db, shutdown_event=shutdown_event, heartbeat=heartbeat)
    thread = DashboardServerThread(app, host=host, port=port)
    thread.start()
    watchdog = HeartbeatWatchdog(heartbeat, shutdown_event)
    watchdog.start()
    return thread
