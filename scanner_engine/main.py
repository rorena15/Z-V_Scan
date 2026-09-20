# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import sys

# [2026-09 부팅 속도 개선] pyi_splash는 --splash로 빌드된 프로즌 실행 파일 안에서만
# 존재하는 모듈이라(개발 환경에서는 항상 ImportError) 가장 먼저 시도한다 - 아래에서
# 실제로 제일 무거운 import(PySide6, 특히 QtWebEngine을 끌고 오는 gui.main_window)가
# 진행되는 동안 스플래시 문구를 실시간으로 갱신하려면, 그 import들보다 먼저
# pyi_splash가 준비돼 있어야 한다.
#
# [2026-09-02] 상태 문구는 한글이 아니라 영어로 쓴다 - 실제로 빌드해 테스트해보니
# PyInstaller 6.21의 스플래시 텍스트 기능(pyi_splash.update_text) 자체에 버그가
# 있어서 부트로더가 텍스트를 Tcl 명령으로 잘못 넘기는 경로가 있다: (1) 대괄호 `[` `]`가
# 들어가면 Tcl이 명령 치환 문법으로 오인해 "invalid command name" 오류가 나고,
# (2) 대괄호를 빼도 한글 등 비-ASCII 문자가 하나라도 있으면 같은 오류가 난다(순수
# ASCII만 안전 - "[Loading]" 실패, "(Loading)" 정상, 블록 문자 "████" 단독도 실패).
# 그래서 대괄호 대신 괄호, 블록 문자 대신 ASCII #/.을 쓰고 라벨도 영어로 쓴다 - 이
# 정확한 형식을 실제로 빌드+실행해서 Tcl 오류 없이 정상 동작하는 것까지 확인했다.
try:
    import pyi_splash
except ImportError:
    pyi_splash = None


def _splash_bar(pct, label, width=20):
    """onefile 부팅 스플래시(ci/build_final_v3.ps1의 --splash, assets/splash.png)에
    표시되는 진행바 텍스트를 만든다. 이미지 자체는 정적이라 다시 그릴 수 없고,
    Splash(text_pos=...)로 지정해 둔 위치에 텍스트 한 줄만 갱신할 수 있다(pyi_splash.
    update_text) - 그래서 진행률을 ASCII 문자로 표현한 바 모양의 텍스트로 만든다.
    괄호는 반드시 대괄호가 아니라 소괄호를 쓰고, 라벨도 반드시 영어(ASCII)만 써야
    한다 - 둘 다 실제 빌드에서 재현된 PyInstaller 스플래시 버그를 피하기 위함이다.
    퍼센트 값은 고정된 애니메이션이 아니라 실제 부팅 단계(무거운 import, DB 복호화,
    메인 창 준비)에 맞춰 호출되므로 실제 진행 상황을 반영한다.
    """
    filled = int(width * pct / 100)
    return f"({'#' * filled}{'.' * (width - filled)})  {pct:3d}%  {label}"


def _splash_update(pct, label):
    if pyi_splash:
        pyi_splash.update_text(_splash_bar(pct, label))


_splash_update(5, "Loading modules...")

import argparse
import os
import ctypes
import multiprocessing
import threading
import traceback
from datetime import datetime
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox
from PySide6.QtGui import QIcon

_splash_update(35, "Loading UI components...")

# 분리된 UI 및 다이얼로그 import - QtWebEngine을 끌고 오는 gui.main_window가 onefile
# 부팅 과정에서 가장 시간이 오래 걸리는 부분이라, 이 import 전후로 스플래시 문구를
# 갱신해서 "여기서 멈춘 게 아니라 실제로 로딩 중"이라는 걸 보여준다.
# [부팅 속도] gui.main_window(~0.6초)는 데스크톱 모드에서만 필요해서 사용처(아래 두 곳)에서
# import한다 - 웹 모드는 이걸 아예 안 불러오므로 모드 선택 창이 더 빨리 뜬다.
from gui.dialogs import LegalDisclaimerDialog, LaunchModeDialog, DashboardAccountSetupDialog
from utils.logger import AppLogger
from utils import db_crypto, dashboard_accounts

_splash_update(70, "Initializing engine...")

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# 전역 예외 처리
def my_exception_hook(exctype, value, tb):
    # 1. 에러 메시지 스택 트레이스 생성
    error_msg = "".join(traceback.format_exception(exctype, value, tb))
    
    # 2. 콘솔 출력 (개발자 확인용)
    print(f"[CRITICAL] Uncaught Exception:\n{error_msg}")
    
    # 3. 로그 파일 기록
    try:
        AppLogger.log_critical(f" PROGRAM CRASHED \n{error_msg}")
    except:
        print("[!] Failed to write to AppLogger inside exception hook.")

sys.excepthook = my_exception_hook


def _run_selftest(out_path=""):
    """[빌드 검증] `exe --selftest [--selftest-out 파일]` - GUI/DB/라이선스 창 없이 "이 빌드가 실제로
    동작 가능한 상태인가"만 확인하고 종료 코드(0=정상)로 알린다. CI가 빌드 직후 이걸 돌려서, 소스에서는 잘
    돌던 코드가 패키징(Cython/PyArmor/PyInstaller) 과정에서 깨진 경우(모듈 누락, Flask 등 hidden import
    누락, rules/웹 정적 파일 미포함)를 릴리즈 전에 잡는다. exe는 콘솔이 없어 stdout을 못 보므로 결과를
    --selftest-out 파일에도 쓴다."""
    import importlib
    import json as _json
    lines, failures = [], []

    def check(name, fn):
        try:
            detail = fn()
            lines.append(f"[OK]   {name}" + (f" - {detail}" if detail else ""))
        except Exception as e:  # noqa: BLE001 - 어떤 실패든 항목으로 기록하고 계속 진행
            failures.append(name)
            lines.append(f"[FAIL] {name} - {type(e).__name__}: {e}")

    # 1) 핵심 모듈 import (Cython .pyd / PyArmor / 서드파티 hidden import 누락 검출)
    for mod in ("core.worker", "core.ssh_inspector", "core.windows_inspector", "core.database_inspector",
                "core.crosscheck_engine", "utils.rule_judge", "utils.rule_crypto", "utils.db_connector",
                "utils.dashboard_accounts", "utils.web_audit_log", "output.pdf_report", "output.excel_report",
                "output.text_report", "web_dashboard_server", "gui.main_window",
                "flask", "werkzeug", "jinja2", "bcrypt", "keyring", "paramiko", "winrm", "openpyxl", "reportlab"):
        check(f"import {mod}", lambda mod=mod: importlib.import_module(mod) and None)

    # 1.5) 배포 빌드에 개발 전용 더미 비밀값이 남아 있지 않은지(ci/inject_release_secrets.py 누락 검출).
    # 소스 실행(개발/테스트)에서는 더미가 정상이라 배포 exe(frozen)에서만 확인한다.
    def release_secrets():
        if not getattr(sys, "frozen", False):
            return "소스 실행 - 건너뜀"
        from core.config import AppConfig
        for name in ("LICENSE_SALT", "RULE_ENCRYPTION_KEY", "ENGINE_ACCESS_TOKEN"):
            if str(getattr(AppConfig, name)).upper().startswith("DEV-ONLY") or name == "RULE_ENCRYPTION_KEY" and                     getattr(AppConfig, name) == "Rche7xHFE4fLTYEKw6jA3woId6pk-w0P58lguf1ruPY=":
                raise ValueError(f"{name}이(가) 개발용 더미 값 - 릴리즈 비밀값 주입 누락")
        return "배포용 비밀값 사용 중"
    check("릴리즈 비밀값 주입 확인", release_secrets)

    # 2) 룰셋 로드(배포판은 암호화된 .enc) + 판정 엔진 동작
    def rules():
        from utils import rule_crypto
        total = 0
        for filename in rule_crypto.RULE_FILES:
            path = rule_crypto.resolve_rules_path(filename)
            data = rule_crypto.load_ruleset(path)
            if not isinstance(data, list) or not data:
                raise ValueError(f"{filename}: 비어있거나 형식 오류")
            total += len(data)
        return f"{len(rule_crypto.RULE_FILES)}개 룰셋 / {total}개 룰"
    check("룰셋 로드(복호화 포함)", rules)

    def judge():
        from utils.rule_judge import judge_rule
        st, _ = judge_rule(
            {"code": "T", "criteria": [{"label": "a", "command": "1", "safe_keyword": "OK"},
                                       {"label": "b", "command": "2", "safe_keyword": "OK"}]},
            "x", execute_fn=lambda c: "OK" if c == "1" else "FAIL")
        if st != "PARTIAL":
            raise AssertionError(f"기대 PARTIAL, 실제 {st}")
    check("판정 엔진(부분만족 판정)", judge)

    # 3) 웹 대시보드: 정적 파일 포함 여부 + Flask 앱이 실제로 응답하는지(임시 계정/설정 폴더 사용)
    def web():
        import tempfile
        import web_dashboard_server as wds
        need = ["dashboard.html", "dashboard.js", "topbar.js", "scan.html", "scan.js", "assets.html", "assets.js",
                "compare.html", "compare.js", "help.html", "help.js", "account.html", "account.js",
                "accounts.html", "accounts.js", "settings.html", "settings.js", "manifest.webmanifest",
                "icon.svg", "sw.js", "vendor/chart.umd.min.js"]
        import os as _os
        missing = [f for f in need if not _os.path.exists(_os.path.join(wds._WEB_DIR, f))]
        if missing:
            raise FileNotFoundError("웹 정적 파일 누락: " + ", ".join(missing))

        class _Db:
            pass
        client = wds.create_app(_Db()).test_client()
        for path in ("/login", "/manifest.webmanifest", "/icon.svg", "/sw.js"):
            code = client.get(path).status_code
            if code != 200:
                raise AssertionError(f"GET {path} -> {code}")
        return f"정적 파일 {len(need)}개 존재, Flask 응답 정상"
    check("웹 대시보드(정적 파일 + Flask)", web)

    ok = not failures
    lines.append("SELFTEST OK" if ok else f"SELFTEST FAILED ({len(failures)}): " + ", ".join(failures))
    text = "\n".join(lines)
    print(text)
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError:
            pass
    return 0 if ok else 1



def _preload_engine_modules():
    """[부팅 속도] 창/서버를 먼저 띄우고, 스캔 엔진·리포트 모듈(paramiko/openpyxl/reportlab 등,
    합쳐서 ~1초)은 백그라운드 스레드로 미리 로드한다. 사용자가 그 사이에 스캔/리포트를 누르면
    해당 import가 파이썬 import 락에서 로딩 완료를 기다릴 뿐이라 안전하다."""
    def _load():
        try:
            import core.worker, core.ssh_inspector, output.pdf_report, output.excel_report, output.text_report  # noqa: F401
        except Exception as e:
            AppLogger.log_error("[Startup] Engine preload failed (will import lazily on use)", e)
    threading.Thread(target=_load, daemon=True, name="engine-preload").start()


def _start_web_dashboard(app, icon_path):
    """[웹 대시보드 모드] LaunchModeDialog에서 '웹'을 골랐을 때만 호출된다.
    DB 복호화/재암호화는 이 함수 밖(__main__ 블록의 ensure_decrypted/aboutToQuit)에서
    이미 처리되므로 여기서는 서버만 다룬다.

    [창 없이 백그라운드로] 처음엔 "웹 대시보드가 실행 중입니다" 상태 창을 하나
    띄워뒀는데(닫으면 종료), 데스크톱에 아무 창도 안 뜨길 원한다는 피드백으로
    없앴다 - 종료는 웹 페이지 자체의 "서버 종료" 버튼(POST /api/server/shutdown)이
    담당한다. Flask는 별도 스레드에서 돌기 때문에 그 버튼이 직접 app.quit()을
    부르지 않고, 대신 스레드 안전한 threading.Event만 set()하고, 메인 스레드에서
    도는 QTimer가 300ms마다 그 이벤트를 확인해서 자기 스레드(메인 스레드)에서
    app.quit()을 부른다 - Qt 객체는 자기 자신을 만든 스레드에서만 조작하는 게
    안전하므로, 다른 스레드가 직접 quit()을 부르는 것보다 이 방식이 안전하다."""
    from utils.db_connector import DBConnector
    from web_dashboard_server import start_server

    if not dashboard_accounts.has_any_account():
        setup = DashboardAccountSetupDialog(allow_cancel=True)
        setup.setWindowIcon(QIcon(icon_path))
        if setup.exec() != QDialog.Accepted:
            sys.exit()

    shutdown_event = threading.Event()
    try:
        db = DBConnector()
        server_thread = start_server(db, host='127.0.0.1', port=8642, shutdown_event=shutdown_event)
    except OSError as e:
        QMessageBox.critical(
            None, "웹 대시보드 시작 실패",
            f"로컬 서버를 시작할 수 없습니다 (포트가 이미 사용 중일 수 있습니다).\n\n{e}"
        )
        sys.exit()

    url = f"http://127.0.0.1:{server_thread.port}"

    _preload_engine_modules()

    import webbrowser
    webbrowser.open(url)

    shutdown_timer = QTimer()
    shutdown_timer.setInterval(300)

    def _check_shutdown():
        if shutdown_event.is_set():
            shutdown_timer.stop()
            app.quit()

    shutdown_timer.timeout.connect(_check_shutdown)
    shutdown_timer.start()

    app.aboutToQuit.connect(server_thread.stop)

    sys.exit(app.exec())


if __name__ == '__main__':
    # 1. 로거 및 멀티프로세싱 초기화
    AppLogger.setup()
    multiprocessing.freeze_support()
    # --- [추가] CLI 인자 파싱 (자동 스캔 연동 모드) ---
    parser = argparse.ArgumentParser(description="Z-VulnScan Professional")
    parser.add_argument("--target", type=str, help="자동으로 스캔할 대상 IP", default=None)
    parser.add_argument("--selftest", action="store_true", help="빌드 검증용 자가진단 후 종료(창 없음)")
    parser.add_argument("--selftest-out", type=str, default="", help="자가진단 결과를 저장할 파일")
    args, unknown = parser.parse_known_args()
    if args.selftest:
        if pyi_splash:
            pyi_splash.close()
        sys.exit(_run_selftest(args.selftest_out))
    # -----------------------------------------------
    # 작업표시줄 아이콘 분리
    myappid = 'z_vuln_scan.pro.v3.0' 
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except Exception:
        pass

    app = QApplication(sys.argv)

    icon_path = resource_path("app_icon.ico")
    app.setWindowIcon(QIcon(icon_path))

    _splash_update(80, "Checking database...")

    # [DB 암호화] 시작 시 이전 세션에서 암호화해 둔 zvuln_scan.db.enc가 있으면
    # 복호화해서 평문 작업 파일을 만든다. 정상 종료 시에는 아래 aboutToQuit에서
    # 다시 암호화한다 - DBConnector 등 기존 코드는 그 사이엔 평문 파일을 그대로 쓰므로
    # 변경할 필요가 없다.
    _db_plain_path = db_crypto.get_default_db_path()
    _db_key_is_new = db_crypto.ensure_decrypted(_db_plain_path)
    app.aboutToQuit.connect(lambda: db_crypto.encrypt_on_exit(_db_plain_path))

    if _db_key_is_new:
        QMessageBox.information(
            None, "DB 암호화 키 생성됨",
            "스캔 결과 DB(zvuln_scan.db)를 프로그램 종료 시 자동으로 암호화하도록\n"
            "암호화 키를 새로 생성했습니다.\n\n"
            f"복구용 키 백업 파일이 여기 저장되었습니다:\n{db_crypto.get_recovery_backup_path()}\n\n"
            "이 키를 잃어버리면(OS 재설치 등) 암호화된 DB를 복구할 방법이 없으니,\n"
            "위 파일을 USB 등 안전한 곳에 반드시 별도로 백업해두세요."
        )

    if args.target:
        # [연동 모드] 미들웨어가 호출했을 때: 법적 고지 패스하고 바로 스캔 돌입
        _splash_update(97, "Starting main window...")
        from gui.main_window import ScannerApp
        scanner = ScannerApp()
        scanner.show()
        if pyi_splash:
            pyi_splash.close()

        # 1. IP 입력란에 미들웨어가 넘겨준 타겟 IP 자동 입력
        scanner.ip_input.setText(args.target)

        # 2. 창이 뜨고 1초(1000ms) 뒤에 취약점 진단 함수(start_audit) 자동 실행
        QTimer.singleShot(1000, scanner.start_audit)

        sys.exit(app.exec())

    else:
        # [일반 모드] 사용자가 더블클릭해서 실행했을 때: 기존 로직 그대로 유지
        # 법적 고지 다이얼로그도 이미 "실제 화면"이므로, 그게 뜨기 직전에 스플래시를
        # 닫아 자연스럽게 이어지게 한다(스플래시가 닫히고 빈 화면이 잠깐 보이는 것보다,
        # 스플래시 -> 고지 다이얼로그 -> 메인 창으로 바로 이어지는 게 더 매끄럽다).
        _splash_update(97, "Starting main window...")
        disclaimer = LegalDisclaimerDialog()
        disclaimer.setWindowIcon(QIcon(icon_path))
        if pyi_splash:
            pyi_splash.close()

        if disclaimer.exec() == QDialog.Accepted:
            # [웹 대시보드 모드] 시작 모드는 매번 새로 묻는다(선택 기억 안 함,
            # 사용자 지시) - 여기서 고른 값에 따라 데스크톱 앱 또는 로컬 전용
            # 웹 대시보드 서버 중 하나로만 진입한다. 둘을 동시에 띄우지 않는다.
            mode_dialog = LaunchModeDialog()
            mode_dialog.setWindowIcon(QIcon(icon_path))
            if mode_dialog.exec() != QDialog.Accepted:
                sys.exit()

            if mode_dialog.chosen_mode == 'web':
                _start_web_dashboard(app, icon_path)
            else:
                from gui.main_window import ScannerApp
                scanner = ScannerApp()
                scanner.show()
                _preload_engine_modules()
                sys.exit(app.exec())
        else:
            sys.exit()