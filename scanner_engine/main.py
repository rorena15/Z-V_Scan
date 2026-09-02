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
import traceback
from datetime import datetime
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox
from PySide6.QtGui import QIcon

_splash_update(35, "Loading UI components...")

# 분리된 UI 및 다이얼로그 import - QtWebEngine을 끌고 오는 gui.main_window가 onefile
# 부팅 과정에서 가장 시간이 오래 걸리는 부분이라, 이 import 전후로 스플래시 문구를
# 갱신해서 "여기서 멈춘 게 아니라 실제로 로딩 중"이라는 걸 보여준다.
from gui.main_window import ScannerApp
from gui.dialogs import LegalDisclaimerDialog
from utils.logger import AppLogger
from utils import db_crypto

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

if __name__ == '__main__':
    # 1. 로거 및 멀티프로세싱 초기화
    AppLogger.setup()
    multiprocessing.freeze_support()
    # --- [추가] CLI 인자 파싱 (자동 스캔 연동 모드) ---
    parser = argparse.ArgumentParser(description="Z-VulnScan Professional")
    parser.add_argument("--target", type=str, help="자동으로 스캔할 대상 IP", default=None)
    args, unknown = parser.parse_known_args()
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
            scanner = ScannerApp()
            scanner.show()
            sys.exit(app.exec())
        else:
            sys.exit()