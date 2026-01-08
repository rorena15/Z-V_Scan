# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import sys
import os
import ctypes  # [추가] 윈도우 작업표시줄 아이콘 분리용
import multiprocessing
import traceback
from datetime import datetime
from PySide6.QtWidgets import QApplication, QDialog
from PySide6.QtGui import QIcon  # [추가] 아이콘 설정용

# 분리된 UI 및 다이얼로그 import
from gui.main_window import ScannerApp
from gui.dialogs import LegalDisclaimerDialog
from utils.logger import AppLogger

# [추가] 빌드 시 리소스 경로 문제 해결 함수
# PyInstaller나 난독화 툴로 빌드하면 파일들이 임시 폴더(_MEIPASS)에 풀리는데,
# 그냥 상대 경로("assets/icon.ico")로 쓰면 그 파일을 못 찾아서 아이콘이 안 뜹니다.
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
    
    # [추가] Windows AppUserModelID 설정 (작업표시줄 아이콘 분리)
    # 이게 없으면 윈도우가 이 프로그램을 그냥 'python'으로 인식해서 기본 아이콘을 띄울 수 있음
    myappid = 'z_vuln_scan.pro.v3.0' 
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except Exception:
        pass # 윈도우가 아니거나 실패해도 프로그램은 켜져야 함

    app = QApplication(sys.argv)

    icon_path = resource_path("app_icon.ico") 
    app.setWindowIcon(QIcon(icon_path))
    
    # 2. 법적 고지 실행
    # 이제 이 다이얼로그도 위에서 설정한 아이콘을 달고 나옵니다.
    disclaimer = LegalDisclaimerDialog()
    
    # (혹시 몰라 다이얼로그 개별 아이콘도 한 번 더 확실하게 지정)
    disclaimer.setWindowIcon(QIcon(icon_path))
    
    try:
        import pyi_splash # type: ignore
        pyi_splash.close()
    except ImportError:
        pass

    if disclaimer.exec() == QDialog.Accepted:
        # 3. 메인 앱 실행
        scanner = ScannerApp()
        scanner.show()
        sys.exit(app.exec())
    else:
        sys.exit()
        sys.exit()