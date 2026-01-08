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
    
    # 작업표시줄 아이콘 분리
    myappid = 'z_vuln_scan.pro.v3.0' 
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except Exception:
        pass

    app = QApplication(sys.argv)

    icon_path = resource_path("app_icon.ico") 
    app.setWindowIcon(QIcon(icon_path))
    
    # 2. 법적 고지 준비
    disclaimer = LegalDisclaimerDialog()
    disclaimer.setWindowIcon(QIcon(icon_path))

    # ----------------------------------------------------------------
    # [Fix] 스플래시 화면 강제 종료 (텍스트 코드 제거됨)
    # ----------------------------------------------------------------
    import time
    
    try:
        import pyi_splash # type: ignore
        
        # 1. 닫기 명령 전송
        pyi_splash.close()
        
        # 2. [핵심] 윈도우가 '닫기' 이벤트를 처리하도록 강제 (Deadlock 방지)
        # 이 한 줄이 없으면 스플래시가 법적 고지 창 뒤에 눌러붙습니다.
        app.processEvents() 
        time.sleep(0.1)     
        
    except ImportError:
        pass
    # ----------------------------------------------------------------
    
    # 3. 법적 고지 실행
    if disclaimer.exec() == QDialog.Accepted:
        scanner = ScannerApp()
        scanner.show()
        sys.exit(app.exec())
    else:
        sys.exit()