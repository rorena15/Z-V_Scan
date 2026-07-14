# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import argparse
import sys
import os
import ctypes
import multiprocessing
import traceback
from datetime import datetime
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QDialog
from PySide6.QtGui import QIcon

# 분리된 UI 및 다이얼로그 import
from gui.main_window import ScannerApp
from gui.dialogs import LegalDisclaimerDialog
from utils.logger import AppLogger

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
    
    if args.target:
        # [연동 모드] 미들웨어가 호출했을 때: 법적 고지 패스하고 바로 스캔 돌입
        scanner = ScannerApp()
        scanner.show()
        
        # 1. IP 입력란에 미들웨어가 넘겨준 타겟 IP 자동 입력
        scanner.ip_input.setText(args.target)
        
        # 2. 창이 뜨고 1초(1000ms) 뒤에 취약점 진단 함수(start_audit) 자동 실행
        QTimer.singleShot(1000, scanner.start_audit)
        
        sys.exit(app.exec())
        
    else:
        # [일반 모드] 사용자가 더블클릭해서 실행했을 때: 기존 로직 그대로 유지
        disclaimer = LegalDisclaimerDialog()
        disclaimer.setWindowIcon(QIcon(icon_path))
        
        if disclaimer.exec() == QDialog.Accepted:
            scanner = ScannerApp()
            scanner.show()
            sys.exit(app.exec())
        else:
            sys.exit()