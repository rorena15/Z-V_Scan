# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import sys
import multiprocessing
import traceback
from datetime import datetime
from PySide6.QtWidgets import QApplication, QDialog

# 분리된 UI 및 다이얼로그 import
from gui.main_window import ScannerApp
from gui.dialogs import LegalDisclaimerDialog
from utils.logger import AppLogger

# 전역 예외 처리
def my_exception_hook(exctype, value, tb):
    # 1. 에러 메시지 스택 트레이스 생성
    error_msg = "".join(traceback.format_exception(exctype, value, tb))
    
    # 2. 콘솔 출력 (개발자 확인용)
    print(f"[CRITICAL] Uncaught Exception:\n{error_msg}")
    
    # 3. 로그 파일(scan_debug.log)에 영구 기록
    #    별도의 error_log.txt를 만들지 않고 통합 관리합니다.
    try:
        AppLogger.log_critical(f"🔥 PROGRAM CRASHED 🔥\n{error_msg}")
    except:
        # 로거조차 실패했을 때를 대비한 최소한의 방어
        print("[!] Failed to write to AppLogger inside exception hook.")

sys.excepthook = my_exception_hook

if __name__ == '__main__':
    # 1. 로거 및 멀티프로세싱 초기화
    AppLogger.setup()
    multiprocessing.freeze_support()
    
    app = QApplication(sys.argv)
    
    # 2. 법적 고지 실행
    disclaimer = LegalDisclaimerDialog()
    if disclaimer.exec() == QDialog.Accepted:
        # 3. 메인 앱 실행
        scanner = ScannerApp()
        scanner.show()
        sys.exit(app.exec())
    else:
        sys.exit()