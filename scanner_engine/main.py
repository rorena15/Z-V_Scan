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
    error_msg = "".join(traceback.format_exception(exctype, value, tb))
    print(f"[CRITICAL] {error_msg}")
    try:
        with open("error_log.txt", "a", encoding="utf-8") as f:
            f.write(f"\n{'='*50}\n[{datetime.now()}]\n{error_msg}")
    except: pass

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