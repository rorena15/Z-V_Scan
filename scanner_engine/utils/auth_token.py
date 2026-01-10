# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import inspect
import sys
import secrets

# 실제 정품 키
REAL_KEY = "ZVulnScan_V3_Pro_Secure_Engine_Key_2026_!@#"

def get_engine_token():
    
    if getattr(sys, 'frozen', False):
        return REAL_KEY

    # 2. 개발 환경(.py) 검증 로직
    try:
        stack = inspect.stack()
        if len(stack) < 2:
            return _generate_fake_token()
            
        caller_frame = stack[1]
        caller_filename = caller_frame.filename
        
        # 허용된 파일명 리스트
        allow_list = ['main_window.py', 'worker.py', 'main.py', 'audit_runner.py', 'advanced_scanner.py']
        
        # 호출자가 허용 리스트에 있거나, scanner_engine 패키지 내부라면 통과
        if "scanner_engine" in caller_filename or \
            any(name in caller_filename for name in allow_list):
            return REAL_KEY
            
        return _generate_fake_token()

    except Exception:
        return _generate_fake_token()
    
def _generate_fake_token():
    return secrets.token_hex(16)