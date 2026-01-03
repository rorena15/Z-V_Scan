# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import inspect
import sys
import os

# 실제 정품 키
REAL_KEY = "ZVulnScan_V3_Pro_Secure_Engine_Key_2026_!@#"
# 해커를 속이기 위한 가짜 키
FAKE_KEY = "Test_Key_1234"

def get_engine_token():
    #호출자를 검증하여, 정당한 내부 모듈(GUI/Core)에서 불렀을 때만
    #진짜 키를 반환합니다. 외부 스크립트에서 부르면 가짜 키를 줍니다.

    try:
        # 1. 현재 스택(호출 경로)을 확인
        # stack[0]: 현재 함수, stack[1]: 나를 부른 함수
        stack = inspect.stack()
        if len(stack) < 2:
            return FAKE_KEY
            
        caller_frame = stack[1]
        
        # 2. 호출한 파일의 이름(경로) 확인
        caller_filename = caller_frame.filename
        
        # 디버깅용 (개발 중에만 주석 해제하여 확인 가능)
        # print(f"DEBUG: Called by {caller_filename}")

        # 3. 검증 로직
        # 정식 빌드된 EXE 환경에서는 파일 경로에 'scanner_engine' 또는 
        # 임시 폴더 경로(_MEI)가 포함되어야 함.
        # 해커가 바탕화면에서 hacker.py로 실행하면 이 경로가 다름.
        
        is_valid_caller = False
        
        # 조건 A: 파일명에 scanner_engine 패키지명이 포함되어 있는가?
        if "scanner_engine" in caller_filename:
            is_valid_caller = True
            
        # 조건 B: PyInstaller로 빌드된 환경(_MEI) 내부인가?
        # (Frozen 상태일 때 sys.frozen이 True임)
        if getattr(sys, 'frozen', False):
            # 빌드된 환경에서는 caller_filename이 임시 폴더 경로를 가리킴
            # 외부에서 침투한 스크립트는 이 경로를 갖기 힘듬
            if "main_window" in caller_filename or "worker" in caller_filename:
                is_valid_caller = True
        
        if is_valid_caller:
            return REAL_KEY
        else:
            return FAKE_KEY

    except Exception:
        # 검증 중 에러가 나면 안전하게 가짜 키 반환
        return FAKE_KEY