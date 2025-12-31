# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
# utils/logger.py
import logging
import os
import sys

class AppLogger:
    _initialized = False

    @staticmethod
    def setup():
        if AppLogger._initialized: return
        
        # 1. 로그 파일 경로 설정
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            
        log_file = os.path.join(base_dir, "scan_debug.log")

        # 2. [Claude Fix] 로그 파일 생성 시도 및 실패 시 Fallback(대체) 처리
        try:
            logging.basicConfig(
                filename=log_file, level=logging.DEBUG,
                format='[%(asctime)s] [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S', encoding='utf-8', filemode='w'
            )
            # 성공 시 콘솔 핸들러 추가
            console = logging.StreamHandler()
            console.setLevel(logging.ERROR)
            logging.getLogger('').addHandler(console)
            
            AppLogger._initialized = True
            logging.info("=== Z-VulnScan Professional v2.2.0 Logger Started ===")
            
        except PermissionError:
            # [Fix] 파일 쓰기 권한이 없으면 콘솔 전용 모드로 작동 (프로그램 크래시 방지)
            logging.basicConfig(
                level=logging.ERROR, 
                handlers=[logging.StreamHandler()] # 파일 없이 콘솔만
            )
            AppLogger._initialized = True
            logging.error("[System] Cannot create log file (Permission Denied). Running in Console-Only mode.")
            
        except Exception as e:
            # 기타 에러 시 안전 모드
            print(f"[CRITICAL] Logger Init Failed: {e}", file=sys.stderr)
            # 최소한의 초기화
            AppLogger._initialized = True

    @staticmethod
    def log_info(message):
        if not AppLogger._initialized: AppLogger.setup()
        logging.info(message)

    @staticmethod
    def log_error(message, exception=None):
        if not AppLogger._initialized: AppLogger.setup()
        if exception:
            logging.error(f"{message} | Details: {str(exception)}")
        else:
            logging.error(message)