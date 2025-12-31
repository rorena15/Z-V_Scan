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
from datetime import datetime

class AppLogger:
    _instance = None

    @staticmethod
    def setup():
        if AppLogger._instance: return
        
        # 로그 파일 경로: 실행 파일 옆에 'scan_log.txt' 생성
        log_file = "scan_debug.log"
        
        logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG, # 모든 에러 기록
            format='[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            encoding='utf-8'
        )
        
        # 콘솔에도 출력 (개발 중 확인용)
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('[%(levelname)s] %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)
        
        AppLogger._instance = True
        logging.info("=== Z-VulnScan Logger Initialized ===")

    @staticmethod
    def log_error(msg, error_obj=None):
        if error_obj:
            logging.error(f"{msg} | Error: {str(error_obj)}")
        else:
            logging.error(msg)