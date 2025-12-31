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
        """애플리케이션 전역 로거 설정 (최초 1회 실행)"""
        if AppLogger._initialized: return

        # 로그 파일은 실행 파일(exe) 옆에 생성
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            
        log_file = os.path.join(base_dir, "scan_debug.log")

        # 로거 설정 (DEBUG 레벨까지 모두 기록)
        logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG,
            format='[%(asctime)s] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            encoding='utf-8',
            filemode='w' # 실행할 때마다 새로 작성 (a로 하면 계속 누적)
        )

        # 콘솔에도 에러는 출력 (개발용)
        console = logging.StreamHandler()
        console.setLevel(logging.ERROR)
        logging.getLogger('').addHandler(console)

        AppLogger._initialized = True
        logging.info("=== Z-VulnScan Professional v2.2.1 Logger Started ===")

    @staticmethod
    def log_info(message):
        if AppLogger._initialized:
            logging.info(message)

    @staticmethod
    def log_error(message, exception=None):
        """에러 발생 시 로그 기록 (예외 정보 포함)"""
        if AppLogger._initialized:
            if exception:
                logging.error(f"{message} | Details: {str(exception)}")
                # 필요시 스택 트레이스까지 남기려면 아래 주석 해제
                # logging.exception(message) 
            else:
                logging.error(message)