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
        # [버그 수정] 예전엔 dev 모드에서 이 파일(utils/logger.py) 기준 dirname 1단계만
        # 써서 scanner_engine/utils/ 밑에 로그가 생겼다 - 실사용 중 "로그 파일이 안
        # 만들어진다"는 보고가 있었는데, 실제로는 만들어지고 있었지만 사용자가 당연히
        # 확인하는 프로젝트 루트(다른 산출물인 audit_agreement.log, zvuln_scan.db가
        # 있는 곳)에는 없어서 못 찾은 것으로 확인됨. utils/db_connector.py 등 다른
        # 모듈이 쓰는 것과 동일한 3단계 dirname으로 맞춰 프로젝트 루트에 생성한다.
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        log_file = os.path.join(base_dir, "scan_debug.log")

        # 2. [Claude Fix] 로그 파일 생성 시도 및 실패 시 Fallback(대체) 처리
        try:
            logging.basicConfig(
                filename=log_file, level=logging.DEBUG,
                format='[%(asctime)s] [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S', encoding='utf-8', filemode='a'
            )
            # 성공 시 콘솔 핸들러 추가
            console = logging.StreamHandler()
            console.setLevel(logging.ERROR)
            logging.getLogger('').addHandler(console)
            
            AppLogger._initialized = True
            logging.info("=== Z-VulnScan Professional v3.0.0 Logger Started ===")
            
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
    
    @staticmethod
    def log_critical(message):
        #프로그램 중단급 에러 기록 (CRITICAL Level)
        if not AppLogger._initialized: AppLogger.setup()
        logging.critical(message)