# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import sys
import os
import platform
import subprocess
import shutil

class OSUtils:
    @staticmethod
    def get_os_type():
        """운영체제 타입 반환 ('Windows', 'Linux', 'Darwin', etc.)"""
        return platform.system()

    @staticmethod
    def is_windows():
        return platform.system() == 'Windows'

    @staticmethod
    def is_linux():
        return platform.system() == 'Linux'

    @staticmethod
    def is_admin():
        """관리자/Root 권한 여부 확인"""
        try:
            if OSUtils.is_windows():
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False

    @staticmethod
    def get_font_path(font_filename='NanumGothic.ttf'):
        """
        OS 및 실행 환경(IDE vs PyInstaller EXE)에 따른 폰트 경로 반환
        """
        # 1. PyInstaller 빌드 환경 (_MEIPASS)
        if hasattr(sys, '_MEIPASS'):
            return os.path.join(sys._MEIPASS, font_filename)
        
        # 2. 개발 환경 (프로젝트 루트 기준 탐색)
        # 현재 위치: scanner_engine/utils/os_utils.py
        # 목표 위치: 프로젝트 루트/NanumGothic.ttf
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        font_path = os.path.join(base_dir, font_filename)
        
        if os.path.exists(font_path):
            return font_path
            
        # 3. 시스템 폰트 대체 (Linux 등)
        if OSUtils.is_linux():
            # 리눅스 시스템 폰트 경로 예시
            return "/usr/share/fonts/truetype/nanum/NanumGothic.ttf"
            
        return font_filename # 못 찾으면 파일명만 리턴 (에러 가능성 있음)

    @staticmethod
    def open_file(filepath):
        """OS별 기본 프로그램으로 파일 열기"""
        if not os.path.exists(filepath):
            return False
            
        try:
            if OSUtils.is_windows():
                os.startfile(filepath)
            elif platform.system() == 'Darwin': # macOS
                subprocess.call(['open', filepath])
            else: # Linux
                subprocess.call(['xdg-open', filepath])
            return True
        except Exception as e:
            print(f"[Error] Failed to open file: {e}")
            return False

    @staticmethod
    def get_ping_command(target_ip):
        """OS별 Ping 명령어 및 subprocess 옵션 반환"""
        if OSUtils.is_windows():
            cmd = ['ping', '-n', '1', '-w', '200', target_ip]
            # 윈도우 전용: 콘솔 창 숨기기 플래그
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            kwargs = {
                'startupinfo': startupinfo,
                'creationflags': subprocess.CREATE_NO_WINDOW
            }
        else:
            cmd = ['ping', '-c', '1', '-W', '1', target_ip]
            kwargs = {} # 리눅스는 옵션 불필요
            
        return cmd, kwargs