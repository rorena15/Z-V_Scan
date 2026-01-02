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
from utils.logger import AppLogger

class OSUtils:
    @staticmethod
    def get_os_type():
        return platform.system()

    @staticmethod
    def is_windows():
        return platform.system() == 'Windows'

    @staticmethod
    def is_linux():
        return platform.system() == 'Linux'

    def get_resource_path(relative_path):
        # PyInstaller 빌드 시 리소스 경로 문제 해결
        #(기존 main_window.py에 있던 resource_path 함수 이관)

        if hasattr(sys, '_MEIPASS'):
            return os.path.join(sys._MEIPASS, relative_path)
        return os.path.join(os.path.abspath("."), relative_path)

    @staticmethod
    def get_subprocess_kwargs():
        #[핵심] Windows에서 subprocess 실행 시 CMD 창이 뜨지 않도록 설정하는 옵션 반환
        kwargs = {}
        if OSUtils.is_windows():
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE # 0 (SW_HIDE)
            
            kwargs['startupinfo'] = startupinfo
            # Python 3.7+ 부터 지원하는 창 숨김 플래그
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        return kwargs

    @staticmethod
    def get_ping_command(target_ip):
        # OS별 Ping 명령어 및 Hidden Window 옵션 반환
        # 공통 숨김 옵션 가져오기
        kwargs = OSUtils.get_subprocess_kwargs()
        
        if OSUtils.is_windows():
            # -n: 횟수, -w: 타임아웃(ms) -> 200ms로 설정하여 속도 향상
            cmd = ['ping', '-n', '1', '-w', '200', target_ip]
        else:
            # -c: 횟수, -W: 타임아웃(s) -> 1초 (Linux Ping은 초 단위)
            cmd = ['ping', '-c', '1', '-W', '1', target_ip]
            
        return cmd, kwargs

    @staticmethod
    def is_admin():
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
        if hasattr(sys, '_MEIPASS'):
            return os.path.join(sys._MEIPASS, font_filename)
        
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        font_path = os.path.join(base_dir, font_filename)
        
        if os.path.exists(font_path):
            return font_path
            
        if OSUtils.is_linux():
            return "/usr/share/fonts/truetype/nanum/NanumGothic.ttf"
            
        return font_filename

    @staticmethod
    def open_file(filepath):
        if not os.path.exists(filepath): return False
        try:
            if OSUtils.is_windows():
                os.startfile(filepath)
            elif platform.system() == 'Darwin':
                subprocess.call(['open', filepath])
            else:
                subprocess.call(['xdg-open', filepath])
            return True
        except Exception as e:
            AppLogger.log_error(f"[Utills] Open File Fail", e)
            return False
        
    @staticmethod
    def open_ping_test(target_ip):
        # UI 컨텍스트 메뉴용: 새 콘솔 창을 열어 Ping을 계속 실행 (-t)
        try:
            if OSUtils.is_windows():
                # start cmd /k : 명령 실행 후 창 유지
                subprocess.Popen(f"start cmd /k ping {target_ip} -t", shell=True)
            elif OSUtils.is_linux():
                # gnome-terminal 사용 (환경에 따라 xterm 등으로 변경 가능)
                subprocess.Popen(f"gnome-terminal -- ping {target_ip}", shell=True)
        except Exception as e:
            AppLogger.log_error(f"[Utills] Fail to open ping test", e)
            
    
    @staticmethod
    def open_rdp(target_ip):
        # UI 컨텍스트 메뉴용: Windows MSTSC(원격 데스크톱) 실행
        if OSUtils.is_windows():
            try:
                subprocess.Popen(f"mstsc /v:{target_ip}", shell=True)
            except Exception as e:
                AppLogger.log_error(f"[Utills] Failed to open RDP:", e)
        else:
            AppLogger.log_error(f"[Utills] [Warning] RDP shortcut is primarily for Windows hosts.")

    @staticmethod
    def open_ssh(target_ip, user="root"):
        # UI 컨텍스트 메뉴용: 새 콘솔 창을 열어 SSH 접속 시도
        try:
            if OSUtils.is_windows():
                # Windows 10/11은 기본 ssh 클라이언트 내장
                subprocess.Popen(f"start cmd /k ssh {user}@{target_ip}", shell=True)
            elif OSUtils.is_linux():
                subprocess.Popen(f"gnome-terminal -- ssh {user}@{target_ip}", shell=True)
        except Exception as e:
            AppLogger.log_error(f"[Utills] Failed to open SSH console:", e)