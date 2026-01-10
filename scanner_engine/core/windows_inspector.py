# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import winrm
import json
import os
import sys

# 상위 폴더 모듈 참조 (utils 접근용)
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.secure_storage import SecureStorage
from utils.logger import AppLogger

class WindowsInspector:
    def __init__(self, ip, username):
        self.ip = ip
        self.username = username
        self.session = None
        self.is_connected = False
        self.is_simulation = False
        
        # [Hybrid Path Strategy] 
        # 정책: 외부 rules 폴더(커스텀) 우선 -> 없으면 내부 _MEIPASS(기본값) 사용
        self.rules_path = self._get_rules_path()

    def _get_rules_path(self):
        filename = 'windows_rules.json'
        
        # 1. 외부 경로 계산 (EXE 실행 위치 기준 / 개발 환경은 프로젝트 루트)
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            # scanner_engine/core/ -> scanner_engine/ -> ProjectRoot/
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
        external_path = os.path.join(base_dir, 'rules', filename)
        
        # 2. 내부 경로 계산 (PyInstaller 임시 폴더)
        internal_path = None
        if hasattr(sys, '_MEIPASS'):
            internal_path = os.path.join(sys._MEIPASS, 'rules', filename)
        else:
            internal_path = external_path # 개발 환경에선 내/외부 동일 취급

        # 3. 우선순위 결정 (외부 파일이 존재하면 외부 사용 -> 플러그인 기능)
        if os.path.exists(external_path):
            return external_path
        elif internal_path and os.path.exists(internal_path):
            return internal_path
            
        # 둘 다 없으면 외부 경로 반환 (run_all_checks에서 에러 로그 처리)
        return external_path

    def connect(self):
        # 시뮬레이션 및 로컬 테스트 IP 체크
        if self.ip in ["0.0.0.0", "127.0.0.2", "localhost"]:
            self.is_simulation = True
            return True
        
        # 연결 직전 암호 저장소에서 비밀번호 로드 (메모리 보안)
        password = SecureStorage.get_credential(self.ip, self.username)
        if not password:
            return False

        try:
            # WinRM 세션 생성 (TimeOut 설정 유지)
            self.session = winrm.Session(
                f'http://{self.ip}:5985/wsman',
                auth=(self.username, password),
                transport='ntlm',
                read_timeout_sec=30,      # 원본 코드 설정 유지
                operation_timeout_sec=25  # 원본 코드 설정 유지
            )

            # 연결 테스트 (hostname 명령)
            if self.session.run_cmd('hostname').status_code == 0:
                self.is_connected = True
                del password # 사용 후 즉시 메모리 해제
                return True
        except: 
            pass 
        return False

    def execute_ps(self, script):
        if self.is_simulation:
            return self.get_mock_data(script)
            
        if not self.is_connected:
            return ""
        try:
            rs = self.session.run_ps(script)
            if rs.status_code == 0:
                # 한글(CP949) 깨짐 방지 디코딩 로직 보존
                try:
                    return rs.std_out.decode('utf-8').strip()
                except UnicodeDecodeError:
                    return rs.std_out.decode('cp949', errors='ignore').strip()
        except: pass
        return ""

    def get_mock_data(self, script):
        """윈도우 가상 진단 데이터 (데모 모드용)"""
        s = script.lower()
        if "administrator" in s: return "Name: Administrator, Enabled: True"
        if "guest" in s: return ""
        if "tlntsvr" in s: return "Status: Running"
        if "net accounts" in s: return "Lockout threshold: Never"
        if "get-smbshare" in s: return "Name: C$, Path: C:\\"
        if "simptcp" in s: return "Status: Stopped"
        if "get-hotfix" in s: return "Cannot find HotFix"
        return ""

    def run_all_checks(self):
        results = {}
        rules = []
        
        # 룰 파일 로드 (예외 처리 강화)
        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
            except Exception as e:
                AppLogger.log_error(f"Failed to load windows rules: {e}")
        else:
            AppLogger.log_error(f"Windows rules file not found: {self.rules_path}")

        for rule in rules:
            code = rule['code']
            cmd = rule['command']
            output = self.execute_ps(cmd)

            status = "SAFE"
            detail = "점검 완료"

            # 키워드 매칭 로직 (취약/양호 판단)
            if "vulnerable_keyword" in rule:
                if rule['vulnerable_keyword'] in output:
                    status = "VULNERABLE"
                    detail = f"취약 설정 발견: {output[:30]}..."
            elif "safe_keyword" in rule:
                if not output or rule['safe_keyword'] not in output:
                    status = "VULNERABLE"
                    detail = f"안전 설정 미흡"

            # 결과 저장 (4개 튜플 포맷 유지: status, detail, name, remediation)
            results[code] = (
                status, 
                detail, 
                rule.get('name', code), 
                rule.get('remediation', '')
            )
            
        return results