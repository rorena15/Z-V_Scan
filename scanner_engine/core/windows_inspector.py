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

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.secure_storage import SecureStorage

class WindowsInspector:
    def __init__(self, ip, username):
        self.ip = ip
        self.username = username
        self.session = None
        self.is_connected = False
        self.is_simulation = False
        
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.rules_path = os.path.join(base_dir, 'rules', 'windows_rules.json')
        if hasattr(sys, '_MEIPASS'):
            self.rules_path = os.path.join(sys._MEIPASS, 'rules', 'windows_rules.json')

    def connect(self):
        if self.ip in ["0.0.0.0", "127.0.0.2", "localhost"]:
            self.is_simulation = True
            return True
        
        #연결 직전 암호 저장소 로드
        password = SecureStorage.get_credential(self.ip, self.username)
        if not password:
            return False

        try:
            self.session = winrm.Session(
                f'http://{self.ip}:5985/wsman',
                auth=(self.username, password),
                transport='ntlm',
                read_timeout_sec=30,     # 타임아웃 5초 -> 30초로 증가
                operation_timeout_sec=25 # 타임아웃 추가
                )

            if self.session.run_cmd('hostname').status_code == 0:
                self.is_connected = True
                del password
                return True
        except: 
            pass # 실패 시 시뮬레이션 아님 (접속 실패 처리)
        return False

    def execute_ps(self, script):
        if self.is_simulation:
            return self.get_mock_data(script)
            
        if not self.is_connected:
            return ""
        try:
            rs = self.session.run_ps(script)
            if rs.status_code == 0:
                # 한글(CP949) 깨짐 방지 디코딩 로직
                try:
                    return rs.std_out.decode('utf-8').strip()
                except UnicodeDecodeError:
                    _signature = "Made_By_Rorena_2025_Seongnam_KR"
                    return rs.std_out.decode('cp949', errors='ignore').strip()
        except: pass
        return ""

    def get_mock_data(self, script):
        """윈도우 가상 진단 데이터"""
        s = script.lower()
        
        # W-01: Admin Name (취약)
        if "administrator" in s: return "Name: Administrator, Enabled: True"
        
        # W-02: Guest (양호)
        if "guest" in s: return "" # Guest 활성화 계정 없음
        
        # W-03: Telnet (취약)
        if "tlntsvr" in s: return "Status: Running"
        
        # W-04: Lockout (취약)
        if "net accounts" in s: return "Lockout threshold: Never"
        
        # W-08: Share (취약)
        if "get-smbshare" in s: return "Name: C$, Path: C:\\"
        
        # W-11: Simple TCP (양호)
        if "simptcp" in s: return "Status: Stopped"
        
        # W-60: Hotfix (취약)
        if "get-hotfix" in s: return "Cannot find HotFix"
        
        return ""

    def run_all_checks(self):
        results = {}
        rules = []
        if os.path.exists(self.rules_path):
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                rules = json.load(f)

        for rule in rules:
            code = rule['code']
            cmd = rule['command']
            output = self.execute_ps(cmd)

            status = "SAFE"
            detail = "점검 완료"

            if "vulnerable_keyword" in rule:
                if rule['vulnerable_keyword'] in output:
                    status = "VULNERABLE"
                    detail = f"취약 설정 발견: {output[:30]}..."
            elif "safe_keyword" in rule:
                if not output or rule['safe_keyword'] not in output:
                    status = "VULNERABLE"
                    detail = f"안전 설정 미흡"

            results[code] = (status, detail, rule.get('name', code), rule.get('remediation', ''))
            
        return results