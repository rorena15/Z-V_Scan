# Copyright (c) 2025 rorena15
# All rights reserved.
# Proprietary License - No redistribution or modification without permission.
# scanner_engine/core/windows_inspector.py
import winrm
import json
import os
import sys

class WindowsInspector:
    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password
        self.session = None
        self.is_connected = False
        
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.rules_path = os.path.join(base_dir, 'rules', 'windows_rules.json')
        if hasattr(sys, '_MEIPASS'):
            self.rules_path = os.path.join(sys._MEIPASS, 'rules', 'windows_rules.json')

    def connect(self):
        try:
            self.session = winrm.Session(f'http://{self.ip}:5985/wsman', auth=(self.username, self.password), transport='ntlm', read_timeout_sec=5)
            if self.session.run_cmd('hostname').status_code == 0:
                self.is_connected = True
                return True
        except: pass
        return False

    def execute_ps(self, script):
        if not self.is_connected: return ""
        try:
            rs = self.session.run_ps(script)
            if rs.status_code == 0: return rs.std_out.decode('utf-8', errors='ignore').strip()
        except: pass
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
            
            # 윈도우 시뮬레이션 처리 (IP가 0.0.0.0 등이면)
            if self.ip in ["0.0.0.0", "127.0.0.2"]:
                # Mock 결과
                if code == "W-01": output = "Administrator" # 취약
                else: output = ""
            else:
                output = self.execute_ps(cmd)

            status = "SAFE"
            detail = f"점검 완료: {output[:50]}..."

            if "vulnerable_keyword" in rule:
                if rule['vulnerable_keyword'] in output:
                    status = "VULNERABLE"
                    detail = f"취약 설정 발견: {output.strip()}"
            elif "safe_keyword" in rule:
                if rule['safe_keyword'] not in output:
                    status = "VULNERABLE"
                    detail = f"안전 설정 미흡"

            results[code] = (status, detail)
            
        return results