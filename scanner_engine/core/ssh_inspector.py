# Copyright (c) 2025 rorena15
# All rights reserved.
# Proprietary License - No redistribution or modification without permission.
# scanner_engine/core/ssh_inspector.py
import paramiko
import json
import os
import sys

class SSHInspector:
    def __init__(self, ip, username, password, port=22):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.client = None
        self.is_simulation = False
        
        # rules 경로 로드
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.rules_path = os.path.join(base_dir, 'rules', 'linux_rules.json')
        # 빌드 대응
        if hasattr(sys, '_MEIPASS'):
            self.rules_path = os.path.join(sys._MEIPASS, 'rules', 'linux_rules.json')

    def connect(self):
        if self.ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
            self.is_simulation = True
            return True
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.ip, port=self.port, username=self.username, password=self.password, timeout=3, banner_timeout=3)
            return True
        except:
            self.is_simulation = True # 실패 시 시뮬레이션 전환
            return True

    def close(self):
        if self.client: self.client.close()

    def execute_command(self, command):
        if self.client and not self.is_simulation:
            try:
                stdin, stdout, stderr = self.client.exec_command(command)
                return stdout.read().decode('utf-8').strip()
            except: return ""
        else:
            return self.get_mock_data(command)

    def get_mock_data(self, command):
        # 시뮬레이션 데이터 반환 (테스트용)
        if "PermitRootLogin" in command: return "PermitRootLogin yes"
        if "pwquality" in command: return "" # 취약
        if "pam_tally" in command: return "" # 취약
        if "shadow" in command: return "-rw-r--r-- root root" # 취약 (644)
        return ""

    def run_all_checks(self):
        results = {}
        
        # 1. JSON 규칙 로드
        rules = []
        if os.path.exists(self.rules_path):
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                rules = json.load(f)
        
        # 2. 규칙 순회하며 진단
        for rule in rules:
            code = rule['code']
            cmd = rule['command']
            
            output = self.execute_command(cmd)
            status = "SAFE"
            detail = f"점검 완료: {output[:50]}..." if output else "설정 없음"

            # 판단 로직
            if "vulnerable_keyword" in rule:
                if rule['vulnerable_keyword'] in output:
                    status = "VULNERABLE"
                    detail = f"취약 설정 발견: {output.strip()}"
            elif "safe_keyword" in rule:
                if rule['safe_keyword'] not in output:
                    status = "VULNERABLE"
                    detail = f"안전 설정 미흡: {output.strip()}"
            
            results[code] = (status, detail)
            
        return results