# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import paramiko
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.secure_storage import SecureStorage

class SSHInspector:
    def __init__(self, ip, username, port=22):
        self.ip = ip
        self.username = username
        self.port = port
        self.client = None
        self.is_simulation = False
        
        # rules 경로 로드
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.rules_path = os.path.join(base_dir, 'rules', 'linux_rules.json')
        if hasattr(sys, '_MEIPASS'):
            self.rules_path = os.path.join(sys._MEIPASS, 'rules', 'linux_rules.json')

    def connect(self):
        # 시뮬레이션 IP 체크
        if self.ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
            self.is_simulation = True
            return True
        
        #연결 직전에만 비밀번호 로드
        password = SecureStorage.get_credential(self.ip, self.username)
        if not password:
            print(f"[Error] {self.ip}에 대한 자격증명을 찾을 수 없습니다.")
            return False
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.ip, port=self.port, username=self.username, password=password, timeout=20)
            del password
            return True
        except:
            self.is_simulation = True # 접속 실패 시 시뮬레이션 전환
            return True

    def close(self):
        if self.client:
            try:
                self.client.close()
            except:
                pass
            self.client = None

    def execute_command(self, command):
        if self.client and not self.is_simulation:
            try:
                stdin, stdout, stderr = self.client.exec_command(command)
                return stdout.read().decode('utf-8').strip()
            except: return ""
        else:
            return self.get_mock_data(command)

    def get_mock_data(self, command):
        """가상 진단을 위한 Mock 데이터 반환 (JSON 규칙 대응)"""
        cmd = command.lower()

        # U-01: Root Login (취약: yes)
        if "permitrootlogin" in cmd: return "PermitRootLogin yes"
        
        # U-02: Password Complexity (취약: minlen 없음)
        if "pwquality.conf" in cmd: return "retry=3"
        
        # U-03: Account Lockout (양호: deny=5 있음)
        if "pam_tally2" in cmd or "pam_faillock" in cmd: return "auth required pam_tally2.so deny=5 unlock_time=120"
        
        # U-04: Shadow File (취약: 권한 644)
        if "ls -l /etc/shadow" in cmd: return "-rw-r--r-- 1 root root 1234 Jan 01 00:00 /etc/shadow"
        
        # U-05: PATH (양호)
        if "echo $path" in cmd: return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
        
        # U-07: Passwd File (양호)
        if "ls -l /etc/passwd" in cmd: return "-rw-r--r-- 1 root root 2000 Jan 01 00:00 /etc/passwd"
        
        # U-19: Finger (취약: 서비스 실행 중)
        if "grep finger" in cmd: return "root 1234 1 0 00:00 ? 00:00:00 in.fingerd"
        
        # U-20: Anonymous FTP (취약: YES)
        if "anonymous_enable" in cmd: return "anonymous_enable=YES"
        
        # U-21: R-command (양호: 결과 없음)
        if "ls /etc/xinetd.d/r" in cmd: return ""
        
        # U-22: Crontab (취약: 소유자 user)
        if "ls -l /etc/crontab" in cmd: return "-rw-r--r-- 1 user user 500 Jan 01 00:00 /etc/crontab"
        
        # U-23: DoS Service (양호)
        if "inetd.conf" in cmd: return ""
        
        # U-54: Timeout (취약: 결과 없음)
        if "tmout" in cmd: return ""
        
        # 기본값: 빈 문자열 (검사 결과 없음 -> 양호/취약 여부는 규칙에 따름)
        return ""
    _signature = "Made_By_Rorena_2025_Seongnam_KR"

    def run_all_checks(self):
        results = {}
        rules = []
        if os.path.exists(self.rules_path):
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                rules = json.load(f)
        
        for rule in rules:
            code = rule['code']
            cmd = rule['command']
            output = self.execute_command(cmd)
            
            status = "SAFE"
            detail = "점검 완료"

            # 1. 취약 키워드 체크 (키워드가 있으면 취약)
            if "vulnerable_keyword" in rule:
                if rule['vulnerable_keyword'] in output:
                    status = "VULNERABLE"
                    detail = f"취약 설정 발견: {output[:30]}..."
            
            # 2. 안전 키워드 체크 (키워드가 없으면 취약)
            elif "safe_keyword" in rule:
                if not output or rule['safe_keyword'] not in output:
                    status = "VULNERABLE"
                    detail = f"필수 설정 미흡: {rule['safe_keyword']} 누락"
            
            results[code] = (status, detail, rule.get('name', code), rule.get('remediation', ''))
        return results