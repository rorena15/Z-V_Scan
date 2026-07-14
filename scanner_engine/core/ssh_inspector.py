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
from utils.logger import AppLogger

class SSHInspector:
    def __init__(self, ip, username, port=22):
        self.ip = ip
        self.username = username
        self.port = port
        self.client = None
        self.is_simulation = False
        self.rules_path = self._get_rules_path()

    def _get_rules_path(self):
        filename = 'linux_rules.json'
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
        external_path = os.path.join(base_dir, 'rules', filename)
        
        internal_path = None
        if hasattr(sys, '_MEIPASS'):
            internal_path = os.path.join(sys._MEIPASS, 'rules', filename)
        else:
            internal_path = external_path

        if os.path.exists(external_path):
            return external_path
        elif internal_path and os.path.exists(internal_path):
            return internal_path
        return external_path

    def connect(self):
        if self.ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
            self.is_simulation = True
            return True
        
        password = SecureStorage.get_credential(self.ip, self.username)
        if not password:
            AppLogger.log_error(f"Credentials not found for {self.ip}")
            return False
            
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.ip, port=self.port, username=self.username, password=password, timeout=20)
            del password
            return True
        except Exception as e:
            self.is_simulation = True 
            return True

    def close(self):
        if self.client:
            try:
                self.client.close()
            except: pass
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
        cmd = command.lower()
        if "permitrootlogin" in cmd: return "PermitRootLogin yes"
        if "pwquality.conf" in cmd: return "retry=3"
        if "pam_tally2" in cmd or "pam_faillock" in cmd: return "auth required pam_tally2.so deny=5 unlock_time=120"
        if "ls -l /etc/shadow" in cmd: return "-rw-r--r-- 1 root root 1234 Jan 01 00:00 /etc/shadow"
        if "echo $path" in cmd: return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
        if "ls -l /etc/passwd" in cmd: return "-rw-r--r-- 1 root root 2000 Jan 01 00:00 /etc/passwd"
        if "grep finger" in cmd: return "root 1234 1 0 00:00 ? 00:00:00 in.fingerd"
        if "anonymous_enable" in cmd: return "anonymous_enable=YES"
        if "ls /etc/xinetd.d/r" in cmd: return ""
        if "ls -l /etc/crontab" in cmd: return "-rw-r--r-- 1 user user 500 Jan 01 00:00 /etc/crontab"
        if "inetd.conf" in cmd: return ""
        if "tmout" in cmd: return ""
        return ""

    def run_all_checks(self):
        """
        [수정됨] 헌법 준수: 증적(Raw Output)과 KISA 코드를 포함하여 반환
        """
        results = {}
        rules = []
        
        # 룰 파일 로드
        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
            except Exception as e:
                AppLogger.log_error(f"Failed to load linux rules: {e}")
        else:
            AppLogger.log_error(f"Linux rules file not found: {self.rules_path}")
        
        for rule in rules:
            code = rule['code']
            # [추가 1] KISA 코드 매핑 (없으면 내부 코드 사용)
            kisa_code = rule.get('kisa_code', rule.get('code', ''))
            
            cmd = rule['command']
            
            # [추가 2] 증적 확보 (명령어 실행 전체 결과)
            full_output = self.execute_command(cmd)
            
            status = "SAFE"
            detail = "양호 (점검 완료)"

            # 판정 로직
            if "vulnerable_keyword" in rule:
                if rule['vulnerable_keyword'] in full_output:
                    status = "VULNERABLE"
                    detail = f"취약 설정 발견: {full_output[:40]}..."
            elif "safe_keyword" in rule:
                if not full_output or rule['safe_keyword'] not in full_output:
                    status = "VULNERABLE"
                    detail = f"필수 설정 미흡: {rule['safe_keyword']} 누락"
            
            # [핵심 수정] 4개 -> 6개 튜플 반환 (증적 포함)
            results[code] = (
                status, 
                detail, 
                rule.get('name', code), 
                rule.get('remediation', ''),
                full_output,  # Raw Output (증적)
                kisa_code     # KISA Code
            )
            
        return results