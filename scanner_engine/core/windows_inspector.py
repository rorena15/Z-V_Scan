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

# 상위 폴더 모듈 참조
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
        self.rules_path = self._get_rules_path()

    def _get_rules_path(self):
        filename = 'windows_rules.json'
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
        if self.ip in ["0.0.0.0", "127.0.0.2", "localhost"]:
            self.is_simulation = True
            return True
        
        password = SecureStorage.get_credential(self.ip, self.username)
        if not password:
            return False

        try:
            self.session = winrm.Session(
                f'http://{self.ip}:5985/wsman',
                auth=(self.username, password),
                transport='ntlm',
                read_timeout_sec=30,
                operation_timeout_sec=25
            )
            if self.session.run_cmd('hostname').status_code == 0:
                self.is_connected = True
                del password
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
                try:
                    return rs.std_out.decode('utf-8').strip()
                except UnicodeDecodeError:
                    return rs.std_out.decode('cp949', errors='ignore').strip()
        except: pass
        return ""

    def get_mock_data(self, script):
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
        """
        [수정됨] 헌법 준수: 증적(Raw Output)과 KISA 코드를 포함하여 반환
        Return: {code: (status, detail, name, remediation, raw_output, kisa_code)}
        """
        results = {}
        rules = []
        
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
            # [추가 1] KISA 코드
            kisa_code = rule.get('kisa_code', rule.get('code', ''))
            
            cmd = rule['command']
            # [추가 2] 증적 확보
            full_output = self.execute_ps(cmd)

            status = "SAFE"
            detail = "양호 (설정 확인됨)"

            if "vulnerable_keyword" in rule:
                if rule['vulnerable_keyword'] in full_output:
                    status = "VULNERABLE"
                    detail = f"취약 설정 발견: {full_output[:40]}..."
            elif "safe_keyword" in rule:
                if not full_output or rule['safe_keyword'] not in full_output:
                    status = "VULNERABLE"
                    detail = f"필수 설정 미흡: {rule['safe_keyword']} 누락"
            else:
                # 판정 기준(키워드)이 없는 항목 = 조직 맥락 판단이 필요해 자동 판정하지 않는 항목
                status = "MANUAL"
                detail = "수동 검토 필요 (증적 확인)"

            # [핵심 수정] 6개 -> 7개 튜플 반환 (중요도 포함)
            results[code] = (
                status,
                detail,
                rule.get('name', code),
                rule.get('remediation', ''),
                full_output, # Raw Output
                kisa_code,   # KISA Code
                rule.get('importance', '중')  # 중요도 (상/중/하)
            )
            
        return results