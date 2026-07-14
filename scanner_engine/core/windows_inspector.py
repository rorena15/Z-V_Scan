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
import time

# 상위 폴더 모듈 참조
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.secure_storage import SecureStorage
from utils.logger import AppLogger
from utils.throttle import AdaptiveThrottle
from utils.rule_judge import judge_rule

class WindowsInspector:
    def __init__(self, ip, username, ruleset="windows_rules.json", throttle=False, demo_mode=False):
        self.ip = ip
        self.username = username
        self.session = None
        self.is_connected = False
        self.is_simulation = False
        self.ruleset = ruleset  # windows_rules.json 또는 pc_rules.json 등
        self.throttle = throttle  # OT/저속 모드: 응답이 느려지면 자동으로 명령 간격을 늘림
        # [실전 안전장치] True일 때만 데모 IP를 가상 데이터로 처리한다. 기본값 False.
        self.demo_mode = demo_mode
        self.rules_path = self._get_rules_path()

    def _get_rules_path(self):
        filename = self.ruleset
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
        if self.demo_mode and self.ip in ["0.0.0.0", "127.0.0.2", "localhost"]:
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
        # [locale-safe 점검] secedit 기반 계정정책 점검(W-04/W-09/PC-01)은 실행 결과를 직접 흉내낸다.
        # 모의 데이터는 실제 PS 스크립트를 실행하지 않으므로, 스크립트의 "최종 반환값"에 맞춰 매핑한다.
        if "lockoutbadcount" in s: return "LockoutBadCount = 0"  # 잠금 임계값 미설정 -> 취약 예시
        # [criteria 데모] 최대 암호 사용기간은 충족(90일), 최소 길이는 미충족(0) -> 부분만족 예시
        if "maximumpasswordage" in s and "minimumpasswordlength" in s:
            return "MaximumPasswordAge = 90\r\nMinimumPasswordLength = 0"
        if "maximumpasswordage" in s: return "OK"
        if "minimumpasswordlength" in s: return "FAIL"
        # [criteria 데모] PC-01 세부기준 2: 만료 미설정 계정 존재 -> 부분만족 예시
        if "win32_useraccount" in s: return "Guest"
        if "administrator" in s: return "Name: Administrator, Enabled: True"
        if "guest" in s: return ""
        if "tlntsvr" in s: return "Status: Running"
        if "net accounts" in s: return "Lockout duration (minutes): 60"
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

        throttle = AdaptiveThrottle(enabled=self.throttle, base_delay=0.3)

        for rule in rules:
            code = rule['code']
            # [추가 1] KISA 코드
            kisa_code = rule.get('kisa_code', rule.get('code', ''))

            cmd = rule['command']
            # [추가 2] 증적 확보
            t0 = time.time()
            full_output = self.execute_ps(cmd)
            # [OT/저속 모드] 응답이 느려질수록 다음 명령 전 대기시간을 자동으로 늘림
            throttle.wait(time.time() - t0)

            # 판정 로직 (단일조건: 취약/양호/수동검토, 다중조건(criteria): 취약/부분만족/양호, 공통: 해당없음)
            status, detail = judge_rule(rule, full_output, execute_fn=self.execute_ps)

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

    def set_ruleset(self, ruleset):
        """연결된 세션을 유지한 채 점검 룰셋만 교체 (PC vs Server 재분류용)"""
        self.ruleset = ruleset
        self.rules_path = self._get_rules_path()

    def get_system_detail(self):
        """
        리포트의 'SYSTEM Detail' 부록용 원시 정보 수집 (시스템/IP/PORT/서비스).
        룰 판정과 무관한 참고용 증적이라 run_all_checks()와 분리된 메서드로 둔다.
        """
        if self.is_simulation:
            return {
                "os_info": "OS Name: Microsoft Windows Server 2019 Standard (Simulation)",
                "ip_info": "Ethernet adapter: 0.0.0.0",
                "port_info": "TCP    0.0.0.0:445    LISTENING\nTCP    0.0.0.0:3389   LISTENING",
                "service_info": "RemoteRegistry     Running\nSpooler            Running",
            }
        return {
            "os_info": self.execute_ps("systeminfo"),
            "ip_info": self.execute_ps("ipconfig /all"),
            "port_info": self.execute_ps("netstat -ano"),
            "service_info": self.execute_ps(
                "Get-Service | Where-Object {$_.Status -eq 'Running'} | Format-Table -AutoSize | Out-String -Width 200"
            ),
        }