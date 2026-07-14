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
import time

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.secure_storage import SecureStorage
from utils.logger import AppLogger
from utils.throttle import AdaptiveThrottle
from utils.rule_judge import judge_rule

class SSHInspector:
    def __init__(self, ip, username, port=22, ruleset="linux_rules.json", throttle=False, demo_mode=False):
        self.ip = ip
        self.username = username
        self.port = port
        self.client = None
        self.is_simulation = False
        self.ruleset = ruleset  # linux_rules.json 또는 web_rules.json 등
        self.throttle = throttle  # OT/저속 모드: 응답이 느려지면 자동으로 명령 간격을 늘림
        # [실전 안전장치] True일 때만 데모 IP/접속 실패 시 가상 데이터를 사용한다.
        # 기본값 False에서는 접속 실패를 절대 조용히 감추지 않고 정직하게 실패로 보고한다.
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
        if self.demo_mode and self.ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
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
            # [실전 안전장치] 데모 모드가 아니면 접속 실패를 절대 가짜 데이터로 감추지 않는다.
            if self.demo_mode:
                self.is_simulation = True
                return True
            AppLogger.log_error(f"[SSH] Connect failed for {self.ip}", e)
            return False

    def close(self):
        if self.client:
            try:
                self.client.close()
            except: pass
            self.client = None

    def execute_command(self, command, timeout=25):
        # [주의] find / 등 전체 파일시스템 탐색 명령이 룰셋에 포함되어 있어
        # 타임아웃 없이는 응답 없는 호스트에서 스캔 스레드가 무한 대기할 수 있음
        if self.client and not self.is_simulation:
            try:
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
                return stdout.read().decode('utf-8').strip()
            except Exception:
                return ""
        else:
            return self.get_mock_data(command)

    def get_mock_data(self, command):
        cmd = command.lower()
        # [criteria 데모] U-02 세부기준: 최소길이는 충족, 최대사용기간은 미충족 -> 부분만족 예시
        if "minlen" in cmd and "awk" in cmd: return "OK"
        if "pass_max_days" in cmd: return "FAIL"
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

        throttle = AdaptiveThrottle(enabled=self.throttle, base_delay=0.3)

        for rule in rules:
            code = rule['code']
            # [추가 1] KISA 코드 매핑 (없으면 내부 코드 사용)
            kisa_code = rule.get('kisa_code', rule.get('code', ''))

            cmd = rule['command']

            # [추가 2] 증적 확보 (명령어 실행 전체 결과)
            t0 = time.time()
            full_output = self.execute_command(cmd)
            # [OT/저속 모드] 응답이 느려질수록 다음 명령 전 대기시간을 자동으로 늘려
            # 대상 서버(특히 레거시/임베디드 장비)에 가해지는 부하를 유동적으로 조절
            throttle.wait(time.time() - t0)

            # 판정 로직 (단일조건: 취약/양호/수동검토, 다중조건(criteria): 취약/부분만족/양호, 공통: 해당없음)
            status, detail = judge_rule(rule, full_output, execute_fn=self.execute_command)

            # [핵심 수정] 6개 -> 7개 튜플 반환 (증적 + 중요도 포함)
            results[code] = (
                status,
                detail,
                rule.get('name', code),
                rule.get('remediation', ''),
                full_output,  # Raw Output (증적)
                kisa_code,    # KISA Code
                rule.get('importance', '중')  # 중요도 (상/중/하)
            )

        return results

    def get_system_detail(self):
        """
        리포트의 'SYSTEM Detail' 부록용 원시 정보 수집 (시스템/IP/PORT/서비스).
        룰 판정과 무관한 참고용 증적이라 run_all_checks()와 분리된 메서드로 둔다.
        """
        if self.is_simulation:
            return {
                "os_info": "Linux localhost 5.15.0 x86_64 GNU/Linux (Simulation)",
                "ip_info": "eth0: 127.0.0.1/8",
                "port_info": "tcp   0.0.0.0:22   LISTEN\ntcp   0.0.0.0:80   LISTEN",
                "service_info": "sshd.service       loaded active running\nnginx.service      loaded active running",
            }
        return {
            "os_info": self.execute_command("uname -a; cat /etc/os-release 2>/dev/null"),
            "ip_info": self.execute_command("ip addr show 2>/dev/null || ifconfig -a 2>/dev/null"),
            "port_info": self.execute_command("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"),
            "service_info": self.execute_command(
                "systemctl list-units --type=service --state=running --no-pager 2>/dev/null || service --status-all 2>/dev/null"
            ),
        }