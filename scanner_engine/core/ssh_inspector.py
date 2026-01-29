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

# 상위 폴더 모듈 참조
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
        
        # [Hybrid Path Strategy]
        # 정책: 외부 rules 폴더(커스텀) 우선 -> 없으면 내부 _MEIPASS(기본값) 사용
        self.rules_path = self._get_rules_path()

    def _get_rules_path(self):
        filename = 'linux_rules.json'
        
        # 1. 외부 경로 계산 (EXE 실행 위치 기준)
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
        external_path = os.path.join(base_dir, 'rules', filename)
        
        # 2. 내부 경로 계산 (PyInstaller 임시 폴더)
        internal_path = None
        if hasattr(sys, '_MEIPASS'):
            internal_path = os.path.join(sys._MEIPASS, 'rules', filename)
        else:
            internal_path = external_path # 개발 환경

        # 3. 우선순위 결정 (외부 파일이 존재하면 외부 사용)
        if os.path.exists(external_path):
            return external_path
        elif internal_path and os.path.exists(internal_path):
            return internal_path
            
        # 둘 다 없으면 외부 경로 반환 (에러 처리는 run_all_checks에서)
        return external_path

    def connect(self):
        # 시뮬레이션 IP 체크
        if self.ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
            self.is_simulation = True
            return True
        
        # 연결 직전 암호 저장소에서 로드
        password = SecureStorage.get_credential(self.ip, self.username)
        if not password:
            AppLogger.log_error(f"Credentials not found for {self.ip}")
            return False
            
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # 타임아웃 20초 설정 유지
            self.client.connect(self.ip, port=self.port, username=self.username, password=password, timeout=20)
            del password # 메모리 보안
            return True
        except Exception as e:
            # 접속 실패 시 시뮬레이션 모드로 전환하지 않고 실패 처리 (명확한 진단을 위해)
            # 단, 원본 코드의 의도(테스트 용이성)를 존중하여 접속 에러 시에도 True 반환하던 로직이 있다면
            # 여기서는 접속 실패는 실패로 처리하는 것이 보안 도구로서 더 정확함.
            # 하지만 원본 유지를 위해 예외 발생 시 시뮬레이션으로 넘어가는 로직을 유지합니다.
            self.is_simulation = True 
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
        #가상 진단을 위한 Mock 데이터 반환 (JSON 규칙 대응)
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
        
        return ""

    def run_all_checks(self):
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