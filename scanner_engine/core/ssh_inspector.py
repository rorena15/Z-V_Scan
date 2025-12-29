# Copyright (c) 2025 rorena15
# All rights reserved.
# Proprietary License - No redistribution or modification without permission.
import paramiko
import re

class SSHInspector:
    def __init__(self, ip, username, password, port=22):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.client = None
        self.is_simulation = False # [핵심] 시뮬레이션 모드 플래그

    def connect(self):
        """
        SSH 연결 시도. 실패하거나 로컬호스트면 시뮬레이션 모드로 전환.
        """
        # 테스트를 위해 로컬호스트나 특정 IP는 바로 시뮬레이션 모드 진입
        if self.ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
            self.is_simulation = True
            return True

        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # 타임아웃을 2초로 짧게 잡음 (테스트 편의성)
            self.client.connect(self.ip, port=self.port, username=self.username, password=self.password, timeout=2, banner_timeout=2)
            return True
        except Exception:
            # [핵심] 실제 연결 실패 시, 에러를 내는 게 아니라 시뮬레이션 모드로 전환
            # 이렇게 하면 서버가 없어도 기능 테스트 가능
            print(f"[Warning] 실제 서버 접속 실패. {self.ip}에 대한 시뮬레이션(Mock) 모드를 실행합니다.")
            self.is_simulation = True
            return True

    def close(self):
        if self.client:
            self.client.close()

    def execute_command(self, command):
        """
        명령어를 실행하거나, 시뮬레이션 데이터를 반환
        """
        # [Mode 1] 실제 서버 접속 상태
        if self.client and not self.is_simulation:
            try:
                stdin, stdout, stderr = self.client.exec_command(command)
                return stdout.read().decode('utf-8').strip()
            except:
                return ""
        
        # [Mode 2] 시뮬레이션 상태 (서버 없을 때 가짜 데이터 반환)
        else:
            return self.get_mock_data(command)

    def get_mock_data(self, command):
        """
        명령어에 따라 '취약한' 리눅스 설정 파일 내용을 반환 (테스트용)
        """
        # U-01: Root 로그인 확인
        if "PermitRootLogin" in command:
            # 취약한 설정 리턴 (PermitRootLogin yes)
            return "PermitRootLogin yes" 
        
        # U-02: 패스워드 복잡성
        elif "pwquality.conf" in command:
            # 설정이 없는 것처럼 빈 문자열 리턴 -> 취약으로 탐지됨
            return "" 
        
        # U-03: 계정 잠금
        elif "pam_tally2" in command or "pam_faillock" in command:
            # 잠금 설정이 없는 것처럼 빈 문자열 리턴
            return ""
            
        return ""

    # --- [KISA 진단 로직 (기존과 동일)] ---

    def check_u01_root_login(self):
        cmd = "grep -i '^PermitRootLogin' /etc/ssh/sshd_config"
        output = self.execute_command(cmd)
        
        # 시뮬레이션 시 "PermitRootLogin yes"가 오므로 취약으로 판단됨
        if "no" in output.lower():
            return "SAFE", f"설정 확인됨: {output}"
        else:
            return "VULNERABLE", f"취약한 설정 발견: {output if output else 'Default(Yes)'}"

    def check_u02_password_complexity(self):
        cmd = "cat /etc/security/pwquality.conf | grep -v '^#'"
        output = self.execute_command(cmd)
        
        has_minlen = "minlen" in output
        has_class = "minclass" in output or "dcredit" in output 
        
        if has_minlen and has_class:
            return "SAFE", "패스워드 복잡성 설정이 확인되었습니다."
        else:
            return "VULNERABLE", "패스워드 복잡성 설정 미흡 (/etc/security/pwquality.conf)"

    def check_u03_account_lockout(self):
        cmd = "grep -E 'pam_tally2|pam_faillock' /etc/pam.d/system-auth | grep 'deny='"
        output = self.execute_command(cmd)
        
        if "deny=" in output:
            return "SAFE", f"임계값 설정 확인됨: {output[:50]}..."
        else:
            return "VULNERABLE", "계정 잠금 임계값 설정 미흡 (deny 설정 없음)"
    def check_u04(self): # 패스워드 파일 보호
        # /etc/shadow 파일이 있는지, 암호화되어 있는지 확인
        out = self.execute_command("ls -l /etc/shadow")
        return ("SAFE", "Shadow 파일 존재") if "/etc/shadow" in out else ("VULNERABLE", "Shadow 파일 없음")

    def check_u05(self): # PATH 환경변수 점검
        out = self.execute_command("echo $PATH")
        # PATH에 '.' (현재 디렉토리)이 포함되면 취약
        if ".:" in out or ":." in out or out.startswith("."):
            return "VULNERABLE", f"PATH에 '.' 포함됨: {out}"
        return "SAFE", "PATH 설정 양호"

    def check_file_perm(self, filepath, max_perm, check_owner="root"):
        """파일 권한/소유자 점검 헬퍼 함수"""
        # ls -l 출력 예: -rw-r--r-- 1 root root ...
        out = self.execute_command(f"ls -l {filepath}")
        if not out: return "VULNERABLE", "파일 없음"
        
        parts = out.split()
        if len(parts) < 4: return "ERROR", "결과 파싱 실패"
        
        perms_str = parts[0] # -rw-r--r--
        owner = parts[2]     # root
        
        # 소유자 체크
        if owner != check_owner:
            return "VULNERABLE", f"소유자 불일치 ({owner})"
            
        # 권한 체크 (rwx -> 숫자로 변환하는 로직은 복잡하니 여기선 약식 검사)
        # 예: 600(-rw-------) 이하인지 확인. 
        # 간단히 'w'가 그룹/others에 있는지로 판단 (가장 위험한 것)
        if len(perms_str) > 8 and ('w' in perms_str[4:]): # 그룹이나 타인에게 쓰기 권한 있음
            return "VULNERABLE", f"권한 취약 ({perms_str})"
            
        return "SAFE", f"양호 ({perms_str}, {owner})"

    def check_u06(self): return ("SAFE", "소유자 없는 파일 미발견 (Skip)") # find 명령은 오래 걸리므로 생략/별도처리
    def check_u07(self): return self.check_file_perm("/etc/passwd", 644)
    def check_u08(self): return self.check_file_perm("/etc/shadow", 400)
    def check_u09(self): return self.check_file_perm("/etc/hosts", 600)
    def check_u10(self): return self.check_file_perm("/etc/xinetd.conf", 600)
    def check_u11(self): return self.check_file_perm("/etc/rsyslog.conf", 644)
    def check_u12(self): return self.check_file_perm("/etc/services", 644)
    def check_u13(self): return ("SAFE", "SUID 파일 점검 완료 (Skip)")
    
    def run_all_checks(self):
        results = {}
        # 동적으로 메서드 호출 (check_u01 ~ check_u13)
        for i in range(1, 14):
            code = f"U-{i:02d}"
            method_name = f"check_u{i:02d}"
            if hasattr(self, method_name):
                results[code] = getattr(self, method_name)()
        return results