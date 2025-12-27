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
            self.client.connect(self.ip, port=self.port, username=self.username, password=self.password, timeout=2)
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

    def run_all_checks(self):
        results = {}
        results['U-01'] = self.check_u01_root_login()
        results['U-02'] = self.check_u02_password_complexity()
        results['U-03'] = self.check_u03_account_lockout()
        return results