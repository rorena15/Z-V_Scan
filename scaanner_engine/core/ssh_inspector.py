import paramiko
import re

class SSHInspector:
    def __init__(self, ip, username, password, port=22):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.client = None

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.ip, port=self.port, username=self.username, password=self.password, timeout=3)
            return True
        except Exception as e:
            # print(f"SSH Connection Failed: {e}")
            return False

    def close(self):
        if self.client:
            self.client.close()

    def execute_command(self, command):
        """SSH 명령 실행 및 결과 반환 헬퍼 함수"""
        if not self.client: return ""
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            return stdout.read().decode('utf-8').strip()
        except:
            return ""

    # --- [KISA 진단 항목] ---

    def check_u01_root_login(self):
        """[U-01] root 계정 원격 접속 제한"""
        try:
            # sshd_config 파일 내용을 읽어옴 (주석 제외)
            cmd = "grep -i '^PermitRootLogin' /etc/ssh/sshd_config"
            output = self.execute_command(cmd)
            
            if "no" in output.lower():
                return "SAFE", f"설정 확인됨: {output}"
            else:
                return "VULNERABLE", f"취약한 설정: {output if output else '설정 없음(Default Yes)'}"
        except Exception as e:
            return "ERROR", str(e)

    def check_u02_password_complexity(self):
        """[U-02] 패스워드 복잡성 설정 (pwquality.conf or system-auth)"""
        try:
            # RHEL/CentOS 7 이상 기준 (pwquality.conf)
            cmd = "cat /etc/security/pwquality.conf | grep -v '^#'"
            output = self.execute_command(cmd)
            
            # 간단 체크: minlen(길이)과 minclass(문자종류) 확인
            # 실제로는 더 복잡하지만 프로토타입용 로직
            has_minlen = "minlen" in output
            has_class = "minclass" in output or "dcredit" in output 
            
            if has_minlen and has_class:
                return "SAFE", "패스워드 복잡성 설정이 확인되었습니다."
            else:
                return "VULNERABLE", "복잡성 설정(minlen, minclass 등)이 /etc/security/pwquality.conf에서 발견되지 않음"
        except Exception as e:
            return "ERROR", str(e)

    def check_u03_account_lockout(self):
        """[U-03] 계정 잠금 임계값 설정 (pam_tally2 or faillock)"""
        try:
            # system-auth 파일에서 deny=5 같은 설정 찾기
            cmd = "grep -E 'pam_tally2|pam_faillock' /etc/pam.d/system-auth | grep 'deny='"
            output = self.execute_command(cmd)
            
            if "deny=" in output:
                # deny=5 설정 값을 추출해서 보여줌
                return "SAFE", f"임계값 설정 확인됨: {output[:50]}..."
            else:
                return "VULNERABLE", "계정 잠금 정책(deny=N)이 설정되어 있지 않습니다."
        except Exception as e:
            return "ERROR", str(e)

    def run_all_checks(self):
        """모든 진단 함수를 한 번에 실행하고 딕셔너리로 반환"""
        results = {}
        
        # 1. U-01
        status, detail = self.check_u01_root_login()
        results['U-01'] = (status, detail)
        
        # 2. U-02
        status, detail = self.check_u02_password_complexity()
        results['U-02'] = (status, detail)
        
        # 3. U-03
        status, detail = self.check_u03_account_lockout()
        results['U-03'] = (status, detail)
        
        return results