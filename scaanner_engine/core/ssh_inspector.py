import paramiko
import logging

class SSHInspector:
    def __init__(self, host, port=22, username="root", password="password"):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client = None
        
        logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
        self.logger = logging.getLogger("SSH_Inspector")

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.host, port=self.port, username=self.username, password=self.password, timeout=5)
            return True
        except Exception as e:
            self.logger.error(f"Connection Failed: {e}")
            return False

    def close(self):
        if self.client:
            self.client.close()

    def execute_command(self, command):
        if not self.client:
            return None
        stdin, stdout, stderr = self.client.exec_command(command)
        return stdout.read().decode().strip()

    def check_u01_root_login(self):
        #[KISA U-01] root 계정 원격 접속 제한 점검
        #판단기준: /etc/ssh/sshd_config 파일에서 'PermitRootLogin no' 설정 여부 확인
        self.logger.info(f"[*] Checking U-01 (Root Login Restriction) on {self.host}...")
        
        # 주석(#) 제외하고 설정값 조회
        cmd = "grep -i '^PermitRootLogin' /etc/ssh/sshd_config"
        result = self.execute_command(cmd)

        if not result:
            # 설정이 아예 없으면 기본값이 OS마다 다르나, 보안상 명시적 설정을 권장하므로 '취약'으로 간주 가능
            # 여기서는 '설정 미발견'으로 처리
            self.logger.warning("   Result: [Warning] 'PermitRootLogin' setting not found (Default used).")
            return "WARNING", "Configuration not explicitly set."

        # 결과 파싱 (예: PermitRootLogin yes)
        parts = result.split()
        if len(parts) >= 2:
            value = parts[1].lower()
            if value == "no":
                self.logger.info("   Result: [SAFE] Root login is disabled.")
                return "SAFE", result
            else:
                self.logger.warning(f"   Result: [VULNERABLE] Root login is allowed ({value}).")
                return "VULNERABLE", result
        
        return "ERROR", "Parse Error"

# --- 테스트 코드 ---
if __name__ == "__main__":
    # 테스트할 리눅스 서버 정보 입력 (가상머신 또는 WSL)
    target_ip = "192.168.0.10" 
    target_user = "root"  # 또는 sudo 권한이 있는 계정
    target_pw = "toor"
    
    inspector = SSHInspector(target_ip, username=target_user, password=target_pw)
    
    if inspector.connect():
        print(f"\n--- Starting Audit for {target_ip} ---")
        
        # U-01 점검 수행
        status, detail = inspector.check_u01_root_login()
        print(f"U-01 Status: {status}")
        print(f"Detail: {detail}")
        
        inspector.close()
    else:
        print("SSH connection failed. Check IP or Creds.")