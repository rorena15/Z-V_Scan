# scanner_engine/core/windows_inspector.py

import winrm
import re

class WindowsInspector:
    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password
        self.session = None
        self.is_connected = False

    def connect(self):
        """WinRM(5985)을 통해 Windows 서버 연결 시도"""
        try:
            # 기본 HTTP(5985) 연결 (내부망 환경)
            # read_timeout_sec: 응답 없을 시 무한 대기 방지 (5초)
            self.session = winrm.Session(
                f'http://{self.ip}:5985/wsman', 
                auth=(self.username, self.password),
                transport='ntlm',
                read_timeout_sec=5,
                operation_timeout_sec=5
            )
            # 연결 테스트 (hostname 명령 실행)
            result = self.session.run_cmd('hostname')
            if result.status_code == 0:
                self.is_connected = True
                return True
        except Exception as e:
            # 연결 실패 (로그는 상위 호출자에서 처리)
            pass
        return False

    def execute_ps(self, script):
        """PowerShell 스크립트 실행 및 결과 반환"""
        if not self.is_connected or not self.session: return ""
        try:
            # run_ps: 파워쉘 스크립트 실행
            rs = self.session.run_ps(script)
            if rs.status_code == 0:
                # 한글 깨짐 방지 및 공백 제거
                return rs.std_out.decode('utf-8', errors='ignore').strip()
            else:
                return rs.std_err.decode('utf-8', errors='ignore').strip()
        except Exception:
            return ""

    # --- [Windows 진단 항목: W-01 ~ W-03] ---
    
    def check_w01(self):
        """W-01: Administrator 계정 이름 변경 또는 비활성화 여부"""
        # Admin 계정이 활성화(Enabled=True)되어 있고 이름이 'Administrator' 그대로인지 확인
        cmd = "Get-LocalUser | Where-Object {$_.Name -eq 'Administrator' -and $_.Enabled -eq $True}"
        output = self.execute_ps(cmd)
        
        if "Administrator" in output:
            return "VULNERABLE", "기본 관리자(Administrator) 계정이 이름 변경 없이 활성화 상태입니다."
        return "SAFE", "Administrator 계정이 비활성화되었거나 이름이 변경되었습니다."

    def check_w02(self):
        """W-02: Guest 계정 비활성화 여부"""
        # Guest 계정이 활성화되어 있는지 확인
        cmd = "Get-LocalUser | Where-Object {$_.Name -eq 'Guest' -and $_.Enabled -eq $True}"
        output = self.execute_ps(cmd)
        
        if "Guest" in output:
            return "VULNERABLE", "Guest 계정이 활성화되어 있습니다. 보안상 비활성화해야 합니다."
        return "SAFE", "Guest 계정이 비활성화되어 있습니다."

    def check_w03(self):
        """W-03: 불필요한 서비스(Telnet, FTP) 실행 여부"""
        # Telnet 서비스 상태 확인
        cmd = "Get-Service -Name TlntSvr -ErrorAction SilentlyContinue | Select-Object Status"
        output = self.execute_ps(cmd)
        
        if "Running" in output:
            return "VULNERABLE", "보안에 취약한 Telnet 서비스가 실행 중입니다."
        return "SAFE", "Telnet 서비스가 실행 중이지 않습니다."

    def run_all_checks(self):
        """동적으로 check_wXX 메서드를 모두 찾아 실행 (확장성 확보)"""
        results = {}
        # 메서드 이름 중 'check_w'로 시작하는 것 자동 검색
        check_funcs = [method for method in dir(self) if method.startswith('check_w')]
        
        for func_name in check_funcs:
            # 예: check_w01 -> W-01 코드로 변환
            code = func_name.split('_')[1].upper().replace('W', 'W-')
            try:
                status, detail = getattr(self, func_name)()
                results[code] = (status, detail)
            except Exception as e:
                results[code] = ("Error", f"진단 중 오류 발생: {str(e)}")
                
        return results