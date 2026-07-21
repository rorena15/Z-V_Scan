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
from utils.expert_profile import get_excluded_codes

class WindowsInspector:
    # [안정성] secedit 기반 룰들이 각자 자기 임시파일에 export/삭제를 반복하면
    # (특히 백신 실시간 검사와 겹칠 때) 간헐적으로 파일이 비어있거나 잠겨 판정이
    # 흔들리는 문제가 있어, 감사 시작 시 딱 한 번만 export한 뒤 모든 룰이 같은
    # 캐시 파일을 읽도록 공유한다.
    SECEDIT_CACHE_PATH = r"C:\zvulnscan_secpol_cache.cfg"

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

        # [보안] HTTPS(5986)를 먼저 시도해 NTLM 릴레이 공격에 취약한 인증 핸드셰이크를
        # TLS 채널 바인딩(send_cbt, pywinrm 기본값 True)으로 보호한다. 사내망 특성상
        # 자체 서명 인증서가 흔해 서버 인증서 신원 검증까지는 못 하지만(server_cert_
        # validation='ignore'), 그래도 채널 바인딩 자체는 그대로 적용된다. HTTPS
        # 리스너가 없는 대상(Enable-PSRemoting만 한 기본 설정, 흔한 케이스)은
        # HTTP(5985)로 폴백한다 - 이 경우도 pywinrm이 기본값(message_encryption=
        # 'auto')으로 NTLM 메시지 레벨 암호화는 이미 자동 적용한다.
        #
        # [실측 확인] HTTPS 리스너가 없는 대상은 TCP 연결 자체가 응답 없이 지연되므로,
        # 원래 타임아웃(30s)을 그대로 쓰면 대상마다 매번 불필요하게 30초씩 낭비된다.
        # HTTPS는 짧은 타임아웃으로 "가능 여부"만 빠르게 확인(probe)하고, 실제 점검에
        # 쓸 세션은 어느 쪽이 성공했든 항상 정상 타임아웃(30/25)으로 다시 만든다.
        endpoints = [
            (f'https://{self.ip}:5986/wsman', {'server_cert_validation': 'ignore'}, 4, 3),
            (f'http://{self.ip}:5985/wsman', {}, 30, 25),
        ]

        for url, extra_kwargs, probe_read_timeout, probe_op_timeout in endpoints:
            try:
                probe_session = winrm.Session(
                    url,
                    auth=(self.username, password),
                    transport='ntlm',
                    read_timeout_sec=probe_read_timeout,
                    operation_timeout_sec=probe_op_timeout,
                    **extra_kwargs
                )
                if probe_session.run_cmd('hostname').status_code == 0:
                    # 프로브 성공 - 실제 점검용 세션은 정상 타임아웃으로 별도 생성
                    self.session = winrm.Session(
                        url,
                        auth=(self.username, password),
                        transport='ntlm',
                        read_timeout_sec=30,
                        operation_timeout_sec=25,
                        **extra_kwargs
                    )
                    self.is_connected = True
                    del password
                    return True
            except Exception:
                continue
        return False

    def execute_ps(self, script):
        if self.is_simulation:
            return self.get_mock_data(script)

        if not self.is_connected:
            return None
        try:
            rs = self.session.run_ps(script)
            if rs.status_code == 0:
                try:
                    return rs.std_out.decode('utf-8').strip()
                except UnicodeDecodeError:
                    return rs.std_out.decode('cp949', errors='ignore').strip()
            else:
                # [판정 정확도] PowerShell 명령이 0이 아닌 종료코드로 실패함(예: secedit 캐시
                # 파일이 없어서 Select-String이 실패, cmdlet 모듈 없음 등) - "정상 실행됐지만
                # 결과가 없음"(빈 문자열)과 절대 혼동하면 안 되므로 None을 반환해 judge_rule이
                # SAFE가 아니라 MANUAL로 판정하도록 구분한다.
                AppLogger.log_error(f"[WinRM] PS command failed (exit={rs.status_code}): {script[:80]}")
                return None
        except Exception as e:
            AppLogger.log_error(f"[WinRM] PS execution error: {script[:80]}", e)
            return None

    def get_mock_data(self, script):
        s = script.lower()
        # [locale-safe 점검] secedit/reg query 기반 점검(W-04/W-08/W-09/W-11/W-12/W-14/W-40/W-41/PC-01/PC-02 등)은
        # 실제 PS 스크립트를 실행하지 않으므로, 스크립트가 최종적으로 반환할 값(OK/FAIL 센티널 또는 원문 텍스트)에
        # 맞춰 흉내낸다. 모든 secedit 룰이 공유 캐시 파일(zvulnscan_secpol_cache.cfg)을 읽으므로 임시파일명 대신
        # 조회 키 이름(들)의 조합으로 MAIN(원문 덤프)과 개별 criteria(OK/FAIL 판정)를 구분한다.
        # [중요] 여러 키를 한 번에 조회하는 "조합 확인"을 먼저 검사하고, 그 다음에 단일 키 확인으로 내려가야 한다.

        # ---- W-08 계정 잠금 기간 (MAIN: 2개 키 동시 조회, criteria: 단일 키 + OK/FAIL) ----
        if "lockoutduration" in s and "resetlockoutcount" in s:
            return "LockoutDuration = 60\r\nResetLockoutCount = 30"
        if "lockoutduration" in s: return "OK"    # criteria: LockoutDuration >= 60
        if "resetlockoutcount" in s: return "FAIL"  # criteria: ResetLockoutCount < 60 -> 부분만족 예시

        # ---- W-04 계정 잠금 임계값 ----
        if "lockoutbadcount" in s: return "LockoutBadCount = 0"  # 잠금 임계값 미설정 -> 취약 예시

        # ---- PC-02 비밀번호 관리정책 (MAIN: 2개 키 동시 조회) - W-09 단일 키 검사보다 먼저 확인해야 함 ----
        if "minimumpasswordlength" in s and "passwordcomplexity" in s:
            return "MinimumPasswordLength = 8\r\nPasswordComplexity = 0"

        # ---- W-09 비밀번호 관리정책 (MAIN: 2개 키 동시 조회, criteria: 단일 키 + OK/FAIL, 5개) ----
        if "maximumpasswordage" in s and "minimumpasswordlength" in s:
            return "MaximumPasswordAge = 90\r\nMinimumPasswordLength = 0"
        if "maximumpasswordage" in s: return "OK"    # criteria: MaximumPasswordAge <= 90
        if "minimumpasswordlength" in s: return "FAIL"  # criteria: MinimumPasswordLength < 8 -> 부분만족 예시
        if "minimumpasswordage" in s: return "OK"    # criteria: MinimumPasswordAge >= 1
        if "passwordhistorysize" in s: return "OK"   # criteria: PasswordHistorySize > 0
        if "passwordcomplexity" in s: return "OK"    # criteria(W-09/PC-02 공용): PasswordComplexity == 1

        # ---- W-11 로컬 로그온 허용 (Administrators SID만 허용) ----
        if "seinteractivelogonright" in s: return "OK"

        # ---- W-12 익명 SID/이름 변환 허용 해제 ----
        if "lsaanonymousnamelookup" in s: return "0"  # 비활성화(0) -> 양호 예시

        # ---- W-14 원격터미널 접속 그룹 제한 (fDenyTSConnections / SeRemoteInteractiveLogonRight) ----
        if "fdenytsconnections" in s: return "DISABLED_OK"  # 원격 데스크톱 비활성화 -> 양호 예시

        # ---- W-06 관리자 그룹 최소 인원 (SID 기반) ----
        if "get-localgroupmember" in s and "s-1-5-32-544" in s: return "Name: Administrator, ObjectClass: User\r\nOK"

        # ---- W-28 터미널 서비스 암호화 수준 (MinEncryptionLevel >= 2) ----
        if "minencryptionlevel" in s: return "OK"

        # ---- W-36 원격터미널 접속 타임아웃 (MaxIdleTime <= 900000ms) ----
        if "maxidletime" in s: return "OK"

        # ---- W-39/W-45 백신 설치 (Defender 서비스 또는 서드파티 프로세스) ----
        if "mcshield" in s or "windefend" in s: return "OK"

        # ---- W-40 감사 정책 (MAIN: 6개 키 동시 조회, criteria: 단일 키 + OK/FAIL, 6개) ----
        if "auditaccountmanage" in s and "auditlogonevents" in s:
            return "AuditAccountManage = 3\r\nAuditLogonEvents = 0\r\nAuditDSAccess = 3\r\nAuditAccountLogon = 3\r\nAuditSystemEvents = 3\r\nAuditPolicyChange = 3"
        if "auditaccountmanage" in s: return "OK"
        if "auditlogonevents" in s: return "FAIL"  # -> 부분만족 예시
        if "auditdsaccess" in s: return "OK"
        if "auditaccountlogon" in s: return "OK"
        if "auditsystemevents" in s: return "OK"
        if "auditpolicychange" in s: return "OK"

        # ---- W-41 NTP 시각 동기화 (NtpServer 레지스트리 값) ----
        if "ntpserver" in s: return "FAIL"  # 값 미설정 -> 취약 예시

        # ---- W-46 SAM 파일 접근 통제 (Administrators/SYSTEM 화이트리스트) ----
        if "config\\sam" in s: return "OK"

        # ---- W-51 SAM/공유 익명 열거 제한 (RestrictAnonymous / RestrictAnonymousSAM) ----
        if "restrictanonymoussam" in s: return "RestrictAnonymousSAM    REG_DWORD    0x1"
        if "restrictanonymous" in s: return "RestrictAnonymous    REG_DWORD    0x1"

        # ---- W-53 이동식 미디어 포맷 (AllocateDASD / SeManageVolumePrivilege) ----
        if "semanagevolumeprivilege" in s: return "OK"
        if "allocatedasd" in s: return "AllocateDASD    REG_SZ    0"

        # ---- W-54 DoS 방어 (IPEnableRouter) ----
        if "ipenablerouter" in s: return "IPEnableRouter    REG_DWORD    0x0"

        # ---- W-56 SMB 세션 중단 (EnableForcedLogOff / AutoDisconnect) ----
        if "enableforcedlogoff" in s and "autodisconnect" in s:
            return "EnableForcedLogOff    REG_DWORD    0x1\r\nAutoDisconnect    REG_DWORD    0xf"
        if "enableforcedlogoff" in s: return "EnableForcedLogOff    REG_DWORD    0x1"
        if "autodisconnect" in s: return "OK"

        # ---- W-57 로그온 경고 메시지 (Policies\\System 우선, Winlogon 폴백) ----
        if "get-regval" in s and "legalnoticecaption" in s: return "OK"
        if "get-regval" in s and "legalnoticetext" in s: return "OK"
        if "legalnoticecaption" in s or "legalnoticetext" in s:
            return "LegalNoticeCaption    REG_SZ    보안 경고\r\nLegalNoticeText    REG_SZ    비인가 접근을 금지합니다"

        # ---- W-59 LAN Manager 인증 수준 (LmCompatibilityLevel >= 3) ----
        if "lmcompatibilitylevel" in s: return "OK"

        # ---- W-60 보안 채널 서명/암호화 (RequireSignOrSeal/SealSecureChannel/SignSecureChannel) ----
        if "sealsecurechannel" in s: return "SealSecureChannel    REG_DWORD    0x1"
        if "signsecurechannel" in s: return "SignSecureChannel    REG_DWORD    0x1"
        if "requiresignorseal" in s: return "RequireSignOrSeal    REG_DWORD    0x1"

        # ---- W-64 윈도우 방화벽 (Domain/Private/Public 3개 프로필) ----
        if "-profile domain" in s: return "True"
        if "-profile private" in s: return "False"  # 부분만족 예시
        if "-profile public" in s: return "True"
        if "get-netfirewallprofile" in s: return "Name: Domain, Enabled: True\r\nName: Private, Enabled: False\r\nName: Public, Enabled: True"

        # ---- PC-01 비밀번호 주기적 변경 (criteria 1: MaximumPasswordAge, W-09 공용 규칙으로 처리됨) ----
        # [criteria 데모] PC-01 세부기준 2: 만료 미설정 계정 존재 -> 부분만족 예시
        if "win32_useraccount" in s: return "Guest"

        # ---- PC-04 공유폴더 제거 (Win32_Share Everyone 점검) ----
        if "win32_share" in s: return "OK"

        # ---- PC-06 비인가 메신저 (설치 폴더/WindowsApps/서비스/GPO) ----
        if "kakaotalk" in s: return "OK"
        if "windowsapps" in s: return "OK"
        if "preventrun" in s: return "OK"

        # ---- PC-09 브라우저 종료 시 데이터 삭제 (Edge ClearBrowsingDataOnExit) ----
        if "clearbrowsingdataonexit" in s: return "ClearBrowsingDataOnExit    REG_DWORD    0x1"

        # ---- PC-13/PC-14 백신 (SecurityCenter2, productState로 구분) ----
        if "productstate" in s: return "OK"          # PC-14: 실시간 감시 활성화
        if "securitycenter2" in s: return "OK"       # PC-13: 백신 등록됨

        # ---- PC-15 방화벽 서비스 상태 ----
        if "mpssvc" in s: return "Running"

        # ---- PC-16 화면보호기 (ScreenSaveActive/ScreenSaverIsSecure/ScreenSaveTimeOut) ----
        if "screensavetimeout" in s: return "ScreenSaveTimeOut    REG_SZ    300"
        if "screensaverissecure" in s: return "ScreenSaverIsSecure    REG_SZ    1"
        if "screensaveactive" in s: return "ScreenSaveActive    REG_SZ    1"

        # ---- PC-17 이동식 미디어 자동실행 (DisableAutoplay/cdrom AutoRun) ----
        if "disableautoplay" in s: return "DisableAutoplay    REG_DWORD    0x1"
        if "cdrom" in s: return "OK"
        if "nodrivetypeautorun" in s: return "NoDriveTypeAutoRun    REG_DWORD    0xff"

        # ---- PC-18 원격 지원 금지 (fAllowUnsolicited) ----
        if "fallowunsolicited" in s: return "fAllowUnsolicited    REG_DWORD    0x0"

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

        # [Phase 3: 전문가 모드] 사용자가 이 룰셋에서 제외한 코드는 아예 실행하지 않는다
        excluded_codes = get_excluded_codes(self.ruleset)
        if excluded_codes:
            rules = [r for r in rules if r['code'] not in excluded_codes]

        throttle = AdaptiveThrottle(enabled=self.throttle, base_delay=0.3)

        def _uses_cache(rule):
            if self.SECEDIT_CACHE_PATH in rule.get('command', ''):
                return True
            return any(self.SECEDIT_CACHE_PATH in c.get('command', '') for c in rule.get('criteria', []))
        needs_secedit = any(_uses_cache(rule) for rule in rules)
        if needs_secedit:
            self._prime_secedit_cache()

        try:
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
        finally:
            if needs_secedit:
                self._cleanup_secedit_cache()

        return results

    def _prime_secedit_cache(self):
        if self.is_simulation:
            return
        self.execute_ps(f'secedit /export /cfg {self.SECEDIT_CACHE_PATH} | Out-Null')

    def _cleanup_secedit_cache(self):
        if self.is_simulation:
            return
        self.execute_ps(f'Remove-Item {self.SECEDIT_CACHE_PATH} -Force -ErrorAction SilentlyContinue')

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
                "os_info": "Host Name:                 SIM-WIN-HOST\r\nOS Name:                   Microsoft Windows Server 2019 Standard (Simulation)",
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