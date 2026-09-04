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
import shlex
import sys
import time

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.secure_storage import SecureStorage
from utils.logger import AppLogger
from utils.throttle import AdaptiveThrottle
from utils.rule_judge import judge_rule
from utils.expert_profile import get_excluded_codes
from utils import rule_crypto
from core.config import AppConfig

class SSHInspector:
    def __init__(self, ip, username, port=22, ruleset="linux_rules.json", throttle=False, demo_mode=False, timeout=20, stop_check=None):
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
        # [Stop 버그 수정, 2026-09] run_all_checks()의 룰 루프(60~90개 명령)는 예전엔
        # 중간에 멈출 방법이 전혀 없었다 - ScanWorker.stop_flag는 인스펙터 "사이"에서만
        # 확인돼서, 사용자가 Stop을 눌러도 지금 실행 중인 인스펙터의 남은 명령을 전부
        # 끝내야 실제로 멈췄다(호스트 하나당 수십 개 명령 × 타임아웃까지 걸릴 수 있어
        # "Stop이 안 먹는다"로 체감됨). worker.py가 lambda: self.stop_flag를 넘겨주면
        # 매 룰마다 확인해 즉시 빠져나간다 - None(기본값)이면 지금까지처럼 계속 실행
        # (다른 곳에서 직접 생성하는 호출부는 하위호환).
        self.stop_check = stop_check
        # [스캔 설정 - 타임아웃 노출, 2026-09] 예전엔 접속 타임아웃(20초)이 고정이라
        # 응답 느린 레거시/OT 장비는 사용자가 조정할 방법이 없었다 - Scan Configuration
        # 카드에서 넘어온 값(기본값은 그대로 20이라 하위호환). execute_command()의
        # 명령 타임아웃(기존 25초)은 이 값+5초로 계산해 기존 "접속보다 5초 여유"
        # 관계를 그대로 유지한다.
        self.timeout = timeout
        self.rules_path = self._get_rules_path()

    def _get_rules_path(self):
        return rule_crypto.resolve_rules_path(self.ruleset)

    @staticmethod
    def _get_known_hosts_path():
        # [보안] 이전에는 AutoAddPolicy만 쓰고 호스트 키를 어디에도 저장하지 않아,
        # 매 스캔마다 "처음 보는 키"로 취급되어 MITM 탐지가 사실상 전혀 동작하지 않았다.
        # known_hosts 파일에 영구 저장해서, 이후 같은 IP에 다른 키가 나타나면
        # (실제 MITM 또는 대상 재설치) paramiko가 접속 자체를 자동으로 거부하게 한다.
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        config_dir = os.path.join(base_dir, 'config')
        try:
            os.makedirs(config_dir, exist_ok=True)
        except OSError:
            pass
        return os.path.join(config_dir, 'known_hosts')

    @staticmethod
    def list_known_hosts():
        # [설정 화면용] known_hosts에 등록된 호스트 목록을 (IP, 키타입 목록) 형태로 반환한다.
        # 대상 서버가 정상적으로 재설치돼 호스트 키가 바뀐 경우, 사용자가 어떤 IP가
        # 등록돼 있는지 확인하고 개별/전체 삭제할 수 있어야 파일을 직접 편집하지 않아도 된다.
        path = SSHInspector._get_known_hosts_path()
        if not os.path.exists(path):
            return []
        hk = paramiko.HostKeys()
        try:
            hk.load(path)
        except Exception:
            return []
        result = []
        for hostname in hk.keys():
            key_types = list(hk[hostname].keys())
            result.append((hostname, key_types))
        return sorted(result, key=lambda x: x[0])

    @staticmethod
    def remove_known_host(hostname):
        path = SSHInspector._get_known_hosts_path()
        if not os.path.exists(path):
            return False
        hk = paramiko.HostKeys()
        try:
            hk.load(path)
        except Exception:
            return False
        if hostname not in hk:
            return False
        del hk[hostname]
        hk.save(path)
        return True

    @staticmethod
    def clear_known_hosts():
        path = SSHInspector._get_known_hosts_path()
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                return False
        return True

    def connect(self):
        if self.demo_mode and self.ip in AppConfig.DEMO_SIMULATION_IPS:
            self.is_simulation = True
            return True

        password = SecureStorage.get_credential(self.ip, self.username)
        if not password:
            AppLogger.log_error(f"Credentials not found for {self.ip}")
            return False

        known_hosts_path = self._get_known_hosts_path()
        try:
            self.client = paramiko.SSHClient()
            if os.path.exists(known_hosts_path):
                try:
                    self.client.load_host_keys(known_hosts_path)
                except Exception as e:
                    # [버그 수정] 예전엔 known_hosts가 손상됐을 때 조용히 넘어가서,
                    # 파일은 있는데 핀 고정된 키가 하나도 안 실린 채로
                    # AutoAddPolicy가 "처음 보는 호스트"처럼 새 키를 그냥 받아들이고
                    # 재저장해버렸다 - TOFU/MITM 방지가 표시 없이 무력화되는 상태였다.
                    # 최소한 로그로 남겨서 "이번 접속은 호스트 키 검증이 사실상
                    # 안 됐다"는 걸 감사 로그에서 확인할 수 있게 한다.
                    AppLogger.log_error(
                        f"[SSH] known_hosts 파일을 읽지 못했습니다({known_hosts_path}) - "
                        f"이번 접속은 기존 핀 고정 키 없이 진행됩니다(MITM 탐지 약화). "
                        f"파일이 손상됐을 수 있으니 확인하세요.", e
                    )
            # 최초 접속(known_hosts에 없는 IP)만 자동 등록하고, 이후 저장해둔 키와
            # 다른 키가 나오면 client.connect()가 BadHostKeyException으로 자동 거부한다.
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.ip, port=self.port, username=self.username, password=password, timeout=self.timeout)
            try:
                self.client.save_host_keys(known_hosts_path)
            except Exception:
                pass
            del password
            return True
        except paramiko.ssh_exception.BadHostKeyException as e:
            # [보안 경고] 이전에 저장해둔 호스트 키와 다르다 - MITM 가능성 또는 대상 재설치.
            # 데모 모드여도 이 경우는 절대 가짜 데이터로 넘기지 않는다 (진짜 보안 이벤트일 수 있음).
            AppLogger.log_error(
                f"[SSH] SECURITY WARNING: Host key mismatch for {self.ip} - possible MITM attack "
                f"or the target was reinstalled. Refusing connection.", e
            )
            return False
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

    def execute_command(self, command, timeout=None, use_sudo=False):
        # [주의] find / 등 전체 파일시스템 탐색 명령이 룰셋에 포함되어 있어
        # 타임아웃 없이는 응답 없는 호스트에서 스캔 스레드가 무한 대기할 수 있음
        if timeout is None:
            timeout = self.timeout + 5
        if self.client and not self.is_simulation:
            try:
                actual_command = command
                if use_sudo:
                    # [권한 상승] "privileged" 룰(예: find / 전체 탐색)은 일반 계정으로
                    # 돌리면 접근 불가 디렉터리를 조용히 건너뛰어 취약 항목을 놓칠 수 있다.
                    # sudo -n(비밀번호 재요구 없음)만 시도한다 - NOPASSWD로 설정된
                    # 전용 감사 계정이면 승격되고, 아니면 즉시 실패해서 원래 계정
                    # 권한으로 그대로 폴백한다. 비밀번호를 stdin/커맨드라인으로 넘기는
                    # 방식은 프로세스 목록 등에 노출될 위험이 있어 의도적으로 쓰지 않는다.
                    quoted = shlex.quote(command)
                    actual_command = f"sudo -n sh -c {quoted} 2>/dev/null || sh -c {quoted}"
                stdin, stdout, stderr = self.client.exec_command(actual_command, timeout=timeout)
                return stdout.read().decode('utf-8').strip()
            except Exception:
                # [버그 수정] 예전엔 실행 실패도 ""(정상 실행+결과없음)와 똑같이
                # 취급해서, judge_rule()이 "값이 없으니 안전"으로 오판정했다.
                # windows_inspector/database_inspector와 동일하게 실패는 None으로
                # 명확히 구분해서 반환한다 - MANUAL로 빠지게 하기 위함.
                return None
        else:
            return self.get_mock_data(command)

    def get_mock_data(self, command):
        cmd = command.lower()

        # ------------------------------------------------------------------
        # [신규/수정 룰 데모 매핑]
        # 아래 항목들은 실제로는 원격 쉘에서 OK/FAIL/SAFE/VULNERABLE 등의
        # 최종 판정 문자열을 자체적으로 산출하는 셸 스니펫이므로, 시뮬레이션
        # 모드에서는 그 최종 산출 문자열을 흉내내어 반환한다(중간 계산 과정
        # 자체를 파이썬으로 재현하지 않음). 더 구체적인 패턴을 먼저 검사해
        # 기존의 범용 패턴(permitrootlogin 등)에 가로채이지 않도록 한다.
        # ------------------------------------------------------------------

        # U-01: SSH PermitRootLogin(메인+drop-in) 세부기준 / Telnet securetty 세부기준
        if "sshd_config.d" in cmd and "permitrootlogin" in cmd:
            return "FAIL"
        if "securetty" in cmd:
            return ""  # pts/ 항목 없음 -> 양호

        # U-02: 비밀번호 정책 세부기준(criteria) 데모 - 5개 중 3개 충족 -> 부분만족 예시
        if "minlen" in cmd and "awk" in cmd: return "OK"
        if "pass_max_days" in cmd: return "FAIL"
        if "pass_min_days" in cmd: return "OK"
        if "dcredit" in cmd: return "FAIL"
        if "pwhistory" in cmd: return "FAIL"

        # U-03: 계정 잠금 임계값(faillock/tally2 통합 numeric 체크)
        if "faillock.conf" in cmd: return "OK"

        # U-06: su 제한 세부기준(PAM wheel / 바이너리 권한)
        if "pam_wheel" in cmd: return "auth required pam_wheel.so use_uid group=wheel"
        if "stat -c %g" in cmd: return "OK"

        # U-13: 비밀번호 암호화 알고리즘(ENCRYPT_METHOD 미설정 시 shadow 해시 보조검증)
        if "encrypt_method" in cmd: return "OK"

        # U-16/18/19/20/21/22/29/37/63: 파일 권한 numeric 체크(stat -c %a 기반)
        if "stat -c %a /etc/passwd" in cmd: return "OK"
        if "stat -c %a /etc/shadow" in cmd: return "OK"
        if "stat -c %a /etc/hosts " in cmd or "stat -c %a /etc/hosts 2" in cmd: return "OK"
        if "xinetd.conf; do" in cmd: return "OK"
        if "rsyslog.conf /etc/syslog.conf" in cmd: return "OK"
        if "stat -c %a /etc/services" in cmd: return "OK"
        if "hosts.lpd" in cmd: return "OK"
        if "usr/bin/crontab /bin/crontab" in cmd: return "OK"
        if "stat -c %a /etc/sudoers" in cmd: return "OK"

        # U-30: umask(파일 다중 확인, 8진수 변환 비교)
        if "profile /etc/login.defs /etc/bashrc" in cmd: return "OK"

        # U-34/38/39/42/43/44/52/58: systemd 단독 의존 제거(다중 신호 통합) 서비스 점검
        if "fingerd" in cmd: return "SAFE"
        if "chargen" in cmd: return "SAFE"
        if "nfs-server" in cmd and "grep -i nfs" in cmd: return "SAFE"
        if "kcms_server" in cmd: return ""  # RPC_FOUND 미포함 -> 양호
        if "ypserv ypbind" in cmd: return "SAFE"
        if "ntalk" in cmd: return "SAFE"
        if "telnetd" in cmd: return "SAFE"
        if "nmptrapd" in cmd: return "SAFE"

        # ------------------------------------------------------------------
        # WEB 룰(web_rules.json)도 동일 SSHInspector를 통해 실행되므로 함께 매핑
        # ------------------------------------------------------------------
        if "autoindex" in cmd: return "SAFE"
        if "allowoverride[[:space:]]+none" in cmd: return ""  # None 미설정 -> 세부기준 충족
        if "allowoverride[[:space:]]+(authconfig|all)" in cmd: return "AllowOverride AuthConfig"
        if "limitrequestbody|client_max_body_size" in cmd: return "OK"
        if "context.xml" in cmd: return "OK"
        if "nginx.conf; do" in cmd: return "OK"
        if "servertokens" in cmd: return "SAFE"
        if "dav_methods" in cmd: return "SAFE"
        if "apache_on=" in cmd: return "OK"
        if "apache_r=" in cmd: return "OK"

        # [criteria 데모] U-02 세부기준: 최소길이는 충족, 최대사용기간은 미충족 -> 부분만족 예시
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

        # 룰 파일 로드 (배포판에서는 rules_path + ".enc"가 암호화돼 있고,
        # rule_crypto.load_ruleset()이 그걸 우선 찾아 복호화한다 - 개발 환경처럼
        # .enc가 없으면 평문 rules_path로 자동 폴백)
        try:
            rules = rule_crypto.load_ruleset(self.rules_path)
        except FileNotFoundError:
            AppLogger.log_error(f"Linux rules file not found: {self.rules_path}")
        except Exception as e:
            AppLogger.log_error(f"Failed to load linux rules: {e}")

        throttle = AdaptiveThrottle(enabled=self.throttle, base_delay=0.3)
        # [Phase 3: 전문가 모드] 사용자가 이 룰셋에서 제외한 코드는 아예 실행하지 않는다
        excluded_codes = get_excluded_codes(self.ruleset)

        for rule in rules:
            if self.stop_check and self.stop_check():
                break
            code = rule['code']
            if code in excluded_codes:
                continue
            # [추가 1] KISA 코드 매핑 (없으면 내부 코드 사용)
            kisa_code = rule.get('kisa_code', rule.get('code', ''))

            cmd = rule['command']

            # [추가 2] 증적 확보 (명령어 실행 전체 결과)
            t0 = time.time()
            full_output = self.execute_command(cmd, use_sudo=rule.get('privileged', False))
            # [OT/저속 모드] 응답이 느려질수록 다음 명령 전 대기시간을 자동으로 늘려
            # 대상 서버(특히 레거시/임베디드 장비)에 가해지는 부하를 유동적으로 조절
            throttle.wait(time.time() - t0)

            # 판정 로직 (단일조건: 취약/양호/수동검토, 다중조건(criteria): 취약/부분만족/양호, 공통: 해당없음)
            status, detail = judge_rule(rule, full_output, execute_fn=self.execute_command)

            # [증적 보강] 상당수 룰의 command가 "echo OK/FAIL" 식으로 판정용 센티널만
            # 내놓기 때문에(예: U-03/U-12/U-37/U-43/U-52/U-58/U-62), 그 값을 그대로
            # Raw Output(리포트 상세 증적)으로 저장하면 리포트에 "FAIL"/"VULNERABLE"라는
            # 글자만 남고 실제 근거(설정값/프로세스/파일 등)가 안 보인다(실측 확인됨).
            # evidence_command가 있으면 그 결과를 사람이 볼 raw_output으로 우선 사용한다 -
            # windows_inspector.py에 이미 적용한 것과 동일한 원칙. 판정(judge_rule)은
            # 여전히 위에서 top-level full_output만으로 이미 끝났으므로 판정 결과에는
            # 영향이 없다.
            evidence_command = rule.get('evidence_command')
            report_evidence = full_output
            if evidence_command:
                report_evidence = self.execute_command(evidence_command, use_sudo=rule.get('privileged', False))
                if report_evidence is None:
                    report_evidence = full_output

            # [현황 보강] utils/rule_judge.py의 _single_condition_result()는 양호일 때
            # 실제 값과 무관하게 "양호 (점검 완료)"만 반환한다(취약일 때는 그나마
            # "{safe_keyword} 누락"/취약 값 일부라도 detail에 남는데, 양호는 내용이
            # 전혀 없음 - 실측 확인됨). evidence_command로 얻은 실제 값이 있으면
            # 이 밋밋한 문구 뒤에 붙여서 "현황"에도 근거가 남게 한다. 판정(status)은
            # 이미 위에서 끝났으므로 여기서는 표시 문구만 보강하고 판정에는 영향 없다.
            if evidence_command and detail == "양호 (점검 완료)" and report_evidence:
                snippet = report_evidence.strip().replace("\r\n", " / ").replace("\n", " / ")[:80]
                if snippet:
                    detail = f"양호 (확인됨: {snippet})"

            # [핵심 수정] 6개 -> 7개 튜플 반환 (증적 + 중요도 포함)
            results[code] = (
                status,
                detail,
                rule.get('name', code),
                rule.get('remediation', ''),
                report_evidence,  # Raw Output (증적)
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
        # [None 방어] execute_command가 이제 실행 실패 시 None을 반환하므로(판정
        # 로직에는 필요한 구분이지만), 이 메서드는 순수 표시용 참고정보라 판정과
        # 무관하다 - 리포트 문자열 조합에 None이 섞여 깨지지 않도록 여기서만
        # 빈 문자열로 되돌린다.
        return {
            "os_info": self.execute_command("uname -a; cat /etc/os-release 2>/dev/null") or "",
            "ip_info": self.execute_command("ip addr show 2>/dev/null || ifconfig -a 2>/dev/null") or "",
            "port_info": self.execute_command("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null") or "",
            "service_info": self.execute_command(
                "systemctl list-units --type=service --state=running --no-pager 2>/dev/null || service --status-all 2>/dev/null"
            ) or "",
        }