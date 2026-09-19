"""Linux 룰 로컬 픽스처 테스트 - VM 없이 로컬 bash(Git Bash/Linux/macOS)로 룰 명령을 실제 실행한다.

룰 명령의 절대경로 /etc/... 를 임시 폴더의 ./etc/... 로 치환하고, 그 안에 가짜 설정 파일을 만들어
상태를 재현한다 - 실제 시스템의 /etc는 읽지 않는다. 파일 권한(stat) 기반 룰은 Windows 파일시스템에서
권한이 에뮬레이션이라 여기서 검증하지 않는다(실제 Linux 대상에서만 의미가 있음)."""
import os
import tempfile
import unittest

import _helpers as h
from utils.rule_judge import judge_rule

BASH = h.find_bash()


class LinuxConfigRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = h.load_rules('linux_rules.json')

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        os.makedirs(os.path.join(self.root, 'etc', 'profile.d'))
        os.makedirs(os.path.join(self.root, 'etc', 'security'))
        os.makedirs(os.path.join(self.root, 'etc', 'pam.d'))
        os.makedirs(os.path.join(self.root, 'etc', 'ssh', 'sshd_config.d'))

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, text):
        with open(os.path.join(self.root, rel), 'w', newline='\n') as f:
            f.write(text)

    def run_cmd(self, cmd):
        return h.run_bash(BASH, cmd.replace('/etc/', './etc/'), self.root)

    def judge(self, code):
        rule = self.rules[code]
        return judge_rule(rule, self.run_cmd(rule['command']), execute_fn=self.run_cmd)

    # ---- U-02 비밀번호 정책 (5개 세부기준): 부분만족 재현 ----
    def test_u02_partial_and_reasons(self):
        self.assertEqual(self.judge('U-02')[0], 'VULNERABLE')           # 아무 설정도 없음
        self.write('etc/security/pwquality.conf', 'minlen = 10\n')
        self.write('etc/login.defs', 'PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\n')
        st, detail = self.judge('U-02')
        self.assertEqual(st, 'PARTIAL')
        self.assertIn('/5', detail)
        self.assertIn('복잡성', detail)                                  # 복잡성/재사용 제한은 미설정
        self.write('etc/login.defs', 'PASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\n')
        st, detail = self.judge('U-02')
        self.assertIn('기준 미달: 비밀번호 최대 사용기간', detail)          # 값은 있으나 기준 미달

    # ---- U-12 세션 타임아웃 ----
    def test_u12(self):
        self.assertEqual(self.judge('U-12')[0], 'VULNERABLE')
        self.write('etc/profile', 'TMOUT=900\n')
        self.assertEqual(self.judge('U-12')[0], 'VULNERABLE')           # 600 초과
        self.write('etc/profile', 'TMOUT=300\nexport TMOUT\n')
        self.assertEqual(self.judge('U-12')[0], 'SAFE')

    # ---- U-30 UMASK ----
    def test_u30(self):
        self.write('etc/profile', 'umask 022\n')
        self.assertEqual(self.judge('U-30')[0], 'SAFE')
        self.write('etc/profile', 'umask 002\n')
        self.assertEqual(self.judge('U-30')[0], 'VULNERABLE')

    # ---- U-03 계정 잠금 임계값 ----
    def test_u03(self):
        self.assertEqual(self.judge('U-03')[0], 'VULNERABLE')
        self.write('etc/security/faillock.conf', 'deny = 5\n')
        self.assertEqual(self.judge('U-03')[0], 'SAFE')
        self.write('etc/security/faillock.conf', 'deny = 50\n')
        self.assertEqual(self.judge('U-03')[0], 'VULNERABLE')

    # ---- U-01 root 원격 접속 제한 (2개 세부기준) ----
    def test_u01(self):
        self.write('etc/ssh/sshd_config', 'PermitRootLogin no\n')
        self.assertEqual(self.judge('U-01')[0], 'SAFE')
        self.write('etc/ssh/sshd_config', 'PermitRootLogin yes\n')
        self.write('etc/securetty', 'console\n')
        self.assertEqual(self.judge('U-01')[0], 'PARTIAL')             # ssh는 취약, securetty는 양호
        self.write('etc/securetty', 'pts/0\n')
        self.assertEqual(self.judge('U-01')[0], 'VULNERABLE')


if BASH is None:
    LinuxConfigRules = unittest.skip("bash 필요(Git Bash/Linux/macOS)")(LinuxConfigRules)

if __name__ == '__main__':
    unittest.main()
