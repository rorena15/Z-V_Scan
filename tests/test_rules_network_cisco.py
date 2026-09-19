"""네트워크 장비(Cisco IOS 계열) 룰 판정 테스트 - 실장비 없이 '설정 텍스트'를 가짜 장비에 넣어 룰 전체를 돌린다.

가짜 장비는 `show running-config | include/section <정규식>`를 IOS와 같은 방식으로 흉내내고,
그 밖의 show 명령은 준비된 출력 문자열을 돌려준다. 명령 문법 자체(장비가 실제로 받아주는지)는
이 테스트로 검증되지 않는다 - 판정 로직과 룰의 정규식이 의도대로 동작하는지만 본다.
"""
import json
import os
import re
import unittest

import _helpers as h  # noqa: F401  (sys.path 설정)
from utils.rule_judge import judge_rule

RULES = json.load(open(os.path.join(h.RULES_DIR, 'network_cisco_rules.json'), encoding='utf-8'))
BY_CODE = {r['code']: r for r in RULES}


class FakeIOS:
    def __init__(self, config, shows=None, all_supported=False):
        self.lines = config.strip('\n').split('\n')
        self.shows = shows or {}
        self.all_supported = all_supported  # show running-config all(기본값 포함) 지원 여부

    def _include(self, pattern):
        return '\n'.join(l for l in self.lines if re.search(pattern, l))

    def _section(self, pattern):
        out, keep = [], False
        for l in self.lines:
            if l and not l[0].isspace():
                keep = re.search(pattern, l) is not None
            if keep:
                out.append(l)
        return '\n'.join(out)

    def run(self, command):
        m = re.match(r'show running-config all \| include (.+)$', command)
        if m:
            return self._include(m.group(1)) if self.all_supported else "% Invalid input detected at '^' marker."
        m = re.match(r'show running-config \| (include|section) (.+)$', command)
        if m:
            return (self._include if m.group(1) == 'include' else self._section)(m.group(2))
        for prefix, out in self.shows.items():
            if command.startswith(prefix):
                return self._filter(command, out)
        return ''

    @staticmethod
    def _filter(command, out):
        m = re.search(r'\| include (.+)$', command)
        if not m:
            return out
        return '\n'.join(l for l in out.split('\n') if re.search(m.group(1), l))

    def judge(self, code):
        rule = BY_CODE[code]
        return judge_rule(rule, self.run(rule['command']), execute_fn=self.run)[0]


HARD_CONFIG = """
service timestamps log datetime msec localtime show-timezone
service password-encryption
service tcp-keepalives-in
no service pad
!
security passwords min-length 10
login block-for 120 attempts 5 within 60
enable secret 9 $9$abc
username admin privilege 15 secret 9 $9$def
!
no ip source-route
no ip bootp server
no ip http server
no ip http secure-server
no ip domain-lookup
no cdp run
ntp server 10.0.0.5
logging buffered 32768 informational
logging host 10.0.0.9
!
banner login ^C Unauthorized access prohibited ^C
!
snmp-server community Kx9#mPq2!zV RO 10
!
line con 0
 exec-timeout 5 0
 login local
line aux 0
 no exec
 transport input none
line vty 0 4
 access-class 10 in
 exec-timeout 5 0
 login local
 transport input ssh
"""

HARD_SHOWS = {
    'show version': 'Cisco IOS Software, Version 17.9.4',
    'show logging': 'Trap logging: level informational, 40 message lines logged',
    'show ip interface brief': ('Interface  IP-Address  OK? Method Status                Protocol\n'
                                'Gi0/0      10.0.0.1    YES NVRAM  up                    up\n'
                                'Gi0/1      unassigned  YES unset  administratively down down'),
    'show ip interface': ('GigabitEthernet0/0 is up\n'
                          '  Directed broadcast forwarding is disabled\n'
                          '  ICMP redirects are never sent\n'
                          '  ICMP unreachables are never sent\n'
                          '  ICMP mask replies are never sent\n'
                          '  Proxy ARP is disabled'),
}

WEAK_CONFIG = """
enable password cisco
!
tftp-server flash:image.bin
ip finger
ip http server
ip http secure-server
ip identd
service tcp-small-servers
service udp-small-servers
service pad
ip domain-lookup
logging buffered informational
snmp-server community public RW
snmp-server community abcdef RO
ip bootp server
cdp run
ip source-route
!
line con 0
 exec-timeout 0 0
line aux 0
 transport input all
line vty 0 4
 password cisco
 login
 transport input telnet ssh
"""

WEAK_SHOWS = {
    'show version': 'Cisco IOS Software, Version 12.2',
    'show logging': 'Trap logging: level errors, 5 message lines logged',
    'show ip interface brief': ('Interface  IP-Address  OK? Method Status                Protocol\n'
                                'Gi0/0      10.0.0.1    YES NVRAM  up                    up\n'
                                'Gi0/1      unassigned  YES unset  down                  down'),
    'show ip interface': ('GigabitEthernet0/0 is up\n'
                          '  Directed broadcast forwarding is enabled\n'
                          '  ICMP redirects are always sent\n'
                          '  ICMP unreachables are always sent\n'
                          '  ICMP mask replies are always sent\n'
                          '  Proxy ARP is enabled'),
}

MANUAL_CODES = {'N-05', 'N-12', 'N-22', 'N-23', 'N-17'}


class NetworkCiscoRules(unittest.TestCase):
    def test_hardened_device_is_all_safe_or_manual(self):
        dev = FakeIOS(HARD_CONFIG, HARD_SHOWS)
        for code in BY_CODE:
            st = dev.judge(code)
            if code in MANUAL_CODES:
                self.assertEqual(st, 'MANUAL', f"{code} {BY_CODE[code]['name']}")
            else:
                self.assertEqual(st, 'SAFE', f"{code} {BY_CODE[code]['name']} -> {st}")

    def test_weak_device_flags_every_automatic_rule(self):
        dev = FakeIOS(WEAK_CONFIG, WEAK_SHOWS)
        still_safe = []
        for code in BY_CODE:
            if code in MANUAL_CODES:
                continue
            st = dev.judge(code)
            if st == 'SAFE':
                still_safe.append(code)
            self.assertNotEqual(st, 'MANUAL', code)
        self.assertEqual(still_safe, [], f"취약 설정인데 양호로 나온 룰: {still_safe}")

    def test_every_vty_block_must_be_locked_down(self):
        # Packet Tracer 기본 구성: line vty 0 4는 SSH 전용이지만 line vty 5 15는 login만 있어 Telnet이 열려 있다
        cfg = ("line con 0\n exec-timeout 5 0\n login local\n"
               "line vty 0 4\n access-class 10 in\n exec-timeout 5 0\n login local\n transport input ssh\n"
               "line vty 5 15\n login\n!\nend\n")
        dev = FakeIOS(cfg)
        self.assertEqual(dev.judge('N-08'), 'PARTIAL')
        self.assertEqual(dev.judge('N-06'), 'PARTIAL')
        self.assertEqual(dev.judge('N-07'), 'PARTIAL')
        fixed = cfg.replace("line vty 5 15\n login\n",
                            "line vty 5 15\n access-class 10 in\n exec-timeout 5 0\n login local\n transport input ssh\n")
        dev = FakeIOS(fixed)
        for code in ('N-06', 'N-07', 'N-08'):
            self.assertEqual(dev.judge(code), 'SAFE', code)

    def test_single_vty_block_at_end_of_output(self):
        cfg = "line vty 0 4\n login local\n transport input telnet"
        self.assertEqual(FakeIOS(cfg).judge('N-08'), 'VULNERABLE')

    def test_default_dependent_rules_use_state_evidence_in_order(self):
        # 명시된 줄이 없고 기본값을 볼 방법(show running-config all, 상태 명령)도 없으면 양호로 추정하지 않는다
        for code in ('N-29', 'N-30', 'N-32', 'N-36', 'N-37'):
            self.assertEqual(FakeIOS("hostname SW1\n").judge(code), 'MANUAL', code)
        # show running-config all 이 되는 장비: 기본값까지 보이므로 확정 판정
        dev = FakeIOS("no service pad\nip source-route\nip domain-lookup\nno cdp run\nno ip bootp server\n", all_supported=True)
        self.assertEqual(dev.judge('N-37'), 'SAFE')
        self.assertEqual(dev.judge('N-32'), 'VULNERABLE')
        self.assertEqual(dev.judge('N-36'), 'VULNERABLE')
        self.assertEqual(dev.judge('N-30'), 'SAFE')
        self.assertEqual(dev.judge('N-29'), 'SAFE')

    def test_cdp_state_command_takes_priority(self):
        on = {'show cdp': 'Global CDP information:\n\tSending CDP packets every 60 seconds'}
        off = {'show cdp': '% CDP is not enabled'}
        self.assertEqual(FakeIOS("hostname SW1\n", on).judge('N-30'), 'VULNERABLE')
        self.assertEqual(FakeIOS("hostname SW1\n", off).judge('N-30'), 'SAFE')
        # 상태 명령이 config와 충돌하면 상태 명령(실제 동작)을 따른다
        self.assertEqual(FakeIOS("no cdp run\n", on).judge('N-30'), 'VULNERABLE')

    def test_domain_lookup_state_command(self):
        self.assertEqual(FakeIOS("x\n", {'show hosts': 'Name/address lookup uses domain service'}).judge('N-36'), 'VULNERABLE')
        self.assertEqual(FakeIOS("x\n", {'show hosts': 'Name/address lookup uses static mappings'}).judge('N-36'), 'SAFE')

    def test_partial_when_only_vty_is_protected(self):
        cfg = "line con 0\n exec-timeout 0 0\nline vty 0 4\n exec-timeout 5 0\n login local\n"
        dev = FakeIOS(cfg)
        self.assertEqual(dev.judge('N-01'), 'PARTIAL')
        self.assertEqual(dev.judge('N-07'), 'PARTIAL')

    def test_exec_timeout_boundaries(self):
        for value, expect in (('5 0', 'SAFE'), ('4 59', 'SAFE'), ('0 30', 'SAFE'), ('0 0', 'VULNERABLE'),
                              ('6 0', 'VULNERABLE'), ('10 0', 'VULNERABLE')):
            cfg = f"line con 0\n exec-timeout {value}\nline vty 0 4\n exec-timeout {value}\n"
            self.assertEqual(FakeIOS(cfg).judge('N-07'), expect, value)
        self.assertEqual(FakeIOS("line con 0\nline vty 0 4\n").judge('N-07'), 'VULNERABLE')

    def test_snmp_rules_when_snmp_is_not_configured(self):
        dev = FakeIOS(HARD_CONFIG.replace('snmp-server community Kx9#mPq2!zV RO 10', ''))
        self.assertEqual(dev.judge('N-17'), 'SAFE')
        for code in ('N-18', 'N-19', 'N-20'):
            self.assertEqual(dev.judge(code), 'NA', code)

    def test_snmp_community_details(self):
        def st(line, code):
            return FakeIOS(line).judge(code)
        self.assertEqual(st('snmp-server community private RO', 'N-18'), 'VULNERABLE')
        self.assertEqual(st('snmp-server community Abcdef1! RO 10', 'N-18'), 'SAFE')
        self.assertEqual(st('snmp-server community Abcdef1! RO', 'N-19'), 'VULNERABLE')
        self.assertEqual(st('snmp-server community Abcdef1! RO 10', 'N-19'), 'SAFE')
        self.assertEqual(st('snmp-server community Abcdef1! RW 10', 'N-20'), 'VULNERABLE')
        self.assertEqual(st('snmp-server community Abcdef1! view v1 RO 10', 'N-20'), 'SAFE')

    def test_unsupported_command_is_not_reported_as_safe(self):
        rule = BY_CODE['N-27']
        status, _ = judge_rule(rule, "% Invalid input detected at '^' marker.")
        self.assertEqual(status, 'NA')

    def test_aux_port_absent_is_na(self):
        self.assertEqual(FakeIOS("line con 0\nline vty 0 4\n").judge('N-09'), 'NA')

    def test_logging_buffer_size(self):
        for line, expect in (('logging buffered 16384', 'SAFE'), ('logging buffered 8192', 'VULNERABLE'),
                             ('logging buffered 1000000 debugging', 'SAFE'), ('logging buffered informational', 'VULNERABLE')):
            self.assertEqual(FakeIOS(line).judge('N-13'), expect, line)


if __name__ == '__main__':
    unittest.main()
