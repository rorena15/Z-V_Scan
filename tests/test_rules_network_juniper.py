"""Juniper Junos 룰 판정 테스트 - `show configuration | display set | match "<정규식>"`를 가짜 장비로 흉내낸다.
명령 문법을 실제 장비가 받아주는지는 검증하지 못한다(판정 로직과 정규식만 검증)."""
import json
import os
import re
import unittest

import _helpers as h  # noqa: F401
from utils.rule_judge import judge_rule

RULES = json.load(open(os.path.join(h.RULES_DIR, 'network_juniper_rules.json'), encoding='utf-8'))
BY_CODE = {r['code']: r for r in RULES}


class FakeJunos:
    def __init__(self, config, shows=None):
        self.lines = [l for l in config.strip().split('\n') if l.strip()]
        self.shows = shows or {}

    def run(self, command):
        m = re.match(r'show configuration \| display set \| match "(.+)"$', command)
        if m:
            return '\n'.join(l for l in self.lines if re.search(m.group(1), l))
        return self.shows.get(command, '')

    def judge(self, code):
        rule = BY_CODE[code]
        return judge_rule(rule, self.run(rule['command']), execute_fn=self.run)[0]


HARD = """
set system root-authentication encrypted-password "$6$abc$def"
set system login password minimum-length 10
set system login retry-options tries-before-disconnect 3
set system login retry-options lockout-period 10
set system login class ops idle-timeout 5
set system login user admin class super-user
set system login message "Unauthorized access prohibited"
set system services ssh protocol-version v2
set system services ssh client-alive-interval 60
set system ntp server 10.0.0.5
set system syslog host 10.0.0.9 any notice
set system syslog file messages any notice
set system no-redirects
set interfaces lo0 unit 0 family inet filter input PROTECT-RE
set snmp community Kx9#mPq2!zV authorization read-only
set snmp community Kx9#mPq2!zV clients 10.0.0.0/24
set protocols lldp interface ge-0/0/0 disable
"""
HARD_SHOWS = {
    'show interfaces terse': 'Interface   Admin Link Proto\nge-0/0/0    up    up\nge-0/0/1    down  down\nge-0/0/1.0  up  down  inet',
}
MANUAL = {'N-05', 'N-12', 'N-16', 'N-17', 'N-22', 'N-23', 'N-32'}
NA = {'N-28', 'N-35', 'N-36', 'N-37', 'N-38'}

WEAK = """
set system login class ops idle-timeout 30
set system ports console insecure
set system services telnet
set system services web-management http
set system services finger
set system services dhcp-local-server
set system tftp-server
set snmp community public authorization read-write
set snmp community public clients 0.0.0.0/0
set protocols lldp interface all
set interfaces ge-0/0/2 unit 0 family inet targeted-broadcast
set interfaces ge-0/0/2 unit 0 proxy-arp
"""
WEAK_SHOWS = {'show interfaces terse': 'Interface   Admin Link Proto\nge-0/0/2    up    down'}


class NetworkJuniperRules(unittest.TestCase):
    def test_hardened_device(self):
        dev = FakeJunos(HARD, HARD_SHOWS)
        for code in BY_CODE:
            st = dev.judge(code)
            if code in MANUAL:
                self.assertEqual(st, 'MANUAL', f"{code} {BY_CODE[code]['name']}")
            elif code in NA:
                self.assertEqual(st, 'NA', code)
            else:
                self.assertEqual(st, 'SAFE', f"{code} {BY_CODE[code]['name']} -> {st}")

    def test_weak_device_flags_every_automatic_rule(self):
        dev = FakeJunos(WEAK, WEAK_SHOWS)
        still_safe = [c for c in BY_CODE if c not in MANUAL and c not in NA and dev.judge(c) == 'SAFE']
        self.assertEqual(still_safe, [], f"취약 설정인데 양호로 나온 룰: {still_safe}")

    def test_snmp_absent(self):
        dev = FakeJunos("set system ntp server 10.0.0.5")
        self.assertEqual(dev.judge('N-17'), 'SAFE')
        for code in ('N-18', 'N-19', 'N-20'):
            self.assertEqual(dev.judge(code), 'NA', code)

    def test_snmp_community_quoted_complex_name(self):
        line = 'set snmp community "Kx9 #mPq2" authorization read-only'
        self.assertEqual(FakeJunos(line).judge('N-18'), 'VULNERABLE')  # 공백 포함 이름 등 파싱 불가/약한 형태는 취약으로 본다
        self.assertEqual(FakeJunos('set snmp community "Kx9#mPq2!" authorization read-only').judge('N-18'), 'SAFE')

    def test_snmp_acl_partial(self):
        cfg = "set snmp community Kx9#mPq2!zV authorization read-only\nset snmp community Kx9#mPq2!zV clients 0.0.0.0/0"
        self.assertEqual(FakeJunos(cfg).judge('N-19'), 'PARTIAL')

    def test_root_password_hash_type(self):
        self.assertEqual(FakeJunos('set system root-authentication encrypted-password "$5$x$y"').judge('N-03'), 'SAFE')
        self.assertEqual(FakeJunos('set system root-authentication encrypted-password "$1$x$y"').judge('N-03'), 'VULNERABLE')

    def test_unused_interface_only_flags_physical_ports(self):
        out = 'Interface   Admin Link Proto\nge-0/0/1.0  up  down  inet\nge-0/0/2    down  down'
        self.assertEqual(FakeJunos('', {'show interfaces terse': out}).judge('N-24'), 'SAFE')


if __name__ == '__main__':
    unittest.main()
