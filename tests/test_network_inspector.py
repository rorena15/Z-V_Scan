"""NetworkInspector(장비 유형 감지/권한 확인/룰셋 선택)와 스캔 워커 배선 테스트 - 실제 SSH 접속 없이 명령 실행만 가짜로 대체한다."""
import unittest

import _helpers as h  # noqa: F401
from core.ssh_inspector import NetworkInspector
from core.worker import ScanWorker


class FakeNet(NetworkInspector):
    def __init__(self, outputs, **kw):
        super().__init__("192.0.2.1", "admin", **kw)
        self.outputs = outputs
        self.is_simulation = False

    def execute_command(self, command, timeout=None, use_sudo=False):
        for prefix, out in self.outputs.items():
            if command.startswith(prefix):
                return out
        return ""


CISCO_VER = "Cisco IOS Software, Version 15.2\nsw1 uptime is 3 weeks"
JUNOS_VER = "Hostname: edge1\nModel: srx300\nJunos: 21.4R3"


class NetworkInspectorTests(unittest.TestCase):
    def test_detects_vendor_and_switches_ruleset(self):
        d = FakeNet({"show version": CISCO_VER})
        self.assertEqual(d.detect_vendor(), "cisco")
        d = FakeNet({"show version": JUNOS_VER})
        self.assertEqual(d.detect_vendor(), "juniper")
        self.assertIsNone(FakeNet({"show version": "unknown box"}).detect_vendor())

    def test_undetected_vendor_returns_manual_not_a_fake_pass(self):
        d = FakeNet({"show version": "unknown box"})
        res = d.run_all_checks()
        self.assertEqual(list(res), ["NET-DETECT"])
        self.assertEqual(res["NET-DETECT"][0], "MANUAL")

    def test_low_privilege_cisco_account_is_not_reported_as_safe(self):
        d = FakeNet({"show privilege": "Current privilege level is 1"}, vendor="cisco")
        res = d.run_all_checks()
        self.assertEqual(list(res), ["NET-PRIV"])
        self.assertEqual(res["NET-PRIV"][0], "MANUAL")

    def test_full_run_uses_vendor_ruleset_and_returns_all_38(self):
        d = FakeNet({"show privilege": "Current privilege level is 15"}, vendor="cisco")
        res = d.run_all_checks()
        self.assertEqual(len(res), 38)
        d = FakeNet({}, vendor="juniper")
        res = d.run_all_checks()
        self.assertEqual(len(res), 38)
        self.assertEqual(res["N-35"][0], "NA")
        for value in res.values():
            self.assertEqual(len(value), 7)

    def test_worker_accepts_device_type_only_for_known_values(self):
        self.assertEqual(ScanWorker("AUDIT_VULN", "192.0.2.1", "u", device_type="cisco").device_type, "cisco")
        self.assertIsNone(ScanWorker("AUDIT_VULN", "192.0.2.1", "u", device_type="bogus").device_type)
        self.assertIsNone(ScanWorker("AUDIT_VULN", "192.0.2.1", "u").device_type)

    def test_hostname_extraction_for_network_devices(self):
        self.assertEqual(ScanWorker._extract_real_hostname(CISCO_VER), "sw1")
        self.assertEqual(ScanWorker._extract_real_hostname(JUNOS_VER), "edge1")


if __name__ == "__main__":
    unittest.main()
