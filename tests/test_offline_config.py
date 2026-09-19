"""설정 파일 점검(접속 없이 텍스트로 네트워크 장비 룰 판정) 테스트."""
import unittest

import _helpers as h  # noqa: F401
from core.ssh_inspector import OfflineConfigInspector, parse_device_capture, _junos_hierarchy_to_set
from core.worker import ScanWorker

CISCO_RUNNING = """
Building configuration...

Current configuration : 1500 bytes
!
version 15.2
service timestamps log datetime msec
service password-encryption
no service pad
!
hostname SW1
!
enable secret 5 $1$abcd$xyz
!
no ip source-route
no ip domain-lookup
no ip http server
no ip http secure-server
no cdp run
!
line con 0
 exec-timeout 5 0
 login local
line vty 0 4
 access-class 10 in
 exec-timeout 5 0
 login local
 transport input ssh
!
end
"""

CAPTURE = """
SW1#show version
Cisco IOS Software, Version 15.2
SW1 uptime is 3 weeks
SW1#show running-config
""" + CISCO_RUNNING + """
SW1#show ip interface
GigabitEthernet0/0 is up
  Directed broadcast forwarding is disabled
  ICMP redirects are never sent
  Proxy ARP is enabled
SW1#
"""

JUNOS_HIER = """
system {
    root-authentication {
        encrypted-password "$6$abc$def";
    }
    login {
        retry-options {
            tries-before-disconnect 3;
            lockout-period 10;
        }
    }
    services {
        ssh {
            protocol-version v2;
        }
        telnet;
    }
}
snmp {
    community public {
        authorization read-write;
    }
}
"""


class OfflineConfig(unittest.TestCase):
    def test_plain_running_config_is_judged_and_missing_outputs_stay_manual(self):
        insp = OfflineConfigInspector("SW1", CISCO_RUNNING)
        self.assertEqual(insp.vendor, "cisco")
        res = insp.run_all_checks()
        self.assertEqual(len(res), 38)
        self.assertEqual(res["N-16"][0], "SAFE")          # service timestamps log datetime
        self.assertEqual(res["N-27"][0], "SAFE")          # no ip http server
        self.assertEqual(res["N-08"][0], "SAFE")          # transport input ssh
        self.assertEqual(res["N-10"][0], "VULNERABLE")    # banner 없음
        self.assertEqual(res["N-33"][0], "MANUAL")        # show ip interface 출력이 파일에 없음
        self.assertIn("show ip interface", res["N-33"][1])

    def test_capture_with_prompts_supplies_show_outputs(self):
        sections = parse_device_capture(CAPTURE)
        self.assertIn("show running-config", sections)
        self.assertIn("show ip interface", sections)
        insp = OfflineConfigInspector("SW1", CAPTURE)
        res = insp.run_all_checks()
        self.assertEqual(res["N-33"][0], "VULNERABLE")    # Proxy ARP is enabled
        self.assertEqual(res["N-31"][0], "SAFE")
        self.assertEqual(res["N-34"][0], "SAFE")          # redirects never sent, unreachables 줄 없음

    def test_junos_hierarchical_config_is_converted(self):
        out = _junos_hierarchy_to_set(JUNOS_HIER)
        self.assertIn("set system services ssh protocol-version v2", out)
        self.assertIn("set system services telnet", out)
        insp = OfflineConfigInspector("EDGE1", JUNOS_HIER)
        self.assertEqual(insp.vendor, "juniper")
        res = insp.run_all_checks()
        self.assertEqual(res["N-01"][0], "SAFE")
        self.assertEqual(res["N-03"][0], "SAFE")
        self.assertEqual(res["N-04"][0], "SAFE")
        self.assertEqual(res["N-08"][0], "PARTIAL")        # SSH 있음 + Telnet 있음
        self.assertEqual(res["N-20"][0], "VULNERABLE")    # read-write community

    def test_undetectable_text_is_manual_not_safe(self):
        res = OfflineConfigInspector("X1", "hello world").run_all_checks()
        self.assertEqual(list(res), ["NET-DETECT"])

    def test_explicit_vendor_overrides_detection(self):
        self.assertEqual(OfflineConfigInspector("X1", "hello", vendor="juniper").vendor, "juniper")

    def test_worker_config_mode_queues_asset_and_results_without_network(self):
        w = ScanWorker("AUDIT_VULN", "SW-1", "u", config_text=CAPTURE)
        self.assertEqual(w.parse_targets(), ["SW-1"])
        w._audit_config_text("SW-1")
        items = []
        while not w.db_queue.empty():
            items.append(w.db_queue.get())
        kinds = [i[0] for i in items]
        self.assertIn("ASSET", kinds)
        results = [i[1] for i in items if i[0] == "SCAN_RESULT"]
        codes = {r[1] for r in results}
        self.assertTrue({f"N-{n:02d}" for n in range(1, 39)} <= codes)
        self.assertTrue(all(r[0] == "SW-1" for r in results))

    def test_worker_rejects_unsafe_label(self):
        self.assertEqual(ScanWorker("AUDIT_VULN", "a;b", "u", config_text="x").parse_targets(), [])


if __name__ == "__main__":
    unittest.main()
