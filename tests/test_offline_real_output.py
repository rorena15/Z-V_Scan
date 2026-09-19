"""Packet Tracer 8.2.2(IOS 15.0)에서 실제로 캡처한 show 출력으로 상태 명령 기반 판정을 확인한다."""
import unittest

import _helpers as h  # noqa: F401
from core.ssh_inspector import OfflineConfigInspector

CAPTURE = """
SW1#show running-config
!
version 15.0
hostname SW1
!
ip domain-name lab.local
!
line con 0
!
line vty 0 4
 login local
 transport input ssh
line vty 5 15
 login
!
end
SW1#show cdp
Global CDP information:
    Sending CDP packets every 60 seconds
    Sending a holdtime value of 180 seconds
    Sending CDPv2 advertisements is enabled
SW1#show hosts
Default Domain is lab.local
Name/address lookup uses domain service
Name servers are 255.255.255.255

Codes: UN - unknown, EX - expired, OK - OK, ?? - revalidate
       temp - temporary, perm - permanent
       NA - Not Applicable None - Not defined

Host                      Port  Flags      Age Type   Address(es)
"""


class RealPacketTracerOutput(unittest.TestCase):
    def test_state_commands_decide_cdp_and_domain_lookup(self):
        res = OfflineConfigInspector("SW1", CAPTURE).run_all_checks()
        self.assertEqual(res["N-30"][0], "VULNERABLE")
        self.assertIn("show cdp", res["N-30"][1])
        self.assertEqual(res["N-36"][0], "VULNERABLE")
        self.assertIn("show hosts", res["N-36"][1])
        # 근거를 못 얻은 항목은 여전히 양호로 추정하지 않는다
        for code in ("N-29", "N-32", "N-37"):
            self.assertEqual(res[code][0], "MANUAL", code)
        self.assertEqual(res["N-08"][0], "PARTIAL")  # line vty 5 15에서 Telnet 허용


if __name__ == "__main__":
    unittest.main()
