"""Windows 룰 로컬 픽스처 테스트 - VM 없이 이 PC의 PowerShell로 룰 명령을 실제 실행한다.

_fixture_env.WindowsEnv가 레지스트리 경로를 임시 키(HKCU\\Software\\ZVulnScanTest\\<id>)로 치환하므로
룰이 읽는 '진짜 경로 그대로' 값을 지정하면 된다 - 관리자 권한이 필요 없고 시스템의 실제 설정은 읽지도
쓰지도 않으며, 끝나면 임시 키를 지운다. Windows + PowerShell에서만 돈다."""
import sys
import unittest

import _fixture_env as fx
import _helpers as h

PS = h.find_powershell() if sys.platform == 'win32' else None

TCPIP = r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
DESKTOP = r'HKCU\Control Panel\Desktop'
EVTLOG = r'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security'


@unittest.skipUnless(PS, "Windows PowerShell 필요")
class WindowsRegistryRules(unittest.TestCase):
    def check(self, code, values, expect, contains=()):
        """values: {경로: {이름: 값}}. 판정 상태와(선택) 사유 문구를 검사한다."""
        res = fx.evaluate(code, reg=values)
        self.assertEqual(res['status'], expect, f"{code} {values}\n{res['detail']}")
        for needle in contains:
            self.assertIn(needle, res['detail'])

    # ---- W-47 화면보호기 (3개 세부기준) ----
    def test_w47(self):
        self.check('W-47', {}, 'VULNERABLE')                                             # 아무 값도 없음
        self.check('W-47', {DESKTOP: {'ScreenSaveActive': 1, 'ScreenSaveTimeOut': 300}}, 'PARTIAL',
                   ('ScreenSaverIsSecure', '미설정'))                                     # 암호 보호만 없음
        good = {'ScreenSaveActive': 1, 'ScreenSaveTimeOut': 300, 'ScreenSaverIsSecure': 1}
        self.check('W-47', {DESKTOP: good}, 'SAFE')
        self.check('W-47', {DESKTOP: dict(good, ScreenSaveTimeOut=3600)}, 'PARTIAL', ('기준 미달',))

    # ---- W-54 DoS 방어 레지스트리 (4개 세부기준) ----
    def test_w54(self):
        self.check('W-54', {}, 'VULNERABLE')
        self.check('W-54', {TCPIP: {'SynAttackProtect': 1, 'EnableDeadGWDetect': 0}}, 'PARTIAL')
        good = {'SynAttackProtect': 1, 'EnableDeadGWDetect': 0, 'KeepAliveTime': 300000, 'NoNameReleaseOnDemand': 1}
        self.check('W-54', {TCPIP: good}, 'SAFE')
        self.check('W-54', {TCPIP: dict(good, KeepAliveTime=7200000)}, 'PARTIAL')

    # ---- W-42 이벤트 로그 (2개 세부기준) ----
    def test_w42(self):
        self.check('W-42', {}, 'VULNERABLE')
        self.check('W-42', {EVTLOG: {'MaxSize': 20971520}}, 'PARTIAL')                   # 크기만 충족, 보존 정책 미설정
        self.check('W-42', {EVTLOG: {'MaxSize': 20971520, 'Retention': 2592000}}, 'SAFE')
        self.check('W-42', {EVTLOG: {'MaxSize': 1048576, 'Retention': 2592000}}, 'PARTIAL')   # 크기 미달

    # ---- 입력 검증: 화면/CLI가 넘기는 값으로 PowerShell 인젝션이 안 되는지 ----
    def test_rejects_unsafe_input(self):
        with self.assertRaises(ValueError):
            fx.evaluate('W-47', reg=[{'path': r"HKCU\Control Panel\Desktop'; calc; '", 'name': 'x', 'value': 1}])
        with self.assertRaises(ValueError):
            fx.evaluate('W-47', reg=[{'path': DESKTOP, 'name': "a'; calc; '", 'value': 1}])


if __name__ == '__main__':
    unittest.main()
