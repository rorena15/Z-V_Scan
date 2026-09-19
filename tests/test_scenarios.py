"""데이터 주도 시나리오 테스트 - tests/scenarios/*.json 에 적은 케이스를 그대로 테스트로 돌린다.
코드를 고칠 필요 없이 JSON만 추가/수정하면 된다. 형식은 tests/scenarios/example.json 참고:

  {
    "name": "설명(자유)",
    "rule": "W-47",                       # 룰 코드 (U-/WEB- = Linux, W-/PC- = Windows)
    "reg": {"HKCU\\\\Control Panel\\\\Desktop": {"ScreenSaveActive": 1}},   # Windows 레지스트리(진짜 경로: int=DWord, 문자열=String)
    "secpol": "LockoutBadCount = 3\\n",    # Windows secedit 보안 정책 텍스트
    "files": {"etc/profile": "TMOUT=300\\n"},   # Linux 파일(상대경로: 내용)
    "expect": "PARTIAL",                  # SAFE | PARTIAL | VULNERABLE | MANUAL | NA
    "detail_contains": ["미설정"]          # (선택) 판정 사유에 포함돼야 할 문구들
  }
"""
import glob
import json
import os
import unittest

import _fixture_env as fx

SCENARIO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scenarios')


def load_scenarios():
    items = []
    for path in sorted(glob.glob(os.path.join(SCENARIO_DIR, '*.json'))):
        with open(path, encoding='utf-8') as f:
            for i, sc in enumerate(json.load(f)):
                items.append((os.path.basename(path), i, sc))
    return items


class Scenarios(unittest.TestCase):
    def test_scenarios(self):
        scenarios = load_scenarios()
        self.assertTrue(scenarios, "시나리오가 하나도 없음")
        for filename, i, sc in scenarios:
            label = f"{filename}#{i} {sc.get('name', sc['rule'])}"
            with self.subTest(label):
                try:
                    ok, res = fx.run_scenario(sc)
                except RuntimeError as e:      # 이 PC에 PowerShell/bash가 없으면 그 OS 시나리오는 건너뜀
                    self.skipTest(str(e))
                    continue
                self.assertTrue(ok, f"{label}\n기대 {res['expected']} / 실제 {res['status']}\n"
                                    f"사유: {res['detail']}\n누락 문구: {res['missing_phrases']}")


if __name__ == '__main__':
    unittest.main()
