"""룰셋 JSON 무결성 게이트 - 룰을 고치다 생기는 흔한 실수(오타, 중복 코드, 세부기준 형식 오류,
매니페스트 개수 불일치)를 실행 없이 바로 잡는다. 빌드 전에 가장 먼저 돌리는 가장 빠른 검사."""
import json
import os
import unittest

import _helpers as h

VALID_IMPORTANCE = {"상", "중", "하"}


class RuleIntegrity(unittest.TestCase):
    def test_every_ruleset_is_wellformed(self):
        files = h.rule_files()
        self.assertGreaterEqual(len(files), 9)
        for path in files:
            name = os.path.basename(path)
            with open(path, encoding='utf-8') as f:
                rules = json.load(f)
            self.assertIsInstance(rules, list, name)
            codes = [r.get('code') for r in rules]
            self.assertEqual(len(codes), len(set(codes)), f"{name}: 중복 코드 {[c for c in codes if codes.count(c) > 1]}")
            for r in rules:
                where = f"{name}:{r.get('code')}"
                for key in ('code', 'name', 'category', 'importance', 'description', 'remediation'):
                    self.assertTrue(r.get(key), f"{where}: '{key}' 누락")
                self.assertIn(r['importance'], VALID_IMPORTANCE, where)
                self.assertTrue(r.get('command') or r.get('criteria'), f"{where}: command/criteria 둘 다 없음")
                if not r.get('criteria'):
                    continue
                self.assertIsInstance(r['criteria'], list, where)
                labels = [c.get('label') for c in r['criteria']]
                self.assertEqual(len(labels), len(set(labels)), f"{where}: 세부기준 label 중복")
                for c in r['criteria']:
                    self.assertTrue(c.get('label'), f"{where}: 세부기준 label 누락")
                    self.assertTrue(any(k in c for k in ('safe_keyword', 'vulnerable_keyword', 'safe_regex', 'vulnerable_regex')),
                                    f"{where}/{c.get('label')}: 판정 조건(keyword/regex) 없음(판정 불가 기준)")

    def test_missing_is_vulnerable_flag_is_only_on_explicit_setting_rules(self):
        """플래그는 safe_keyword 룰(단일 조건 또는 criteria)에서만 의미가 있다 - 취약키워드 룰에 붙어 있으면 오설정."""
        for path in h.rule_files():
            with open(path, encoding='utf-8') as f:
                for r in json.load(f):
                    if r.get('missing_is_vulnerable'):
                        where = f"{os.path.basename(path)}:{r['code']}"
                        self.assertIn('safe_keyword', r, where)
                        self.assertNotIn('vulnerable_keyword', r, where)

    def test_manifest_counts_match_files(self):
        with open(os.path.join(h.RULES_DIR, 'ruleset_manifest.json'), encoding='utf-8') as f:
            manifest = json.load(f)['rulesets']
        for filename, meta in manifest.items():
            with open(os.path.join(h.RULES_DIR, filename), encoding='utf-8') as f:
                actual = len(json.load(f))
            self.assertEqual(meta['item_count'], actual, f"{filename}: 매니페스트 item_count 불일치")

    def test_all_rule_files_registered_in_engine(self):
        from utils.rule_crypto import RULE_FILES
        on_disk = {os.path.basename(p) for p in h.rule_files()}
        self.assertEqual(on_disk, set(RULE_FILES), "rules/*_rules.json 과 rule_crypto.RULE_FILES 불일치")


if __name__ == '__main__':
    unittest.main()
