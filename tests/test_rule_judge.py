"""판정 엔진(utils/rule_judge.judge_rule) 단위 테스트 - 대상 시스템 없이 가짜 출력만으로 검증한다."""
import unittest

import _helpers as h
from utils.rule_judge import judge_rule


def crit(label, **kw):
    return dict({"label": label, "command": "x"}, **kw)


def ok_crit(label):
    return crit(label, safe_keyword="OK")


def judge(criteria, outputs, top="ok"):
    it = iter(outputs)
    return judge_rule({"code": "T", "criteria": criteria}, top, execute_fn=lambda c: next(it))


class CriteriaJudge(unittest.TestCase):
    def test_all_met_is_safe(self):
        self.assertEqual(judge([ok_crit("a"), ok_crit("b")], ["OK", "OK"])[0], "SAFE")

    def test_some_met_is_partial_and_explains_why(self):
        st, detail = judge([ok_crit("a"), ok_crit("b"), ok_crit("c")], ["OK", "FAIL", "NOTSET"])
        self.assertEqual(st, "PARTIAL")
        self.assertIn("기준 미달: b", detail)
        self.assertIn("미설정/확인 불가: c", detail)

    def test_missing_value_variants_count_as_unset(self):
        for out in ("NOTSET", "", "Cannot index into a null array"):
            st, detail = judge([ok_crit("a"), ok_crit("b")], ["OK", out])
            self.assertEqual(st, "PARTIAL", out)
            self.assertIn("미설정/확인 불가: b", detail, out)

    def test_none_met_is_vulnerable(self):
        self.assertEqual(judge([ok_crit("a"), ok_crit("b")], ["FAIL", "NOTSET"])[0], "VULNERABLE")

    def test_permission_denied_never_leaks_as_safe(self):
        # vulnerable_keyword 기준은 원래 "문구 없음 = 양호"라 권한 오류가 안전으로 새던 경로
        st, detail = judge([crit("v", vulnerable_keyword="pts"), ok_crit("b")],
                           ["grep: /etc/securetty: Permission denied", "OK"])
        self.assertEqual(st, "PARTIAL")
        self.assertIn("권한 부족", detail)

    def test_not_applicable_criterion_is_excluded(self):
        self.assertEqual(judge([ok_crit("a"), ok_crit("b")], ["OK", "NOTAPPLICABLE"])[0], "SAFE")
        self.assertEqual(judge([ok_crit("a"), ok_crit("b")], ["NOTAPPLICABLE", "NOTAPPLICABLE"])[0], "NA")

    def test_all_execution_failures_is_manual(self):
        st, _ = judge_rule({"code": "T", "criteria": [ok_crit("a"), ok_crit("b")]}, "ok", execute_fn=lambda c: None)
        self.assertEqual(st, "MANUAL")

    def test_criteria_without_command_reuse_top_output(self):
        rule = {"code": "T", "criteria": [{"label": "p", "safe_keyword": "wheel"},
                                          {"label": "q", "vulnerable_keyword": "pts"}]}
        self.assertEqual(judge_rule(rule, "auth required pam_wheel.so wheel", execute_fn=None)[0], "SAFE")


class SingleConditionJudge(unittest.TestCase):
    def test_safe_and_vulnerable_keyword(self):
        self.assertEqual(judge_rule({"code": "T", "safe_keyword": "OK"}, "OK")[0], "SAFE")
        self.assertEqual(judge_rule({"code": "T", "safe_keyword": "OK"}, "FAIL")[0], "VULNERABLE")
        self.assertEqual(judge_rule({"code": "T", "vulnerable_keyword": "bad"}, "a bad b")[0], "VULNERABLE")
        self.assertEqual(judge_rule({"code": "T", "vulnerable_keyword": "bad"}, "fine")[0], "SAFE")

    def test_none_output_is_manual_and_permission_is_conservative(self):
        self.assertEqual(judge_rule({"code": "T", "safe_keyword": "OK"}, None)[0], "MANUAL")
        self.assertEqual(judge_rule({"code": "T", "safe_keyword": "OK"}, "Permission denied")[0], "VULNERABLE")

    def test_service_absent_signal_is_na(self):
        self.assertEqual(judge_rule({"code": "T", "safe_keyword": "OK"}, "bash: foo: command not found")[0], "NA")


class MissingIsVulnerable(unittest.TestCase):
    """레지스트리 값 부재(reg query 오류 문구)를 NA로 보낼지 취약으로 볼지 - 룰 플래그로 결정."""
    KO_MISSING = "오류: 오류: 시스템이 지정된 레지스트리 키 또는 값을 찾을 수 없습니다."
    EN_MISSING = "ERROR: The system was unable to find the specified registry key or value."

    def test_flagged_rule_treats_missing_registry_value_as_vulnerable(self):
        rule = {"code": "T", "safe_keyword": "0x0", "missing_is_vulnerable": True}
        for out in (self.KO_MISSING, self.EN_MISSING):
            st, detail = judge_rule(rule, out)
            self.assertEqual(st, "VULNERABLE", out)
            self.assertIn("미설정", detail)

    def test_unflagged_rule_keeps_na_for_missing_registry_value(self):
        rule = {"code": "T", "safe_keyword": "0x0"}
        self.assertEqual(judge_rule(rule, self.KO_MISSING)[0], "NA")

    def test_flag_does_not_swallow_other_na_signals_or_real_values(self):
        rule = {"code": "T", "safe_keyword": "0x0", "missing_is_vulnerable": True}
        self.assertEqual(judge_rule(rule, "bash: reg: command not found")[0], "NA")
        self.assertEqual(judge_rule(rule, "    SecurityLevel    REG_DWORD    0x0")[0], "SAFE")
        self.assertEqual(judge_rule(rule, "    SecurityLevel    REG_DWORD    0x1")[0], "VULNERABLE")


class AllRulesetsSmoke(unittest.TestCase):
    """어떤 출력이 와도 모든 룰이 예외 없이 5개 상태 중 하나로 판정돼야 한다."""

    def test_no_rule_crashes(self):
        import json
        valid = {"SAFE", "VULNERABLE", "PARTIAL", "MANUAL", "NA"}
        executors = (None, lambda c: "OK", lambda c: None, lambda c: "")
        for path in h.rule_files():
            with open(path, encoding='utf-8') as f:
                rules = json.load(f)
            for rule in rules:
                for out in ("", "OK", "FAIL", "NOTSET", "Permission denied", "not found", "random text"):
                    for fn in executors:
                        st, _ = judge_rule(rule, out, execute_fn=fn)
                        self.assertIn(st, valid, rule['code'])


if __name__ == '__main__':
    unittest.main()
