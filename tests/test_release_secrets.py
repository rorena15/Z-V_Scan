"""배포 비밀값 주입/유출 방지 검사 - 저장소의 config.py에는 개발 전용 더미만 있어야 하고, 주입 스크립트는 잘못된 값을 거부해야 한다."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import _helpers as h
from cryptography.fernet import Fernet

CONFIG = os.path.join(h.ENGINE, 'core', 'config.py')
SCRIPT = os.path.join(h.ROOT, 'ci', 'inject_release_secrets.py')

# 공개 저장소에 노출됐던 예전 실제 값의 식별용 조각(전체 값을 다시 적지 않는다) - 어떤 파일에도 다시 나타나면 안 된다
OLD_LEAKED = ("Secret-Salt-2026-DoNotShare", "8gUHbl7QOUhh", "V3_Pro_Secure_Engine_Key")


def good_env():
    return {"ZVULN_LICENSE_SALT": "s" * 40, "ZVULN_RULE_KEY": Fernet.generate_key().decode(), "ZVULN_ENGINE_TOKEN": "t" * 40}


class ReleaseSecrets(unittest.TestCase):
    def run_inject(self, env_overrides, config_path):
        env = {k: v for k, v in os.environ.items() if not k.startswith("ZVULN_")}
        env.update(env_overrides)
        return subprocess.run([sys.executable, SCRIPT, "--config", config_path], env=env, capture_output=True, text=True)

    def temp_config(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, 'config.py')
        shutil.copy(CONFIG, path)
        return path

    def test_repo_config_has_only_dev_placeholders(self):
        sys.path.insert(0, h.ENGINE)
        from core.config import AppConfig
        self.assertTrue(AppConfig.LICENSE_SALT.startswith("DEV-ONLY"))
        self.assertTrue(AppConfig.ENGINE_ACCESS_TOKEN.startswith("DEV-ONLY"))
        Fernet(AppConfig.RULE_ENCRYPTION_KEY.encode())  # 형식은 유효해야 개발/테스트 룰 암호화가 돈다

    def test_old_leaked_values_are_gone_from_tracked_sources(self):
        hits = []
        for base in (h.ENGINE, os.path.join(h.ROOT, 'ci'), os.path.join(h.ROOT, '.github')):
            for root, _, files in os.walk(base):
                for f in files:
                    if not f.endswith(('.py', '.yml', '.ps1', '.json', '.md')) or f == 'test_release_secrets.py':
                        continue
                    try:
                        text = open(os.path.join(root, f), encoding='utf-8', errors='ignore').read()
                    except OSError:
                        continue
                    hits += [os.path.join(root, f) for needle in OLD_LEAKED if needle in text]
        self.assertEqual(hits, [], f"예전 노출 값이 남아 있음: {hits}")

    def test_inject_replaces_constants_and_prints_no_secret(self):
        path = self.temp_config()
        env = good_env()
        r = self.run_inject(env, path)
        self.assertEqual(r.returncode, 0, r.stderr)
        for value in env.values():
            self.assertNotIn(value, r.stdout + r.stderr)
        text = open(path, encoding='utf-8').read()
        self.assertIn(f'LICENSE_SALT = "{env["ZVULN_LICENSE_SALT"]}"', text)
        self.assertIn(f'RULE_ENCRYPTION_KEY = "{env["ZVULN_RULE_KEY"]}"', text)
        self.assertNotIn("DEV-ONLY-license-salt-not-for-release\"", text)
        compile(text, path, 'exec')

    def test_inject_rejects_missing_dummy_and_malformed_values(self):
        path = self.temp_config()
        original = open(path, encoding='utf-8').read()
        cases = {
            "missing": {k: v for k, v in good_env().items() if k != "ZVULN_RULE_KEY"},
            "dummy": dict(good_env(), ZVULN_LICENSE_SALT="DEV-ONLY-license-salt-not-for-release"),
            "bad_fernet": dict(good_env(), ZVULN_RULE_KEY="not-a-fernet-key"),
            "too_short": dict(good_env(), ZVULN_ENGINE_TOKEN="short"),
            "quote": dict(good_env(), ZVULN_LICENSE_SALT='abc"def' + "x" * 30),
        }
        for name, env in cases.items():
            r = self.run_inject(env, path)
            self.assertNotEqual(r.returncode, 0, name)
        self.assertEqual(open(path, encoding='utf-8').read(), original, "실패한 주입이 파일을 건드림")


if __name__ == '__main__':
    unittest.main()
