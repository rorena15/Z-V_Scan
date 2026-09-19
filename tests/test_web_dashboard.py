"""웹 대시보드 서버(web_dashboard_server) 통합 테스트 - Flask 테스트 클라이언트 + 가짜 DB.

계정/설정/감사로그 파일 위치를 임시 폴더로 바꿔서 실제 config/를 건드리지 않고, DBConnector를
아예 만들지 않는다(기본 생성자는 실제 zvuln_scan.db 경로에 연결되므로 테스트에서 쓰면 안 된다)."""
import os
import tempfile
import threading
import unittest

import _helpers as h

try:
    import flask  # noqa: F401
    import PySide6  # noqa: F401
    HAVE_DEPS = True
except ImportError:
    HAVE_DEPS = False


class FakeDB:
    def get_latest_findings(self):
        return [{'ip': '1.1.1.1', 'hostname': '=cmd|x', 'os_type': 'Linux', 'code': 'U-01', 'name': 'n',
                 'category': 'c', 'importance': '상', 'status': 'VULNERABLE', 'risk': 'Critical'}]

    def get_security_level_history(self): return []
    def get_assets_for_manager(self): return []
    def purge_old_results(self, days): return 0
    def get_round_comparison(self):
        return [{'asset_id': 1, 'ip': '1.1.1.1', 'hostname': 'h', 'prev_score': 50, 'current_score': 70,
                 'improvement': 20, 'prev_vuln_total': 3, 'current_vuln_total': 1,
                 'prev_partial_total': 0, 'current_partial_total': 0}]

    def get_code_changes_for_asset(self, asset_id): return []


@unittest.skipUnless(HAVE_DEPS, "Flask/PySide6 필요")
class WebDashboard(unittest.TestCase):
    def setUp(self):
        from utils import dashboard_accounts, web_audit_log
        import utils.app_settings as app_settings
        self._tmp = tempfile.TemporaryDirectory()
        for mod in (dashboard_accounts, app_settings, web_audit_log):
            mod.get_base_dir = lambda p=self._tmp.name: p
        dashboard_accounts.create_account('admin', 'testpass123')          # 최초 계정은 항상 admin
        dashboard_accounts.create_account('op', 'testpass123', role='operator')
        dashboard_accounts.create_account('view', 'testpass123', role='viewer')
        self.accounts = dashboard_accounts
        import web_dashboard_server as wds
        self.shutdown = threading.Event()
        self.app = wds.create_app(FakeDB(), shutdown_event=self.shutdown)

    def tearDown(self):
        self._tmp.cleanup()

    def login(self, user):
        c = self.app.test_client()
        c.post('/login', data={'username': user, 'password': 'testpass123'})
        return c, {'X-CSRF-Token': c.get('/api/whoami').get_json()['csrf_token']}

    def test_role_gating(self):
        admin, ha = self.login('admin')
        op, ho = self.login('op')
        view, hv = self.login('view')
        anon = self.app.test_client()
        self.assertEqual(anon.get('/api/accounts').status_code, 401)
        self.assertEqual(view.get('/settings').status_code, 403)
        self.assertEqual(op.get('/settings').status_code, 403)
        self.assertEqual(admin.get('/settings').status_code, 200)
        self.assertEqual(view.post('/api/scan/start', json={}, headers=hv).status_code, 403)
        self.assertEqual(view.get('/api/scan/status').status_code, 200)
        self.assertEqual(op.post('/api/server/shutdown', headers=ho).status_code, 403)
        self.assertFalse(self.shutdown.is_set())
        self.assertEqual(admin.post('/api/server/shutdown', headers=ha).status_code, 200)
        self.assertTrue(self.shutdown.is_set())

    def test_csrf(self):
        admin, ha = self.login('admin')
        self.assertEqual(admin.post('/api/settings/general', json={'theme': 'dark'}).status_code, 403)
        self.assertEqual(admin.post('/api/settings/general', json={'theme': 'dark'},
                                    headers={'X-CSRF-Token': 'bogus'}).status_code, 403)
        self.assertEqual(admin.post('/api/settings/general', json={'theme': 'dark'}, headers=ha).status_code, 200)

    def test_last_admin_and_self_delete_guards(self):
        admin, ha = self.login('admin')
        self.assertEqual(admin.delete('/api/accounts/admin', headers=ha).status_code, 400)   # 본인
        ok, _ = self.accounts.delete_account('admin')                                       # 마지막 admin
        self.assertFalse(ok)

    def test_api_tokens(self):
        op, ho = self.login('op')
        view, hv = self.login('view')
        self.assertEqual(view.post('/api/tokens', json={'name': 't', 'role': 'operator'}, headers=hv).status_code, 400)
        r = op.post('/api/tokens', json={'name': 'ci', 'role': 'operator'}, headers=ho)
        self.assertEqual(r.status_code, 200)
        token = r.get_json()['token']
        auth = {'Authorization': 'Bearer ' + token}
        anon = self.app.test_client()
        self.assertEqual(anon.get('/api/export/findings.csv', headers=auth).status_code, 200)
        self.assertEqual(anon.get('/api/settings', headers=auth).status_code, 403)             # admin 라우트 불가
        self.assertEqual(anon.post('/api/tokens', json={'name': 'x', 'role': 'viewer'}, headers=auth).status_code, 403)
        self.assertEqual(anon.get('/api/export/findings.csv', headers={'Authorization': 'Bearer zvs_bad'}).status_code, 401)
        with open(os.path.join(self._tmp.name, 'config', 'api_tokens.json'), encoding='utf-8') as f:
            self.assertNotIn(token, f.read())                                                   # 원문 미저장
        self.accounts.delete_account('op')                                                      # 소유자 삭제 -> 토큰 무효
        self.assertEqual(anon.get('/api/export/findings.csv', headers=auth).status_code, 401)

    def test_session_revocation(self):
        admin, ha = self.login('admin')
        view, _ = self.login('view')
        rows = admin.get('/api/sessions').get_json()
        pid = [r for r in rows if r['username'] == 'view'][0]['public_id']
        self.assertEqual(view.get('/api/whoami').status_code, 200)
        self.assertEqual(admin.delete('/api/sessions/' + pid, headers=ha).status_code, 200)
        self.assertEqual(view.get('/api/whoami').status_code, 401)

    def test_csv_formula_injection_neutralized(self):
        admin, _ = self.login('admin')
        body = admin.get('/api/export/findings.csv').data.decode('utf-8')
        self.assertTrue(body.startswith('﻿'))
        self.assertIn("'=cmd|x", body)

    def test_public_pwa_assets_and_pages(self):
        anon = self.app.test_client()
        for path in ('/manifest.webmanifest', '/icon.svg', '/sw.js', '/login'):
            self.assertEqual(anon.get(path).status_code, 200, path)
        admin, _ = self.login('admin')
        for path in ('/', '/scan', '/assets', '/compare', '/help', '/account', '/accounts', '/settings',
                     '/topbar.js', '/api/compare', '/api/help'):
            self.assertEqual(admin.get(path).status_code, 200, path)

    def test_sse_first_event(self):
        admin, _ = self.login('admin')
        stream = admin.get('/api/scan/stream', buffered=False)
        self.assertIn('text/event-stream', stream.headers['Content-Type'])
        self.assertTrue(bytes(next(iter(stream.response))).startswith(b'data: '))
        stream.close()

    def test_password_change_revokes_other_sessions(self):
        c1, h1 = self.login('view')
        c2, _ = self.login('view')
        r = c1.post('/api/account/password', headers=h1,
                    json={'current_password': 'testpass123', 'new_password': 'brandnew123', 'confirm': 'brandnew123'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(c1.get('/api/whoami').status_code, 200)
        self.assertEqual(c2.get('/api/whoami').status_code, 401)


if __name__ == '__main__':
    unittest.main()
