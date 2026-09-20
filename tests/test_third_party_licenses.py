"""오픈소스 라이선스 고지 데이터/화면 검사 - 배포물에 들어가는 고지가 비어 있거나 '확인 필요'가 남아 있으면 실패시킨다."""
import json
import os
import unittest

import _helpers as h

PATH = os.path.join(h.ROOT, 'scanner_engine', 'gui', 'web', 'third_party_licenses.json')


class ThirdPartyLicenses(unittest.TestCase):
    def setUp(self):
        with open(PATH, encoding='utf-8') as f:
            self.packages = json.load(f)['packages']

    def test_every_requirement_is_listed_with_a_known_license(self):
        names = {p['name'].lower().replace('_', '-') for p in self.packages}
        for req in ('flask', 'paramiko', 'pyside6', 'cryptography', 'reportlab', 'pymssql', 'psycopg2-binary', 'openpyxl'):
            self.assertIn(req, names, req)
        unknown = [p['name'] for p in self.packages if p['license'] == '확인 필요']
        self.assertEqual(unknown, [], f"라이선스 이름을 못 찾은 패키지: {unknown}")

    def test_license_full_text_is_included(self):
        missing = [p['name'] for p in self.packages if not p['text'].strip()]
        self.assertEqual(missing, [], f"라이선스 전문이 없는 패키지: {missing}")

    def test_settings_dialog_tab_lists_every_package(self):
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        from PySide6.QtWidgets import QApplication, QListWidget
        app = QApplication.instance() or QApplication([])
        from gui.settings_dialog import SettingsDialog
        dlg = SettingsDialog(object())
        labels = [dlg.nav_list.item(i).text() for i in range(dlg.nav_list.count())]
        self.assertIn('오픈소스 라이선스', labels)
        page = dlg.pages.widget(labels.index('오픈소스 라이선스'))
        lst = page.findChild(QListWidget)
        self.assertEqual(lst.count(), len(self.packages))
        del app


if __name__ == '__main__':
    unittest.main()
