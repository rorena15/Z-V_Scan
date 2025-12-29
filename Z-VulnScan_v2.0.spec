# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('dist/obf/scanner_engine/core', 'core'), ('dist/obf/scanner_engine/utils', 'utils'), ('app_icon.ico', '.')]
binaries = []
hiddenimports = ['PyQt5', 'reportlab', 'reportlab.graphics.charts.piecharts', 'reportlab.pdfbase.ttfonts', 'winrm', 'paramiko', 'sqlite3']
tmp_ret = collect_all('scapy')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['dist\\obf\\scanner_engine\\gui\\main_gui.py'],
    pathex=['dist/obf'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Z-VulnScan_v2.0',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['app_icon.ico'],
)
