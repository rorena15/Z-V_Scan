# -*- mode: python ; coding: utf-8 -*-
# Z-VulnScan 배포 빌드용 PyInstaller spec (onedir).
#
# ci/build_final_v3.ps1이 아래 환경변수를 채워서 호출한다:
#   ZVULN_APP_NAME    - 결과 폴더/exe 이름 (예: Z-VulnScan_Professional_Edition_v3.0.5)
#   ZVULN_RUNTIME_DIR - PyArmor 런타임 폴더명 (예: pyarmor_runtime_000000, 버전마다 달라질 수 있음)
# 실행 위치는 저장소 루트다(dist/obfuscated, dist/rules_staged가 거기 있음).
#
# [onedir을 쓰는 이유] PySide6/paramiko/psycopg2/pymssql은 LGPL이라, 사용자가 그 라이브러리를 수정본으로
# 교체할 수 있어야 한다. onefile은 exe 안에 묶여 교체가 사실상 어렵고, onedir은 라이브러리가
# 폴더(_internal)에 파일로 남아 교체 가능하다. 배포는 폴더째(zip)로 한다.
import os

from PyInstaller.utils.hooks import collect_all

ROOT = os.path.dirname(SPECPATH)  # noqa: F821  (SPECPATH는 PyInstaller가 주입)
APP_NAME = os.environ["ZVULN_APP_NAME"]
RUNTIME_DIR = os.environ["ZVULN_RUNTIME_DIR"]
SRC = os.path.join(ROOT, "dist", "obfuscated")


def p(*parts):
    return os.path.join(ROOT, *parts)


datas = [
    (os.path.join(SRC, RUNTIME_DIR), RUNTIME_DIR),
    (os.path.join(SRC, "scanner_engine", "core"), "scanner_engine/core"),
    (os.path.join(SRC, "scanner_engine", "core"), "core"),
    (os.path.join(SRC, "scanner_engine", "utils"), "scanner_engine/utils"),
    (os.path.join(SRC, "scanner_engine", "utils"), "utils"),
    (os.path.join(SRC, "scanner_engine", "output"), "scanner_engine/output"),
    (os.path.join(SRC, "scanner_engine", "output"), "output"),
    (os.path.join(SRC, "scanner_engine", "gui"), "scanner_engine/gui"),
    (os.path.join(SRC, "scanner_engine", "gui"), "gui"),
    (p("dist", "rules_staged"), "rules"),
    (p("app_icon.ico"), "."),
]

# 기본 설정 파일만 넣는다. config/ 폴더 전체를 넣으면 개발 PC의 웹 대시보드 계정(bcrypt 해시),
# API 토큰, 감사 로그 같은 개인 파일이 배포물에 섞일 수 있어 명시한 4개만 포함한다.
for name in ("app_settings.json", "expert_profile.json", "revoked_licenses.json", "rule_update_config.json"):
    path = p("config", name)
    if os.path.exists(path):
        datas.append((path, "config"))

binaries = []
hiddenimports = [
    "scanner_engine.core.discovery", "scanner_engine.core.vuln_matcher",
    "sqlite3", "_sqlite3", "winrm", "re",
    "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineCore", "PySide6.QtXml", "PySide6.QtNetwork",
    "PySide6.QtPrintSupport", "PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets",
    "utils", "utils.logger", "utils.os_utils", "utils.secure_storage", "gui",
    "web_dashboard_server",
]

for pkg in ("reportlab", "openpyxl", "paramiko", "keyring", "bcrypt", "pynacl", "cryptography",
            "pymysql", "psycopg2", "pymssql", "oracledb",
            # 웹 대시보드 모드(web_dashboard_server.py)
            "flask", "werkzeug", "jinja2"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

a = Analysis(
    [os.path.join(SRC, "scanner_engine", "main.py")],
    pathex=[SRC],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    # LGPL 순수 Python 라이브러리(paramiko 등)도 사용자가 파일로 교체할 수 있도록 .pyc를 exe 안의 PYZ에 묶지 않고
    # _internal 폴더에 낱개 파일로 둔다.
    noarchive=True,
    optimize=0,
)

# [라이선스] PySide6 wheel에는 Qt 전 모듈이 들어 있어 PyInstaller가 우리 코드가 쓰지 않는 것까지 배포 폴더에 담는다.
# 그중 Qt Graphs / Qt Quick 3D / Qt Virtual Keyboard는 Qt 문서상 GPLv3(또는 상용 라이선스)로만 제공되는 모듈이라
# 독점 소프트웨어에 넣어 배포하면 안 된다. 우리는 QtCore/Gui/Widgets/Network/Xml/PrintSupport와 QtWebEngine만 쓰므로
# 그 GPL 전용 모듈과, 안 쓰는 큰 모듈(용량 절감 + 라이선스 확인 대상 축소)을 배포물에서 뺀다.
# release.yml이 빌드 후 이 파일들이 없는지 다시 검사한다.
_BLOCKED_QT = (
    "Qt63D", "Qt6Graphs", "Qt6Quick3D", "Qt6VirtualKeyboard", "Qt6Charts", "Qt6DataVisualization",
    "Qt6Multimedia", "Qt6SpatialAudio", "Qt6Location", "Qt6Sensors", "Qt6RemoteObjects", "Qt6Scxml",
    "Qt6TextToSpeech", "Qt6WebView",
)
_BLOCKED_DIRS = (
    "qt3d", "qtgraphs", "qtquick3d", "qtvirtualkeyboard", "qtcharts", "qtdatavisualization",
    "qtmultimedia", "qtlocation", "qtsensors", "qtremoteobjects", "qtscxml", "qttexttospeech", "qtwebview",
    "virtualkeyboard", "multimedia", "qmltooling",
)


def _is_blocked(dest):
    d = dest.replace("\\", "/")
    name = d.rsplit("/", 1)[-1]
    if any(name.startswith(prefix) for prefix in _BLOCKED_QT):
        return True
    parts = [seg.lower() for seg in d.split("/")]
    if "pyside6" in parts:
        return any(seg in _BLOCKED_DIRS for seg in parts)
    return False


a.binaries = [t for t in a.binaries if not _is_blocked(t[0])]
a.datas = [t for t in a.datas if not _is_blocked(t[0])]

pyz = PYZ(a.pure)  # noqa: F821

# 부팅 진행바: assets/splash.png의 빈 막대(약 x75~525, y272~294) 안에 main.py가 pyi_splash.update_text()로
# ASCII 진행 문구를 갱신한다(비-ASCII/대괄호는 PyInstaller 스플래시 버그로 금지 - main.py 주석 참고).
splash = Splash(  # noqa: F821
    p("assets", "splash.png"),
    binaries=a.binaries,
    datas=a.datas,
    text_pos=(90, 290),
    text_size=10,
    text_color="#9FB0CF",
    text_default="Starting...",
    minify_script=True,
    always_on_top=False,
)

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    splash,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[p("app_icon.ico")],
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    splash.binaries,
    strip=False,
    upx=False,
    name=APP_NAME,
)
