# build_final_v3.ps1
#
# CI(.github/workflows/release.yml)와 로컬 수동 하이브리드 빌드가 공유하는 단일
# 소스. 예전에는 Z-VulnScan_Build_Work/ 안에만 있었고 .gitignore 대상이라 버전
# 관리가 안 됐다 - CI가 쓰려면 추적 대상 경로가 필요해서 이곳으로 옮겼다.
#
# 원본과의 차이는 딱 하나: $VERSION이 하드코딩("v3.0.0")이 아니라 -Version
# 파라미터로 받는다(기본값은 기존 하드코딩 값과 동일해서 로컬 수동 실행은 예전과
# 똑같이 동작). $DIST_DIR도 예전엔 "Z-VulnScan_Professional_v3.0.0_Final"로
# 따로 하드코딩돼 있어서 $VERSION을 바꿔도 폴더명이 안 바뀌는 버그가 있었는데,
# 이번에 $VERSION에서 파생되도록 고쳤다.
param(
    [string]$Version = "v3.0.0"
)

# 에러 발생 시 즉시 중단
$ErrorActionPreference = "Stop"

# 버전 정보
$VERSION = $Version
$APP_NAME = "Z-VulnScan_Professional_Edition_$VERSION"
$DIST_DIR = "Z-VulnScan_Professional_${VERSION}_Final"

# 난독화된 소스가 있는 위치
$SRC_DIR = "dist\obfuscated"

# rules/*_rules.json을 암호화해서 담아둘 스테이징 폴더 (평문 rules/*.json
# 자체는 여기 안 들어가고 .enc로만 들어간다 - 아래 [4/4] PyInstaller 단계가
# rules/ 대신 이 폴더를 배포판의 "rules"로 채택한다)
$RULES_STAGED_DIR = "dist\rules_staged"

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " 🚀 Hybrid Build Started: $APP_NAME" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------
# [1/4] rules/*_rules.json 암호화 스테이징
# ---------------------------------------------------------------------
Write-Host "[1/4] Encrypting rules/*_rules.json..." -ForegroundColor Yellow
python ci\encrypt_rules.py rules $RULES_STAGED_DIR
if ($LASTEXITCODE -ne 0) {
    Write-Host "`n ❌ Rules encryption failed!" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------
# [2/4] 누락된 모듈(Cython + GUI) 수동 병합
# ---------------------------------------------------------------------
Write-Host "[2/4] Merging modules into obfuscated folder..." -ForegroundColor Yellow

$modules_to_copy = @("core", "utils", "output", "gui")

foreach ($folder in $modules_to_copy) {
    $dest_path = "$SRC_DIR\scanner_engine\$folder"
    if (-not (Test-Path $dest_path)) {
        New-Item -ItemType Directory -Force -Path $dest_path | Out-Null
    }

    $source_path = "scanner_engine\$folder"

    if ($folder -eq "gui") {
        # GUI: .py 스크립트 복사
        if ((Get-ChildItem $dest_path).Count -eq 0) {
            Copy-Item "$source_path\*.py" -Destination $dest_path -Force
            Write-Host "   -> Copied GUI scripts (.py) to: $folder" -ForegroundColor Gray
        }
    }
    else {
        # Core/Utils/Output: .pyd 모듈 복사
        # [주의] discovery.py도 pyd로 변환되어 있어야 복사됨!
        if (Test-Path $source_path) {
            Copy-Item "$source_path\*.pyd" -Destination $dest_path -Force
            Write-Host "   -> Copied Cython modules (.pyd) for: $folder" -ForegroundColor Gray
        }
    }
}

# ---------------------------------------------------------------------
# [3/4] PyArmor 런타임 폴더 자동 감지
# ---------------------------------------------------------------------
$RUNTIME_DIR = Get-ChildItem "$SRC_DIR" -Directory -Filter "pyarmor_runtime_*" | Select-Object -ExpandProperty Name -First 1

if (-not $RUNTIME_DIR) {
    Write-Error "❌ PyArmor 런타임 폴더를 찾을 수 없습니다! 2단계(pyarmor gen)를 확인하세요."
    exit
}
Write-Host "[3/4] Found Runtime: $RUNTIME_DIR" -ForegroundColor Gray

# 기존 빌드 정리
if (Test-Path $DIST_DIR) { Remove-Item -Recurse -Force $DIST_DIR }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "*.spec") { Remove-Item -Force "*.spec" }

# ---------------------------------------------------------------------
# [4/4] PyInstaller 실행
# ---------------------------------------------------------------------
Write-Host "`n[4/4] Packaging into Single EXE..." -ForegroundColor Yellow

pyinstaller --noconfirm --onefile --windowed --clean `
    --noupx `
    --name $APP_NAME `
    --icon "app_icon.ico" `
    --distpath $DIST_DIR `
    --paths "$SRC_DIR" `
    --add-data "$SRC_DIR/$RUNTIME_DIR;${RUNTIME_DIR}" `
    `
    --add-data "$SRC_DIR/scanner_engine/core;scanner_engine/core" `
    --add-data "$SRC_DIR/scanner_engine/core;core" `
    `
    --add-data "$SRC_DIR/scanner_engine/utils;scanner_engine/utils" `
    --add-data "$SRC_DIR/scanner_engine/utils;utils" `
    `
    --add-data "$SRC_DIR/scanner_engine/output;scanner_engine/output" `
    --add-data "$SRC_DIR/scanner_engine/output;output" `
    `
    --add-data "$SRC_DIR/scanner_engine/gui;scanner_engine/gui" `
    --add-data "$SRC_DIR/scanner_engine/gui;gui" `
    `
    --add-data "$RULES_STAGED_DIR;rules" `
    --add-data "app_icon.ico;." `
    `
    --collect-all "reportlab" `
    --collect-all "openpyxl" `
    --collect-all "networkx" `
    --collect-all "matplotlib" `
    --collect-all "paramiko" `
    --collect-all "keyring" `
    --collect-all "bcrypt" `
    --collect-all "pynacl" `
    --collect-all "cryptography" `
    --exclude-module "matplotlib.tests" `
    --exclude-module "matplotlib.testing" `
    --hidden-import "PIL" `
    --hidden-import "PIL.Image" `
    --hidden-import "scanner_engine.core.discovery" `
    --hidden-import "scanner_engine.core.vuln_matcher" `
    --hidden-import "sqlite3" `
    --hidden-import "_sqlite3" `
    --hidden-import "PySide6.QtWebEngineWidgets" `
    --hidden-import "PySide6.QtWebEngineCore" `
    --hidden-import "PySide6.QtXml" `
    --hidden-import "PySide6.QtNetwork" `
    --hidden-import "PySide6.QtPrintSupport" `
    --hidden-import "winrm" `
    --hidden-import "wmi" `
    --hidden-import "re" `
    --hidden-import "PySide6.QtCore" `
    --hidden-import "PySide6.QtGui" `
    --hidden-import "PySide6.QtWidgets" `
    --hidden-import "utils" `
    --hidden-import "utils.logger" `
    --hidden-import "utils.os_utils" `
    --hidden-import "utils.secure_storage" `
    --hidden-import "gui" `
    "$SRC_DIR/scanner_engine/main.py"

# 4. 결과 확인
if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=======================================================" -ForegroundColor Green
    Write-Host " 🎉 BUILD SUCCESS! (Hybrid Obfuscation Complete)" -ForegroundColor Green
    Write-Host " 📂 Output: $DIST_DIR\$APP_NAME.exe" -ForegroundColor White
    Write-Host "=======================================================" -ForegroundColor Green

    if ($env:CI -ne "true") {
        Invoke-Item $DIST_DIR
    }
}
else {
    Write-Host "`n ❌ Build Failed!" -ForegroundColor Red
    exit 1
}
