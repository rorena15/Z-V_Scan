# 에러 발생 시 즉시 중단
$ErrorActionPreference = "Stop"

# 버전 정보
$VERSION = "v3.0.0"
$APP_NAME = "Z-VulnScan_Professional_Edition_$VERSION"
$DIST_DIR = "Z-VulnScan_Professional_v3.0.0_Final"

# 난독화된 소스가 있는 위치
$SRC_DIR = "dist\obfuscated" 

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " 🚀 Hybrid Build Started: $APP_NAME" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------
# [1/3] 누락된 모듈(Cython + GUI) 수동 병합
# ---------------------------------------------------------------------
Write-Host "[1/3] Merging modules into obfuscated folder..." -ForegroundColor Yellow

$modules_to_copy = @("core", "utils", "output", "gui") 

foreach ($folder in $modules_to_copy) {
    $dest_path = "$SRC_DIR\scanner_engine\$folder"
    if (-not (Test-Path $dest_path)) {
        New-Item -ItemType Directory -Force -Path $dest_path | Out-Null
    }

    $source_path = "scanner_engine\$folder"
    
    if ($folder -eq "gui") {
        # GUI: .py 스크립트 복사 (빈 폴더 방지)
        if ((Get-ChildItem $dest_path).Count -eq 0) {
             Copy-Item "$source_path\*.py" -Destination $dest_path -Force
             Write-Host "   -> Copied GUI scripts (.py) to: $folder" -ForegroundColor Gray
        }
    } else {
        # Core/Utils/Output: .pyd 모듈 복사
        if (Test-Path $source_path) {
            Copy-Item "$source_path\*.pyd" -Destination $dest_path -Force
            Write-Host "   -> Copied Cython modules (.pyd) for: $folder" -ForegroundColor Gray
        }
    }
}

# ---------------------------------------------------------------------
# [2/3] PyArmor 런타임 폴더 자동 감지
# ---------------------------------------------------------------------
$RUNTIME_DIR = Get-ChildItem "$SRC_DIR" -Directory -Filter "pyarmor_runtime_*" | Select-Object -ExpandProperty Name -First 1

if (-not $RUNTIME_DIR) {
    Write-Error "❌ PyArmor 런타임 폴더를 찾을 수 없습니다! 2단계(pyarmor gen)를 확인하세요."
    exit
}
Write-Host "[2/3] Found Runtime: $RUNTIME_DIR" -ForegroundColor Gray

# 기존 빌드 정리
if (Test-Path $DIST_DIR) { Remove-Item -Recurse -Force $DIST_DIR }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "*.spec") { Remove-Item -Force "*.spec" }

# ---------------------------------------------------------------------
# [3/3] PyInstaller 실행 (PyVis & WebEngine 추가됨)
# ---------------------------------------------------------------------
Write-Host "`n[3/3] Packaging into Single EXE..." -ForegroundColor Yellow

# [Fix Key Point]
# 기존 경로 매핑 로직 유지 (루트/하위 폴더 이중 매핑) + PyVis/WebEngine 추가

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
    --add-data "rules;rules" `
    --add-data "app_icon.ico;." `
    `
    --collect-all "pyvis" `
    --collect-all "reportlab" `
    --collect-all "openpyxl" `
    --collect-all "networkx" `
    --collect-all "matplotlib" `
    --collect-all "paramiko" `
    --collect-all "keyring" `
    `
    --exclude-module "matplotlib.tests" `
    --exclude-module "matplotlib.testing" `
    `
    --hidden-import "PySide6.QtWebEngineWidgets" `
    --hidden-import "PySide6.QtWebEngineCore" `
    --hidden-import "PySide6.QtXml" `
    --hidden-import "PySide6.QtNetwork" `
    --hidden-import "PySide6.QtPrintSupport" `
    --hidden-import "winrm" `
    --hidden-import "wmi" `
    --hidden-import "PySide6.QtCore" `
    --hidden-import "PySide6.QtGui" `
    --hidden-import "PySide6.QtWidgets" `
    --hidden-import "utils" `
    --hidden-import "utils.logger" `
    --hidden-import "utils.os_utils" `
    --hidden-import "utils.secure_storage" `
    --hidden-import "gui.topology_dialog" `
    --hidden-import "gui" `
    "$SRC_DIR/scanner_engine/main.py"

# 4. 결과 확인
if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=======================================================" -ForegroundColor Green
    Write-Host " 🎉 BUILD SUCCESS! (Hybrid Obfuscation Complete)" -ForegroundColor Green
    Write-Host " 📂 Output: $DIST_DIR\$APP_NAME.exe" -ForegroundColor White
    Write-Host "=======================================================" -ForegroundColor Green
    
    Invoke-Item $DIST_DIR
} else {
    Write-Host "`n ❌ Build Failed!" -ForegroundColor Red
}