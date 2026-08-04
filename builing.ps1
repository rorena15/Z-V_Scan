# 에러 발생 시 즉시 중단
$ErrorActionPreference = "Stop"

# 버전 정보 변수 설정 (유지보수 용이성)
$VERSION = "v3.0.0"
$APP_NAME = "Z-VulnScan_Professional_Edition_$VERSION"
$DIST_DIR = "Z-VulnScan_Professional_Edition_$VERSION(01-02-newest)"

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " 🚀 Build Started: $APP_NAME" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

# 1. 기존 빌드 폴더 정리
Write-Host "`n[1/2] Cleaning previous build files..." -ForegroundColor Yellow
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "*.spec") { Remove-Item -Force "*.spec" }

# 2. EXE 패키징
Write-Host "`n[2/2] Packaging into EXE with PyInstaller..." -ForegroundColor Yellow

# PyInstaller 실행
pyinstaller --noconfirm --onefile --windowed --clean `
    --noupx `
    --name $APP_NAME `
    --icon "app_icon.ico" `
    --distpath $DIST_DIR `
    --add-data "scanner_engine/core;core" `
    --add-data "scanner_engine/utils;utils" `
    --add-data "scanner_engine/output;output" `
    --add-data "scanner_engine/gui;gui" `
    --add-data "rules;rules" `
    --add-data "app_icon.ico;." `
    --collect-all "reportlab" `
    --collect-all "openpyxl" `
    --collect-all "networkx" `
    --collect-all "matplotlib" `
    --collect-all "paramiko" `
    --collect-all "keyring" `
    --collect-all "pymysql" `
    --collect-all "psycopg2" `
    --collect-all "pymssql" `
    --hidden-import "winrm" `
    --hidden-import "wmi" `
    --hidden-import "core.database_inspector" `
    --hidden-import "PySide6.QtCore" `
    --hidden-import "PySide6.QtGui" `
    --hidden-import "PySide6.QtWidgets" `
    --hidden-import "utils.os_utils" `
    --hidden-import "utils.secure_storage" `
    --hidden-import "gui.topology_dialog" `
    scanner_engine/main.py

# 3. 결과 확인
if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=======================================================" -ForegroundColor Green
    Write-Host "  Build Success!" -ForegroundColor Green
    Write-Host "  Location: $DIST_DIR\$APP_NAME.exe" -ForegroundColor White
    Write-Host "=======================================================" -ForegroundColor Green
    
    # 폴더 열기
    Invoke-Item $DIST_DIR
} else {
    Write-Host "`n Build Failed! Check the error messages above." -ForegroundColor Red
}