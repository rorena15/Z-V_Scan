# 에러 발생 시 즉시 중단
$ErrorActionPreference = "Stop"

# 버전 정보 변수 설정 (유지보수 용이성)
$APP_NAME = "Z-VulnScan_Professional_Edition_v2.2.0"
$DIST_DIR = "Z-VulnScan_Professional_Edition_v2.2.0(Stable)"

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
# --noupx: 백신 오탐 방지를 위해 압축 해제 (중요)
# --collect-all "scapy": 제거됨 (더 이상 안 씀)
pyinstaller --noconfirm --onefile --windowed --clean `
    --noupx `
    --name $APP_NAME `
    --icon "app_icon.ico" `
    --distpath $DIST_DIR `
    --add-data "scanner_engine/core;core" `
    --add-data "scanner_engine/utils;utils" `
    --add-data "scanner_engine/output;output" `
    --add-data "rules;rules" `
    --add-data "app_icon.ico;." `
    --collect-all "reportlab" `
    --collect-all "openpyxl" `
    --collect-all "paramiko" `
    --collect-all "keyring" `
    --hidden-import "winrm" `
    --hidden-import "wmi" `
    --hidden-import "PySide6" `
    --hidden-import "utils.os_utils" `
    --hidden-import "utils.secure_storage" `
    scanner_engine/gui/main_gui.py

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