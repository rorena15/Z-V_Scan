# 에러 발생 시 즉시 중단
$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " 🚀 Z-VulnScan Enterprise Build (Standard)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. 기존 빌드 폴더 정리
Write-Host "`n[1/2] Cleaning previous build files..." -ForegroundColor Yellow
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "*.spec") { Remove-Item -Force "*.spec" }
if (Test-Path "Z-VulnScan_Enterprise_v2.1_Alpha") { Remove-Item -Recurse -Force "Z-VulnScan_Enterprise_v2.1_Alpha" }

# 2. EXE 패키징
Write-Host "`n[2/2] Packaging into EXE with PyInstaller..." -ForegroundColor Yellow

# PyInstaller 실행
# --collect-all: 라이브러리의 모든 데이터/바이너리를 강제로 포함 (에러 방지용)
pyinstaller --noconfirm --onefile --windowed --clean `
    --name "Z-VulnScan_Professional_Edition_v2.1.0_Alpha" `
    --icon "app_icon.ico" `
    --distpath "Z-VulnScan_Professional_Edition_v2.1_Alpha" `
    --add-data "scanner_engine/core;core" `
    --add-data "scanner_engine/utils;utils" `
    --add-data "scanner_engine/output;output" `
    --add-data "rules;rules" `
    --add-data "app_icon.ico;." `
    --collect-all "reportlab" `
    --collect-all "scapy" `
    --collect-all "openpyxl" `
    --collect-all "paramiko" `
    --collect-all "keyring" `
    --hidden-import "winrm" `
    --hidden-import "wmi" `
    --hidden-import "PyQt5" `
    --hidden-import "utils.os_utils" `
    --hidden-import "utils.secure_storage" `
    scanner_engine/gui/main_gui.py

# 3. 결과 확인
if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=======================================================" -ForegroundColor Green
    Write-Host " ✅ Build Success!" -ForegroundColor Green
    Write-Host " 📂 Output: Z-VulnScan_Professional_Edition_v2.1_Alpha\Z-VulnScan_Professional_Edition_v2.1_Alpha.exe" -ForegroundColor White
    Write-Host "=======================================================" -ForegroundColor Green
    
    # (선택) 탐색기로 폴더 열기
    Invoke-Item "Z-VulnScan_Professional_Edition_v2.1_Alpha"
} else {
    Write-Host "`n❌ Build Failed! Check the error messages above." -ForegroundColor Red
}