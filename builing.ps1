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

# 2. EXE 패키징
Write-Host "`n[2/2] Packaging into EXE with PyInstaller..." -ForegroundColor Yellow

# [수정] --key 옵션 제거 & paramiko/winrm 의존성 강화
pyinstaller --noconfirm --onefile --windowed --clean `
    --name "Z-VulnScan_Enterprise_v2.1.0_Alpha_Potable" `
    --icon "app_icon.ico" `
    --paths "." `
    --add-data "scanner_engine/core;core" `
    --add-data "scanner_engine/utils;utils" `
    --add-data "scanner_engine/output;output" `
    --add-data "rules;rules" `
    --add-data "app_icon.ico;." `
    --collect-all "reportlab" `
    --collect-all "scapy" `
    --collect-all "openpyxl" `
    --collect-all "paramiko" `
    --hidden-import "winrm" `
    --hidden-import "wmi" `
    --hidden-import "PyQt5" `
    --hidden-import "utils.os_utils" `
    scanner_engine/gui/main_gui.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ Build Success! File located at: dist/Z-VulnScan_Enterprise_v2.1.0_Alpha_Potable.exe" -ForegroundColor Green
} else {
    Write-Host "`n❌ Build Failed!" -ForegroundColor Red
}