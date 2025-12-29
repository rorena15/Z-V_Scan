pyinstaller --noconfirm --onefile --windowed --clean `
    --name "Z-VulnScan_Enterprise_v2.1" `
    --icon "app_icon.ico" `
    --paths "dist/obf" `
    --add-data "dist/obf/scanner_engine/core;core" `
    --add-data "dist/obf/scanner_engine/utils;utils" `
    --add-data "dist/obf/scanner_engine/output;output" `
    --add-data "rules;rules" `
    --add-data "app_icon.ico;." `
    --hidden-import "openpyxl" `
    --hidden-import "reportlab" `
    --hidden-import "winrm" `
    --hidden-import "paramiko" `
    --hidden-import "PyQt5" `
    --collect-all "scapy" `
    --collect-all "openpyxl" `
    dist/obf/scanner_engine/gui/main_gui.py