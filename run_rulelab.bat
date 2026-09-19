@echo off
rem Rule Lab launcher - opens the rule what-if screen in your browser (dev/QA tool, not shipped in the exe).
rem ASCII only on purpose: cmd.exe misparses UTF-8 Korean text in .bat files. Stop with Ctrl+C.
setlocal
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
python tests\rule_lab.py
pause
