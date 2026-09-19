@echo off
rem Local test runner (ASCII only on purpose: cmd.exe misparses UTF-8 Korean text in .bat files).
rem   run_tests.bat            all tests + source self-check (--selftest)
rem   run_tests.bat quick      rule integrity + judge engine only (about 1 second)
rem   run_tests.bat NAME       one test file, e.g. run_tests.bat test_rules_windows_local
rem Never touches the real DB/accounts/settings (tests use temp folders and a temp registry key only).
setlocal
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8

if /i "%~1"=="quick" goto quick
if not "%~1"=="" goto single
goto full

:quick
python -m unittest discover -s tests -p "test_rule_*.py" -v
goto end

:single
python -m unittest discover -s tests -p "%~1.py" -v
goto end

:full
python -m unittest discover -s tests -v
if errorlevel 1 goto end
echo.
echo ===== source self-check (--selftest) =====
python scanner_engine\main.py --selftest

:end
echo.
pause
