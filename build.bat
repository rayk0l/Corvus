@echo off
REM Always run from the directory where build.bat lives
cd /d "%~dp0"

echo ============================================
echo   Corvus Endpoint Scanner - Build (Nuitka)
echo   v2.0
echo ============================================
echo.

REM -------------------------------------------------------
REM  PREREQUISITES:
REM   1. Python 3.10+ with pip
REM   2. C compiler: MSVC (Visual Studio Build Tools) or MinGW-w64
REM      MSVC: https://visualstudio.microsoft.com/visual-cpp-build-tools/
REM      MinGW: choco install mingw  (or https://winlibs.com/)
REM      Nuitka can auto-download MinGW if MSVC is not found.
REM -------------------------------------------------------

REM Install dependencies
echo [*] Installing dependencies...
pip install psutil yara-python tqdm nuitka ordered-set zstandard 2>nul
echo.

echo [*] Building corvus.exe with Nuitka...
echo [i] This compiles Python to C, then to native binary.
echo [i] First build takes 5-10 minutes. Subsequent builds are faster (cached).
echo.

set PYTHONPATH=src
python -m nuitka ^
    --onefile ^
    --standalone ^
    --zig ^
    --output-dir=. ^
    --output-filename=corvus.exe ^
    --include-package=scanner_core ^
    --include-package=scanners ^
    --include-package=report ^
    --include-module=yara ^
    --include-module=tqdm ^
    --include-data-dir=iocs=iocs ^
    --include-data-dir=yara_rules=yara_rules ^
    --include-data-files=config.json=config.json ^
    --nofollow-import-to=tkinter ^
    --nofollow-import-to=_tkinter ^
    --nofollow-import-to=unittest ^
    --nofollow-import-to=pydoc ^
    --nofollow-import-to=doctest ^
    --nofollow-import-to=xmlrpc ^
    --nofollow-import-to=ftplib ^
    --nofollow-import-to=imaplib ^
    --nofollow-import-to=smtplib ^
    --nofollow-import-to=nntplib ^
    --nofollow-import-to=curses ^
    --nofollow-import-to=lib2to3 ^
    --nofollow-import-to=test ^
    --nofollow-import-to=idlelib ^
    --nofollow-import-to=pip ^
    --nofollow-import-to=setuptools ^
    --nofollow-import-to=nuitka ^
    --windows-console-mode=force ^
    --windows-icon-from-ico=corvus.ico ^
    --company-name="Corvus Security" ^
    --product-name="Corvus Endpoint Scanner" ^
    --file-version=2.0.0.0 ^
    --product-version=2.0.0.0 ^
    --file-description="Corvus - Endpoint Threat Detection Scanner" ^
    --onefile-tempdir-spec="{CACHE_DIR}/corvus_runtime" ^
    --onefile-no-compression ^
    --remove-output ^
    --assume-yes-for-downloads ^
    src/main.py

echo.
if exist "corvus.exe" (
    echo ============================================
    echo   BUILD SUCCESSFUL
    echo ============================================
    echo.
    echo [+] Output: corvus.exe ^(project root^)
    for %%F in (corvus.exe) do echo [+] Size : %%~zF bytes
    echo.
    echo [i] IMPORTANT: Add Windows Defender exclusions before first run:
    echo     powershell -Command "Add-MpPreference -ExclusionPath '%CD%\corvus.exe'"
    echo     powershell -Command "Add-MpPreference -ExclusionPath '%LOCALAPPDATA%\corvus_runtime'"
    echo.
    echo [i] To further reduce AV false positives:
    echo     1. Sign the executable with a code signing certificate:
    echo        signtool sign /a /tr http://timestamp.digicert.com /td SHA256 corvus.exe
    echo     2. Submit false positive reports to AV vendors
    echo     3. Consider EV code signing for near-zero false positives
) else (
    echo ============================================
    echo   BUILD FAILED
    echo ============================================
    echo.
    echo [!] Check output above for errors.
    echo.
    echo [i] Common issues:
    echo     - Missing C compiler: install Visual Studio Build Tools or MinGW-w64
    echo     - Missing dependencies: pip install nuitka ordered-set zstandard
    echo     - yara-python: ensure yara-python is installed correctly
)
echo.
pause
