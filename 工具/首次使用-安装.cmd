@echo off
rem =====================================================================
rem  auto-ops-console -- first-run setup  (bootstrap, PURE ASCII on purpose)
rem
rem  WHY THIS FILE IS ALL-ENGLISH / ALL-ASCII:
rem    cmd.exe reads a .cmd file using the OEM code page, NOT UTF-8.
rem    Any non-ASCII byte gets shredded and the script fails to parse
rem    (we hit exactly that during development: "'Y' is not recognized").
rem    => the bootstrap stays ASCII; the real work (and all Chinese text)
rem       is done by a Python helper, which handles UTF-8 properly.
rem
rem  WHAT IT DOES:
rem    1) find a usable python (3.10+) -- same 6-tier search the launcher uses
rem    2) hand over to  install.py  (it does the actual setup, in Chinese)
rem =====================================================================
setlocal
set "HERE=%~dp0"
set "PROJ=%HERE%.."
set "REPO=%PROJ%\repo"

echo.
echo ================ auto-ops-console :: first-run setup ================
echo   project: %PROJ%
echo.

rem ---- 1) find python ---------------------------------------------------
set "PY="
set "PYARGS="

if not "%AOC_PYTHON%"=="" (
    set "PY=%AOC_PYTHON%"
    goto :checkpy
)

rem tier 2: "python" on PATH
for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PY set "PY=%%i"
)

rem tier 3: python3 / tier 4: the official py launcher
if not defined PY (
    for /f "delims=" %%i in ('where python3 2^>nul') do (
        if not defined PY set "PY=%%i"
    )
)
if not defined PY (
    for /f "delims=" %%i in ('where py 2^>nul') do (
        if not defined PY (
            set "PY=%%i"
            set "PYARGS=-3"
        )
    )
)

rem tier 5: per-user / machine-wide default install locations
if not defined PY (
    for %%d in (
        "%LOCALAPPDATA%\Programs\Python"
        "%ProgramFiles%\Python"
        "%ProgramFiles(x86)%\Python"
    ) do (
        for /f "delims=" %%i in ('dir /b /o-n "%%~d\Python3*\python.exe" 2^>nul') do (
            if not defined PY set "PY=%%~d\%%i"
        )
    )
)

rem tier 6 (LAST resort): the author's own interpreter path -- NOT portable.
if not defined PY (
    if exist "D:\Python311\python.exe" set "PY=D:\Python311\python.exe"
)

:checkpy
if not defined PY (
    echo   [X] No python found.  Tried: AOC_PYTHON, PATH, python3, py -3,
    echo       %%LOCALAPPDATA%%\Programs\Python, %%ProgramFiles%%\Python.
    echo.
    echo   Please install Python 3.10 or newer, then run this file again:
    echo       https://www.python.org/downloads/windows/
    echo   ^(tick "Add python.exe to PATH" during install^)
    echo.
    pause
    exit /b 2
)

rem ---- 2) version check + hand over -------------------------------------
echo   [1/2] using: %PY% %PYARGS%
"%PY%" %PYARGS% -c "import sys;raise SystemExit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
if errorlevel 1 (
    echo   [X] That python is too old -- this project needs 3.10 or newer
    echo       ^(the code uses "X | Y" type hints^).
    echo       Found: & "%PY%" %PYARGS% --version
    echo.
    echo   Set AOC_PYTHON to a newer interpreter and run this file again.
    pause
    exit /b 3
)

echo   [2/2] handing over to the installer ^(Chinese text from here on^)...
echo.
"%PY%" %PYARGS% "%HERE%install.py"
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo Done.
) else (
    echo The installer exited with code %RC% -- see the messages above.
)
echo.
pause
exit /b %RC%
