@echo off
rem ===================================================================
rem T18  build-launcher.cmd  --  rebuild the one-click launcher.
rem
rem *** THIS FILE MUST STAY PURE ASCII.  NO EXCEPTIONS. ***
rem   cmd.exe reads a .bat using the OEM code page, NOT the code page set
rem   below.  Any non-ASCII byte (even inside a rem line) can swallow the
rem   following ASCII characters, and the line then breaks into fragments
rem   that cmd tries to run as commands.  Observed: 'Y' is not recognized,
rem   'et' is not recognized, 'hinese' is not recognized.
rem   -> Chinese explanation lives in the launcher doc (.md). This file: ASCII only.
rem
rem WHY NO INSTALL IS NEEDED:
rem   the built-in .NET Framework C# compiler is enough.  It is the OLD one
rem   C# 5 only: things like  out string why  fail with CS1513 / CS1520.
rem
rem VERDICT  spec 12.142:
rem   this product is NOT byte-reproducible.  Compiling the same source twice
rem   yields two different hashes.  Acceptance is therefore:
rem   same size + same behaviour + source sha256.  NOT product hash equality.
rem ===================================================================
chcp 65001 >nul
setlocal
set "HERE=%~dp0"
set "SRC=%HERE%launcher\AutoOpsConsole.cs"
set "OUT=%HERE%AutoOpsConsole.exe"
set "CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo [X] csc.exe not found - this script deliberately requires no installation.
  echo     looked for: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
  echo                 C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
  exit /b 2
)

echo ---- auto-ops-console launcher :: build ----
echo   compiler : %CSC%
echo   source   : %SRC%
echo   output   : %OUT%
echo.

"%CSC%" /nologo /optimize+ /target:exe /out:"%OUT%" "%SRC%"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo [X] build failed, exit code %RC%
  echo     NOTE: old C# 5 compiler. C# 7 syntax such as   out string why   gives CS1513 / CS1520.
  exit /b %RC%
)

echo.
echo   [OK] built
echo.
echo ---- fingerprints ----
rem certutil prints its labels LOCALIZED and in the OEM code page, and it also
rem writes its own error text to stderr. Both pollute captured output, so keep
rem only the hash lines: they are pure hex and contain no colon.
echo [source sha256]
certutil -hashfile "%SRC%" SHA256 2>nul | findstr /v ":"
echo [output sha256] - differs every run, this is expected, see spec 12.142
certutil -hashfile "%OUT%" SHA256 2>nul | findstr /v ":"
for %%A in ("%OUT%") do echo [output size] %%~zA bytes
echo.
echo Verdict: same size + same behaviour + source sha256. Product hash equality is NOT required.
exit /b 0
