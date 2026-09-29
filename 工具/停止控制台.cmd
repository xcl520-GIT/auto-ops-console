@echo off
rem 停止 auto-ops-console（双击即可）
rem ★ 逻辑在 AutoOpsConsole.exe 里，这里只是"双击能传参数"的壳。
chcp 65001 >nul
"%~dp0AutoOpsConsole.exe" stop
echo.
pause
