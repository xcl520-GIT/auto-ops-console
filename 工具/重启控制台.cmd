@echo off
rem 重启 auto-ops-console（双击即可）
rem ★ 逻辑在 AutoOpsConsole.exe 里，这里只是"双击能传参数"的壳。
rem   用途：改了代码之后让新代码生效（控制台不会自己热加载）。
chcp 65001 >nul
"%~dp0AutoOpsConsole.exe" restart
echo.
pause
