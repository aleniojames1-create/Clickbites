@echo off
setlocal
cd /d "%~dp0"
title ClickBites - Repair and Setup
where node >nul 2>nul || (echo ERROR: Node.js is not installed or not in PATH.& echo Install Node.js 22.16+ and reopen CMD.& pause& exit /b 1)
node -e "const v=process.versions.node.split('.').map(Number); if(v[0]<22 || (v[0]===22 && v[1]<16)){console.error('ERROR: Node.js 22.16+ is required. Found '+process.version); process.exit(1)}"
if errorlevel 1 (pause & exit /b 1)
node scripts/setup-windows.mjs
if errorlevel 1 (echo.&echo Setup failed. Review the error above.&pause&exit /b 1)
echo.&echo ClickBites setup completed successfully.
pause
