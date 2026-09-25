@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul || (echo ERROR: Node.js is not installed or not in PATH.& pause& exit /b 1)
if not exist node_modules (echo Installing dependencies...& npm install& if errorlevel 1 goto :fail)
if not exist .env copy /y .env.example .env >nul
start "ClickBites Backend" cmd /k "cd /d "%~dp0" && npm run server"
echo Waiting briefly for the backend to start...
timeout /t 4 /nobreak >nul
start "ClickBites Frontend" cmd /k "cd /d "%~dp0" && npm run dev"
echo ClickBites backend and frontend are starting in separate CMD windows.
exit /b 0
:fail
echo Failed to install dependencies.
pause
exit /b 1
