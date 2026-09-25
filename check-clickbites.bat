@echo off
setlocal
cd /d "%~dp0"
echo ==============================================
echo          ClickBites Diagnostic Check
 echo ==============================================
where node >nul 2>nul && (echo Node.js: OK) || (echo Node.js: MISSING)
where npm >nul 2>nul && (echo npm: OK) || (echo npm: MISSING)
if exist package.json (echo package.json: OK) else (echo package.json: MISSING)
if exist node_modules (echo node_modules: OK) else (echo node_modules: MISSING - run npm install)
if exist .env (echo .env: OK) else (echo .env: MISSING - run copy .env.example .env)
if exist data (echo database folder: OK) else (echo database folder: MISSING)
if exist public\index.html (echo frontend: OK) else (echo frontend: MISSING)
if exist server\server.js (echo backend: OK) else (echo backend: MISSING)
call npm run build
if errorlevel 1 echo Build check: FAILED
if exist data\clickbites.db (echo database file: FOUND) else (echo database file: not created yet - it will be created on first server start)
echo.
echo Recommended:
echo   npm install
 echo   npm run seed:admin
 echo   npm start
pause
