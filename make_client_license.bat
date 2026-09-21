@echo off
cd /d "%~dp0"
set /p CLIENT="Client name: "
set /p EXPIRY="Expiry (YYYY-MM-DD): "
node make_license.js %EXPIRY% "%CLIENT%"
echo.
echo License generated: %~dp0license.key
pause