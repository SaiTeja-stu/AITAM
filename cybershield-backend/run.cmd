@echo off
REM Cyber Shield backend - dev launcher (cmd.exe). Usage: run.cmd
setlocal

if "%CYBERSHIELD_JWT_SECRET%"==""     set CYBERSHIELD_JWT_SECRET=dev-jwt-secret-change-me-at-least-32-characters
if "%CYBERSHIELD_HMAC_SECRET%"==""    set CYBERSHIELD_HMAC_SECRET=dev-hmac-secret-change-me
if "%CYBERSHIELD_ADMIN_USER%"==""     set CYBERSHIELD_ADMIN_USER=admin
if "%CYBERSHIELD_ADMIN_PASSWORD%"=="" set CYBERSHIELD_ADMIN_PASSWORD=admin-password-123456
if "%CYBERSHIELD_DB_PATH%"==""        set CYBERSHIELD_DB_PATH=./data/cybershield.db
if "%CYBERSHIELD_ARCHIVE_DIR%"==""    set CYBERSHIELD_ARCHIVE_DIR=./data/archive
if "%PORT%"==""                       set PORT=8899

echo.
echo Cyber Shield backend starting...
echo   API     : http://localhost:%PORT%
echo   Swagger : http://localhost:%PORT%/swagger-ui.html
echo   Admin   : %CYBERSHIELD_ADMIN_USER% / %CYBERSHIELD_ADMIN_PASSWORD%
echo.

call "%~dp0gradlew.bat" bootRun
endlocal
