@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [nasrun] 필요한 라이브러리 설치 (paramiko, keyring)
python -m pip install --upgrade paramiko keyring
if errorlevel 1 ( echo Python이 설치돼 있는지 확인하세요. & pause & exit /b 1 )
echo.
echo [nasrun] NAS 접속 정보와 비밀번호를 설정합니다.
python nasrun.py setup
pause
