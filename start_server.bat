@echo off
title Hawk Threat Scanner Launcher
color 0b
echo ========================================================
echo   Starting Hawk Threat Scanner on localhost:8000
echo ========================================================
powershell -ExecutionPolicy Bypass -File "%~dp0start_server.ps1"
pause
