@echo off
title Hawk Threat Scanner - Push to GitHub
color 0a
echo ========================================================
echo   Pushing Hawk Threat Scanner to GitHub
echo   Repository: https://github.com/ipraghavendra-dev/p2.git
echo ========================================================
echo.

set GIT_PATH=%LOCALAPPDATA%\MinGit\cmd\git.exe
if not exist "%GIT_PATH%" (
    set GIT_PATH=git
)

"%GIT_PATH%" add .
"%GIT_PATH%" commit -m "feat: complete Hawk Threat Scanner fullstack application" 2>nul
"%GIT_PATH%" branch -M main
"%GIT_PATH%" push -u origin main

echo.
echo ========================================================
echo   Push completed! You can now deploy on Render.com
echo ========================================================
pause
