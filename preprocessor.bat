@echo off

cd /d "%~dp0"

WHERE py >nul 2>nul
IF %ERRORLEVEL% EQU 0 (py -3 preprocessor.py %*) ELSE (python preprocessor.py %*)

pause

