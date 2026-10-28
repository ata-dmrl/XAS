@echo off
REM XAS baslatici (Windows). Cift tiklanabilir ya da terminalden xas.cmd ile calisir.
REM bin\xas.js ilk calistirmada eksik bagimliliklari kendisi kurar.
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js bulunamadi. Kurun: https://nodejs.org/
  pause
  exit /b 1
)

node "%~dp0bin\xas.js" %*
