@echo off
setlocal

REM Generate Drogon ORM models from model.json
cd /d "%~dp0.."

where drogon_ctl >nul 2>&1
if %errorlevel% neq 0 (
  echo Error: drogon_ctl not found in PATH
  exit /b 1
)

drogon_ctl create model models
if %errorlevel% neq 0 (
  echo Error: drogon_ctl failed
  exit /b 1
)

echo Models generated in models/
