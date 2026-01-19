@echo off
setlocal enabledelayedexpansion

REM Store the script directory
set CURRENT_DIR=%~dp0
cd /d "%CURRENT_DIR%"

REM Check for Conan environment script
if exist "build\conanrun.bat" (
    call "build\conanrun.bat"
) else (
    echo Warning: build\conanrun.bat not found. DLL lookup might fail.
)

REM Try to run Release version first
if exist "build\Release\PayServer.exe" (
    echo Starting PayServer (Release)...
    cd build\Release
    PayServer.exe
    goto :eof
)

REM Try Debug version
if exist "build\Debug\PayServer.exe" (
    echo Starting PayServer (Debug)...
    cd build\Debug
    PayServer.exe
    goto :eof
)

echo Error: PayServer.exe not found in build/Release or build/Debug.
echo Please run build.bat first.
exit /b 1
