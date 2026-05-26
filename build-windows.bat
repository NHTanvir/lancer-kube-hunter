@echo off
REM Windows release build for lancer-kube-hunter.
REM Output: dist\lancer-kube-hunter-windows-x86_64\bin\lancer-kube-hunter.exe

echo === Building lancer-kube-hunter (release) for Windows x86_64 ===
cargo build --release
if errorlevel 1 exit /b 1

echo === Packaging ===
set DIST=dist\lancer-kube-hunter-windows-x86_64
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"
mkdir "%DIST%\bin"

copy target\release\lancer-kube-hunter.exe "%DIST%\bin\" >nul
copy LICENSE "%DIST%\" >nul 2>nul
copy README.md "%DIST%\" >nul 2>nul

echo === Done. Binary: %DIST%\bin ===
dir "%DIST%\bin"
exit /b 0
