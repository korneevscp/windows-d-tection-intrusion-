@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  echo Visual Studio C compiler (cl.exe) not found.
  echo Open "x64 Native Tools Command Prompt for Visual Studio" and run this file again.
  pause
  exit /b 1
)
cl /nologo /O2 /W4 /D_CRT_SECURE_NO_WARNINGS korneev_ids_pro.c /Fe:KorneevIDS.exe /link iphlpapi.lib psapi.lib advapi32.lib ws2_32.lib shell32.lib
if errorlevel 1 (
  echo Build failed.
  pause
  exit /b 1
)
echo Build successful: KorneevIDS.exe
pause
