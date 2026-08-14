@echo off
rem ============================================================
rem  Emberboot — double-click launcher for Windows
rem  Elevates itself, allows the app through Windows Firewall,
rem  starts the server, and opens the management console.
rem ============================================================
cd /d "%~dp0"

rem --- find the server binary ---------------------------------
set "EXE=%~dp0dist\emberbootd-windows-amd64.exe"
if not exist "%EXE%" set "EXE=%~dp0emberbootd.exe"
if not exist "%EXE%" (
  echo Could not find emberbootd-windows-amd64.exe in dist\ or emberbootd.exe here.
  echo Build it first:  go build -o emberbootd.exe .\cmd\emberbootd
  pause
  exit /b 1
)

rem --- self-elevate (UDP ports 67/69 need administrator) ------
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator access...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

rem --- one-time firewall rule for this binary -----------------
netsh advfirewall firewall show rule name="Emberboot" >nul 2>&1
if %errorlevel% neq 0 (
  echo Adding Windows Firewall rule "Emberboot"...
  netsh advfirewall firewall add rule name="Emberboot" dir=in action=allow program="%EXE%" enable=yes >nul
)

rem --- open the console once the server has had a moment ------
start "" /min cmd /c "timeout /t 3 /nobreak >nul & start http://localhost:8443"

rem --- run (first run creates emberboot.yaml and images\) -----
echo.
echo  Emberboot is starting. The management console opens at:
echo     http://localhost:8443
echo.
echo  Drop ISO files into the "images" folder next to this script.
echo  Close this window or press Ctrl+C to stop the server.
echo.
"%EXE%" -config "%~dp0emberboot.yaml"

echo.
echo Emberboot stopped. The messages above explain why, if it exited on its own.
pause
