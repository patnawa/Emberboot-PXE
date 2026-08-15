@echo off
setlocal EnableExtensions EnableDelayedExpansion
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

rem --- least-privilege firewall rules --------------------------
rem Remove the pre-v0.6 whole-program exception if an older launcher added it.
netsh advfirewall firewall delete rule name="Emberboot" >nul 2>&1
set "TFTP_PORT=69"
set "HTTP_PORT=8090"
set "ISCSI_PORT=3260"
set "ISCSI_ENABLED=false"
set "DASHBOARD_BIND=127.0.0.1:8443"
set "DASHBOARD_SCHEME=http"
if exist "%~dp0emberboot.yaml" (
  for /f "tokens=2" %%P in ('findstr /R /C:"^[ ]*tftp_port:[ ]*[0-9]" "%~dp0emberboot.yaml"') do set "TFTP_PORT=%%P"
  for /f "tokens=2" %%P in ('findstr /R /C:"^[ ]*http_port:[ ]*[0-9]" "%~dp0emberboot.yaml"') do set "HTTP_PORT=%%P"
  for /f "tokens=2" %%P in ('findstr /R /C:"^[ ]*iscsi_port:[ ]*[0-9]" "%~dp0emberboot.yaml"') do set "ISCSI_PORT=%%P"
  rem Legacy configs enabled iSCSI by supplying an ACL before the explicit
  rem iscsi_enabled switch existed. Preserve that effective behavior.
  findstr /R /C:"^[ ]*iscsi_allowed_subnets:" "%~dp0emberboot.yaml" >nul 2>&1 && set "ISCSI_ENABLED=true"
  findstr /R /C:"^[ ]*iscsi_enabled:[ ]*false" "%~dp0emberboot.yaml" >nul 2>&1 && set "ISCSI_ENABLED=false"
  findstr /R /C:"^[ ]*iscsi_enabled:[ ]*true" "%~dp0emberboot.yaml" >nul 2>&1 && set "ISCSI_ENABLED=true"
  for /f "tokens=2" %%P in ('findstr /R /C:"^[ ]*dashboard_bind:" "%~dp0emberboot.yaml"') do set "DASHBOARD_BIND=%%~P"
  for /f "tokens=2" %%P in ('findstr /R /C:"^[ ]*dashboard_tls_cert:[ ]*[^ ]" "%~dp0emberboot.yaml"') do if not "%%~P"=="" set "DASHBOARD_SCHEME=https"
)
set "DASHBOARD_URL="
if defined DASHBOARD_BIND (
  if "!DASHBOARD_BIND:~0,1!"==":" set "DASHBOARD_BIND=localhost!DASHBOARD_BIND!"
  if /I "!DASHBOARD_BIND:~0,8!"=="0.0.0.0:" set "DASHBOARD_BIND=localhost:!DASHBOARD_BIND:~8!"
  if /I "!DASHBOARD_BIND:~0,5!"=="[::]:" set "DASHBOARD_BIND=localhost:!DASHBOARD_BIND:~5!"
  set "DASHBOARD_URL=!DASHBOARD_SCHEME!://!DASHBOARD_BIND!"
)
echo Updating local-subnet PXE firewall rules...
for %%R in ("Emberboot PXE UDP" "Emberboot Boot HTTP" "Emberboot iSCSI") do netsh advfirewall firewall delete rule name=%%R >nul 2>&1
netsh advfirewall firewall add rule name="Emberboot PXE UDP" dir=in action=allow program="%EXE%" protocol=UDP localport=67,%TFTP_PORT%,4011 remoteip=localsubnet profile=domain,private enable=yes >nul
netsh advfirewall firewall add rule name="Emberboot Boot HTTP" dir=in action=allow program="%EXE%" protocol=TCP localport=%HTTP_PORT% remoteip=localsubnet profile=domain,private enable=yes >nul
if /I "%ISCSI_ENABLED%"=="true" netsh advfirewall firewall add rule name="Emberboot iSCSI" dir=in action=allow program="%EXE%" protocol=TCP localport=%ISCSI_PORT% remoteip=localsubnet profile=domain,private enable=yes >nul
rem TCP 8443 is intentionally not opened. Remote management requires an
rem explicit management-subnet rule plus TLS/auth in emberboot.yaml.

rem --- open the console once the server has had a moment ------
if defined DASHBOARD_URL start "" /min cmd /c "timeout /t 3 /nobreak >nul & start !DASHBOARD_URL!"

rem --- run (first run creates emberboot.yaml and images\) -----
echo.
echo  Emberboot is starting.
if defined DASHBOARD_URL (
  echo  The management console opens at: !DASHBOARD_URL!
) else (
  echo  The management console is disabled by network.dashboard_bind.
)
echo.
echo  Drop ISO files into the "images" folder next to this script.
echo  Close this window or press Ctrl+C to stop the server.
echo.
"%EXE%" -config "%~dp0emberboot.yaml"

echo.
echo Emberboot stopped. The messages above explain why, if it exited on its own.
pause
