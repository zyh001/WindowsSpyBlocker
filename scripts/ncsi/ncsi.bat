@ECHO OFF
SETLOCAL EnableDelayedExpansion
TITLE WindowsSpyBlocker - NCSI

SET binPath=%~dp0..\.bin
SET tmpPs1=%TEMP%\ncsiTest.ps1

CLS
IF "%1"=="" GOTO CHECK_UAC
IF "%1"=="start" GOTO START


::::::::::::::::::::::::::::::::::::::::
:CHECK_UAC
::::::::::::::::::::::::::::::::::::::::
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"  
If '%ERRORLEVEL%' NEQ '0' (
    ECHO Requesting administrative privileges...
    GOTO UAC_PROMPT
) Else (
    GOTO ADMIN
)


::::::::::::::::::::::::::::::::::::::::
:UAC_PROMPT
::::::::::::::::::::::::::::::::::::::::
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%TEMP%\getadmin.vbs"
ECHO UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%TEMP%\getadmin.vbs"
"%TEMP%\getadmin.vbs"
EXIT /B


::::::::::::::::::::::::::::::::::::::::
:ADMIN
::::::::::::::::::::::::::::::::::::::::
IF EXIST "%TEMP%\getadmin.vbs" ( DEL "%TEMP%\getadmin.vbs" )
PUSHD "%CD%"
CD /D "%~dp0"
CD %CD%
%COMSPEC% /c "ncsi.bat" start
EXIT


::::::::::::::::::::::::::::::::::::::::
:START
::::::::::::::::::::::::::::::::::::::::
CLS
ECHO.
ECHO # WindowsSpyBlocker - NCSI
ECHO # https://github.com/crazy-max/WindowsSpyBlocker
ECHO.

ECHO  1 - Apply github.com NCSI (WindowsSpyBlocker) from Github
ECHO  2 - Apply msftncsi.com NCSI (Original Microsoft) from Github
ECHO.
ECHO  3 - Apply github.com NCSI (WindowsSpyBlocker) from local file
ECHO  4 - Apply msftncsi.com NCSI (Original Microsoft) from local file
ECHO.
ECHO  5 - Test Internet connection
ECHO.
ECHO  9 - Exit
ECHO.
SET /P task="Choose a task: "
ECHO.


::::::::::::::::::::::::::::::::::::::::
:ACTION
::::::::::::::::::::::::::::::::::::::::
IF %task% == 1 (
  SET reg=github.com
  SET type=remote
  GOTO APPLY_NCSI
)
IF %task% == 2 (
  SET reg=msftncsi.com
  SET type=remote
  GOTO APPLY_NCSI
)
IF %task% == 3 (
  SET reg=github.com
  SET type=local
  GOTO APPLY_NCSI
)
IF %task% == 4 (
  SET reg=msftncsi.com
  SET type=local
  GOTO APPLY_NCSI
)
IF %task% == 5 GOTO TEST
IF %task% == 9 GOTO EXIT
GOTO START


::::::::::::::::::::::::::::::::::::::::
:APPLY_NCSI
::::::::::::::::::::::::::::::::::::::::
ECHO.
ECHO ### Apply %reg% NCSI...
"%binPath%\php.exe" -c "%binPath%\php.ini" "%~dp0ncsi.php" "applyNcsi" "%reg%" "%type%"
GOTO END


::::::::::::::::::::::::::::::::::::::::
:TEST
::::::::::::::::::::::::::::::::::::::::
ECHO.
ECHO ### Test Internet connection...
ECHO # Web request test with IPv4>%tmpPs1%
ECHO try {>>%tmpPs1%
ECHO     if( (Invoke-Webrequest ("http://{0}/{1}" -f (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbeHost,>>%tmpPs1%
ECHO                                                 (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbePath)>>%tmpPs1%
ECHO         ).Content -eq (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbeContent ) {>>%tmpPs1%
ECHO         Write-Host 'IPv4 web probe succeeded.'>>%tmpPs1%
ECHO    }>>%tmpPs1%
ECHO } catch { # Ignore errors>>%tmpPs1%
ECHO    Write-Host 'IPv4 web probe failed.'>>%tmpPs1%
ECHO }>>%tmpPs1%
ECHO # Web request test with IPv6>>%tmpPs1%
ECHO try {>>%tmpPs1%
ECHO    if( (Invoke-Webrequest ("http://{0}/{1}" -f (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbeHostV6,>>%tmpPs1%
ECHO                                                (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbePathV6)>>%tmpPs1%
ECHO        ).Content -eq (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbeContentV6 ) {>>%tmpPs1%
ECHO        Write-Host 'IPv6 web probe succeeded.'>>%tmpPs1%
ECHO    }>>%tmpPs1%
ECHO } catch { # Ignore errors>>%tmpPs1%
ECHO    Write-Host 'IPv6 web probe failed.'>>%tmpPs1%
ECHO }>>%tmpPs1%
ECHO # DNS resolution test with IPv4>>%tmpPs1%
ECHO if( (Resolve-DnsName -Type A -ErrorAction SilentlyContinue (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveDnsProbeHost).IPAddress -eq>>%tmpPs1%
ECHO    (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveDnsProbeContent ) {>>%tmpPs1%
ECHO    Write-Host 'IPv4 name resolution succeeded.'>>%tmpPs1%
ECHO } else {>>%tmpPs1%
ECHO    Write-Host 'IPv4 name resolution failed.'>>%tmpPs1%
ECHO }>>%tmpPs1%
ECHO # DNS resolution test with IPv6>>%tmpPs1%
ECHO if( (Resolve-DnsName -Type AAAA -ErrorAction SilentlyContinue (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveDnsProbeHostV6).IPAddress -eq>>%tmpPs1%
ECHO    (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveDnsProbeContentV6 ) {>>%tmpPs1%
ECHO    Write-Host 'IPv6 name resolution succeeded.'>>%tmpPs1%
ECHO } else {>>%tmpPs1%
ECHO    Write-Host 'IPv6 name resolution failed.'>>%tmpPs1%
ECHO }>>%tmpPs1%
powershell.exe -executionpolicy remotesigned -File %tmpPs1%
GOTO END


::::::::::::::::::::::::::::::::::::::::
:END
::::::::::::::::::::::::::::::::::::::::
ECHO.
PAUSE
GOTO START


::::::::::::::::::::::::::::::::::::::::
:EXIT
::::::::::::::::::::::::::::::::::::::::
ENDLOCAL
