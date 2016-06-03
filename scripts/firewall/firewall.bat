@ECHO OFF
SETLOCAL EnableDelayedExpansion
TITLE WindowsSpyBlocker - Firewall

SET binPath=%~dp0..\.bin

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
%COMSPEC% /c "firewall.bat" start
EXIT


::::::::::::::::::::::::::::::::::::::::
:START
::::::::::::::::::::::::::::::::::::::::
CLS
ECHO.
ECHO # WindowsSpyBlocker - Firewall
ECHO # https://github.com/crazy-max/WindowsSpyBlocker
ECHO.

ECHO  1  - Add rules win10_extra (from github)
ECHO  2  - Add rules win10_spy (from github)
ECHO  3  - Add rules win10_update (from github)
ECHO.
ECHO  4  - Add rules win10_extra (local file)
ECHO  5  - Add rules win10_spy (local file)
ECHO  6  - Add rules win10_update (local file)
ECHO.
ECHO  7  - Remove rules
ECHO  8  - Test IPs (from github)
ECHO  9  - Test IPs (local files)
ECHO.
ECHO  99 - Exit
ECHO.
SET /P task="Choose a task: "
ECHO.


::::::::::::::::::::::::::::::::::::::::
:ACTION
::::::::::::::::::::::::::::::::::::::::
IF %task% == 1 (
  SET rule=win10_extra
  SET type=remote
  GOTO ADD_RULES
)
IF %task% == 2 (
  SET rule=win10_spy
  SET type=remote
  GOTO ADD_RULES
)
IF %task% == 3 (
  SET rule=win10_update
  SET type=remote
  GOTO ADD_RULES
)
IF %task% == 4 (
  SET rule=win10_extra
  SET type=local
  GOTO ADD_RULES
)
IF %task% == 5 (
  SET rule=win10_spy
  SET type=local
  GOTO ADD_RULES
)
IF %task% == 6 (
  SET rule=win10_update
  SET type=local
  GOTO ADD_RULES
)
IF %task% == 7 (
  GOTO REMOVE_RULES
)
IF %task% == 8 (
  SET type=remote
  GOTO TEST_IPS
)
IF %task% == 9 (
  SET type=local
  GOTO TEST_IPS
)
IF %task% == 99 GOTO EXIT
GOTO START


::::::::::::::::::::::::::::::::::::::::
:REMOVE_RULES
::::::::::::::::::::::::::::::::::::::::
ECHO.
ECHO ### Remove rules...
"%binPath%\php.exe" -c "%binPath%\php.ini" "%~dp0firewall.php" "removeRules"
GOTO END


::::::::::::::::::::::::::::::::::::::::
:ADD_RULES
::::::::::::::::::::::::::::::::::::::::
ECHO.
ECHO ### Add %rule% rules...
"%binPath%\php.exe" -c "%binPath%\php.ini" "%~dp0firewall.php" "addRules" "%rule%" "%type%"
GOTO END


::::::::::::::::::::::::::::::::::::::::
:TEST_IPS
::::::::::::::::::::::::::::::::::::::::
ECHO.
ECHO ### Test IPs...
"%binPath%\php.exe" -c "%binPath%\php.ini" "%~dp0firewall.php" "testIps" "%type%"
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
