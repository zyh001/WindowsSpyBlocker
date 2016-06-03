@ECHO OFF
SETLOCAL EnableDelayedExpansion
TITLE WindowsSpyBlocker - Proxifier

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
%COMSPEC% /c "proxifier.bat" start
EXIT


::::::::::::::::::::::::::::::::::::::::
:START
::::::::::::::::::::::::::::::::::::::::
CLS
ECHO.
ECHO # WindowsSpyBlocker - Proxifier
ECHO # https://github.com/crazy-max/WindowsSpyBlocker
ECHO.

ECHO  1 - Extract log
ECHO  9 - Exit
ECHO.
SET /P task="Choose a task: "
ECHO.


::::::::::::::::::::::::::::::::::::::::
:ACTION
::::::::::::::::::::::::::::::::::::::::
IF %task% == 1 GOTO EXTRACT
IF %task% == 9 GOTO EXIT
GOTO START


::::::::::::::::::::::::::::::::::::::::
:EXTRACT
::::::::::::::::::::::::::::::::::::::::
ECHO ### Extract log...
"%binPath%\php.exe" -c "%binPath%\php.ini" "%~dp0proxifier.php" "extractLog"
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
