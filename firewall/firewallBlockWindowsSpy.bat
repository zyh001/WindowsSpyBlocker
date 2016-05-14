@ECHO OFF
SETLOCAL EnableDelayedExpansion
TITLE WindowsSpyBlocker - Firewall rules

SET firewallRulesPrefix=windowsSpyBlocker-
SET firewallRulesFile=firewallBlockWindowsSpy.txt
SET firewallRulesUrl=https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/firewall/%firewallRulesFile%
::SET firewallRulesUrl=http://localhost/%firewallRulesFile%
SET tmpVbs=%TEMP%\firewallBlockWindowsSpy.vbs

CLS
IF "%1"=="" GOTO CHECKUAC
IF "%1"=="start" GOTO START

:CHECKUAC
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"  
IF '%ERRORLEVEL%' NEQ '0' (
    ECHO Requesting administrative privileges...
    GOTO UAC_PROMPT
) else (
    GOTO ADMIN
)
  
:UAC_PROMPT  
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%TEMP%\getadmin.vbs"
ECHO UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%TEMP%\getadmin.vbs"
"%TEMP%\getadmin.vbs"
EXIT /B

:ADMIN
IF EXIST "%TEMP%\getadmin.vbs" ( DEL "%TEMP%\getadmin.vbs" )
PUSHD "%CD%"
CD /D "%~dp0"
CD %CD%
%COMSPEC% /c "firewallBlockWindowsSpy.bat" start
EXIT

:START

CLS
ECHO ### WindowsSpyBlocker - Firewall rules 1.5
ECHO ### More info: https://github.com/crazy-max/WindowsSpyBlocker

:: Remove old rules
ECHO.
ECHO - Remove old rules...
ECHO Dim objFwPolicy2 >%tmpVbs%
ECHO Dim objCurrentProfiles >>%tmpVbs%
ECHO Dim objRules >>%tmpVbs%
ECHO Dim objRule >>%tmpVbs%
ECHO. >>%tmpVbs%
ECHO Set objFwPolicy2 = CreateObject("HNetCfg.FwPolicy2") >>%tmpVbs%
ECHO objCurrentProfiles = objFwPolicy2.CurrentProfileTypes >>%tmpVbs%
ECHO Set objRules = objFwPolicy2.Rules >>%tmpVbs%
ECHO For Each objRule In objRules >>%tmpVbs%
ECHO   If objRule.Profiles And objCurrentProfiles Then >>%tmpVbs%
ECHO     If InStr(1, objRule.Name, "%firewallRulesPrefix%") = 1 Then >>%tmpVbs%
ECHO       Wscript.Echo objRule.Name >>%tmpVbs%
ECHO       objFwPolicy2.Rules.Remove objRule.Name >>%tmpVbs%
ECHO     End If >>%tmpVbs%
ECHO   End If >>%tmpVbs%
ECHO Next >>%tmpVbs%
cscript.exe /NoLogo %tmpVbs%

:: Download firewall rules
ECHO.
ECHO - Download rules from GitHub...
ECHO WScript.StdOut.Write "Download " ^& "%firewallRulesUrl%" ^& " " >%tmpVbs%
ECHO dim http: set http = createobject("WinHttp.WinHttpRequest.5.1") >>%tmpVbs%
ECHO dim bStrm: set bStrm = createobject("Adodb.Stream") >>%tmpVbs%
ECHO http.Open "GET", "%firewallRulesUrl%", True >>%tmpVbs%
ECHO http.Send >>%tmpVbs%
ECHO while http.WaitForResponse(0) = 0 >>%tmpVbs%
ECHO   WScript.StdOut.Write "." >>%tmpVbs%
ECHO   WScript.Sleep 1000 >>%tmpVbs%
ECHO wend >>%tmpVbs%
ECHO WScript.StdOut.WriteLine " [HTTP " ^& http.Status ^& " " ^& http.StatusText ^& "]" >>%tmpVbs%
ECHO with bStrm >>%tmpVbs%
ECHO .type = 1 '//binary >>%tmpVbs%
ECHO .open >>%tmpVbs%
ECHO .write http.responseBody >>%tmpVbs%
ECHO .savetofile "%~dp0\%firewallRulesFile%", 2 >>%tmpVbs%
ECHO end with >>%tmpVbs%
cscript.exe /NoLogo %tmpVbs%

:: Add rules
ECHO.
ECHO - Add rules...
ECHO Dim ipAddress >>%tmpVbs%
ECHO Set objShell = WScript.CreateObject("WScript.Shell") >%tmpVbs%
ECHO Set objFso = CreateObject("Scripting.FileSystemObject") >>%tmpVbs%
ECHO Set file = objFso.OpenTextFile("%~dp0\%firewallRulesFile%") >>%tmpVbs%
ECHO Do Until file.AtEndOfStream >>%tmpVbs%
ECHO   ipAddress = Trim(file.ReadLine) >>%tmpVbs%
ECHO   If Not InStr(1, ipAddress, "#") = 1 And Len(ipAddress) Then >>%tmpVbs%
ECHO     WScript.Echo "%firewallRulesPrefix%" ^& ipAddress >>%tmpVbs%
ECHO     res = objShell.Run("netsh advfirewall firewall add rule name=""%firewallRulesPrefix%" ^& ipAddress ^& """ dir=out protocol=any action=block remoteip=" ^& ipAddress, 0, True) >>%tmpVbs%
ECHO   End If >>%tmpVbs%
ECHO Loop >>%tmpVbs%
cscript.exe /NoLogo %tmpVbs%

:END
ECHO.
ENDLOCAL
PAUSE
