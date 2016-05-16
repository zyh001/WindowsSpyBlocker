@ECHO OFF
SETLOCAL EnableDelayedExpansion
TITLE WindowsSpyBlocker - Firewall rules

SET firewallRulesPrefix=windowsSpyBlocker-
SET firewallTestIPsCSV=firewallTestIPs.csv
SET firewallRulesUrl=https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/firewall/windows10_spy.txt
SET tmpVbs=%TEMP%\firewallBlockWindowsSpy.vbs


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
%COMSPEC% /c "firewallBlockWindowsSpy.bat" start
EXIT


::::::::::::::::::::::::::::::::::::::::
:START
::::::::::::::::::::::::::::::::::::::::
CLS
ECHO.
ECHO # WindowsSpyBlocker - Firewall rules
ECHO # https://github.com/crazy-max/WindowsSpyBlocker
ECHO.

ECHO  1 - Download and add rules from GitHub
ECHO  2 - Add rules from local file
ECHO  3 - Remove rules
ECHO  4 - Test IPs
ECHO  9 - Exit
ECHO.
SET /P task="Choose a task: "
ECHO.


::::::::::::::::::::::::::::::::::::::::
:ACTION
::::::::::::::::::::::::::::::::::::::::
IF %task% == 1 GOTO DOWNLOAD_GITHUB
IF %task% == 2 GOTO LOCAL
IF %task% == 3 GOTO REMOVE_RULES
IF %task% == 4 GOTO DOWNLOAD_GITHUB
IF %task% == 9 GOTO EXIT
GOTO START


::::::::::::::::::::::::::::::::::::::::
:DOWNLOAD_GITHUB
::::::::::::::::::::::::::::::::::::::::
SET firewallRulesFile=windows10_spy_github.txt
ECHO - Download rules from GitHub...
ECHO WScript.StdOut.Write "Download " ^& "%firewallRulesUrl%" ^& " " >%tmpVbs%
ECHO Dim objHttp : Set objHttp = CreateObject("WinHttp.WinHttpRequest.5.1") >>%tmpVbs%
ECHO Dim objStream : Set objStream = CreateObject("Adodb.Stream") >>%tmpVbs%
ECHO objHttp.Open "GET", "%firewallRulesUrl%", True >>%tmpVbs%
ECHO objHttp.Send >>%tmpVbs%
ECHO While objHttp.WaitForResponse(0) = 0 >>%tmpVbs%
ECHO   WScript.StdOut.Write "." >>%tmpVbs%
ECHO   WScript.Sleep 1000 >>%tmpVbs%
ECHO Wend >>%tmpVbs%
ECHO WScript.StdOut.WriteLine " [HTTP " ^& objHttp.Status ^& " " ^& objHttp.StatusText ^& "]" >>%tmpVbs%
ECHO With objStream >>%tmpVbs%
ECHO   .Type = 1 '//binary >>%tmpVbs%
ECHO   .Open >>%tmpVbs%
ECHO   .Write objHttp.ResponseBody >>%tmpVbs%
ECHO   .Savetofile "%~dp0\%firewallRulesFile%", 2 >>%tmpVbs%
ECHO End With >>%tmpVbs%
cscript.exe /NoLogo %tmpVbs%
IF %task% == 4 (
  GOTO TEST_IPS
) Else (
  GOTO REMOVE_RULES
)


::::::::::::::::::::::::::::::::::::::::
:LOCAL
::::::::::::::::::::::::::::::::::::::::
SET firewallRulesFile=windows10_spy.txt
GOTO REMOVE_RULES


::::::::::::::::::::::::::::::::::::::::
:REMOVE_RULES
::::::::::::::::::::::::::::::::::::::::
ECHO.
ECHO - Remove rules...
ECHO Dim objFwPolicy2 >%tmpVbs%
ECHO Dim objCurrentProfiles >>%tmpVbs%
ECHO Dim objRules >>%tmpVbs%
ECHO Dim objRule >>%tmpVbs%
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
IF %task% == 3 (
  GOTO END
) Else (
  GOTO ADD_RULES
)


::::::::::::::::::::::::::::::::::::::::
:ADD_RULES
::::::::::::::::::::::::::::::::::::::::
ECHO.
ECHO - Add rules...
ECHO Dim ipAddress >%tmpVbs%
ECHO Set objShell = WScript.CreateObject("WScript.Shell") >>%tmpVbs%
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
GOTO END

::::::::::::::::::::::::::::::::::::::::
:TEST_IPS
::::::::::::::::::::::::::::::::::::::::
ECHO.
ECHO - Test IPs...
ECHO Dim ipAddress >%tmpVbs%
ECHO Dim objShell : Set objShell = WScript.CreateObject("WScript.Shell") >>%tmpVbs%
ECHO Dim objFso : Set objFso = CreateObject("Scripting.FileSystemObject") >>%tmpVbs%
ECHO Dim objTestIPsCSV : Set objTestIPsCSV = objFSO.CreateTextFile("%~dp0\%firewallTestIPsCSV%", True) >>%tmpVbs%
ECHO Dim objRules : Set objRules = objFso.OpenTextFile("%~dp0\%firewallRulesFile%") >>%tmpVbs%
ECHO Dim objIE : Set objIE = CreateObject("InternetExplorer.Application") >>%tmpVbs%
ECHO objIE.Visible = False >>%tmpVbs%
ECHO objTestIPsCSV.Write "IP,NETNAME,ORGANIZATION,COUNTRY,DNS RESOLVE" ^& vbCrLf >>%tmpVbs%
ECHO Do Until objRules.AtEndOfStream >>%tmpVbs%
ECHO   ipAddress = Trim(objRules.ReadLine) >>%tmpVbs%
ECHO   If Len(ipAddress) And Not InStr(1, ipAddress, "#") = 1 And InStr(ipAddress, "-") = 0 Then >>%tmpVbs%
ECHO     WScript.StdOut.Write "Checking " ^& ipAddress >>%tmpVbs%
ECHO     objIE.Navigate "https://dnsquery.org/ipwhois,request/" ^& ipAddress >>%tmpVbs%
ECHO     Do Until objIE.ReadyState = 4 >>%tmpVbs%
ECHO       WScript.StdOut.Write "." >>%tmpVbs%
ECHO       WScript.Sleep 500 >>%tmpVbs%
ECHO     Loop >>%tmpVbs%
ECHO     rawIpData = objIE.Document.Body.innerText >>%tmpVbs%
ECHO     rawIpDataSp = Split(Trim(objIE.Document.getElementsByTagName("pre").item(0).innerText), vbNewLine) >>%tmpVbs%
ECHO     ipNetName = "" >>%tmpVbs%
ECHO     ipOrganization = "" >>%tmpVbs%
ECHO     ipCountry = "" >>%tmpVbs%
ECHO     For Each ipData In rawIpDataSp >>%tmpVbs%
ECHO       ''' whois.arin.net >>%tmpVbs%
ECHO       If InStr(rawIpData, "whois.arin.net") ^> 0 Then >>%tmpVbs%
ECHO         If InStr(1, ipData, "NetName:") = 1 Then >>%tmpVbs%
ECHO           ipNetName = Trim(Replace(ipData, "NetName:        ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO         If InStr(1, ipData, "Organization:") = 1 Then >>%tmpVbs%
ECHO           ipOrganization = Trim(Replace(ipData, "Organization:   ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO         If InStr(1, ipData, "Country:") = 1 Then >>%tmpVbs%
ECHO           ipCountry = Trim(Replace(ipData, "Country:        ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO       End If >>%tmpVbs%
ECHO       ''' whois.ripe.net >>%tmpVbs%
ECHO       If InStr(rawIpData, "whois.ripe.net") ^> 0 Then >>%tmpVbs%
ECHO         If InStr(1, ipData, "netname:") = 1 Then >>%tmpVbs%
ECHO           ipNetName = Trim(Replace(ipData, "netname:        ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO         If Len(ipOrganization) = 0 And InStr(1, ipData, "descr:") = 1 Then >>%tmpVbs%
ECHO           ipOrganization = Trim(Replace(ipData, "descr:          ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO         If InStr(1, ipData, "country:") = 1 Then >>%tmpVbs%
ECHO           ipCountry = Trim(Replace(ipData, "country:        ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO       End If >>%tmpVbs%
ECHO       ''' whois.lacnic.net >>%tmpVbs%
ECHO       If InStr(rawIpData, "whois.lacnic.net") ^> 0 Then >>%tmpVbs%
ECHO         If InStr(1, ipData, "aut-num:") = 1 Then >>%tmpVbs%
ECHO           ipNetName = Trim(Replace(ipData, "aut-num:     ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO         If InStr(1, ipData, "owner:") = 1 Then >>%tmpVbs%
ECHO           ipOrganization = Trim(Replace(ipData, "owner:       ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO         If InStr(1, ipData, "country:") = 1 Then >>%tmpVbs%
ECHO           ipCountry = Trim(Replace(ipData, "country:     ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO       End If >>%tmpVbs%
ECHO       ''' whois.apnic.net >>%tmpVbs%
ECHO       If InStr(rawIpData, "whois.apnic.net") ^> 0 Then >>%tmpVbs%
ECHO         If InStr(1, ipData, "netname:") = 1 Then >>%tmpVbs%
ECHO           ipNetName = Trim(Replace(ipData, "netname:        ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO         If Len(ipOrganization) = 0 And InStr(1, ipData, "descr:") = 1 Then >>%tmpVbs%
ECHO           ipOrganization = Trim(Replace(ipData, "descr:          ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO         If InStr(1, ipData, "country:") = 1 Then >>%tmpVbs%
ECHO           ipCountry = Trim(Replace(ipData, "country:        ", "")) >>%tmpVbs%
ECHO         End If >>%tmpVbs%
ECHO       End If >>%tmpVbs%
ECHO     Next >>%tmpVbs%
ECHO     objIE.Navigate "http://www.webyield.net/cgi-bin/ipwhois.cgi?addr=" ^& ipAddress >>%tmpVbs%
ECHO     Do Until objIE.ReadyState = 4 >>%tmpVbs%
ECHO       WScript.StdOut.Write "." >>%tmpVbs%
ECHO       WScript.Sleep 500 >>%tmpVbs%
ECHO     Loop >>%tmpVbs%
ECHO     ipResolvesTo = Trim(Replace(objIE.Document.getElementsByTagName("p").item(1).innerText, "Resolves to: ", "")) >>%tmpVbs%
ECHO     ipResolvesTo = Replace(ipResolvesTo, "no reverse DNS for this IP", "") >>%tmpVbs%
ECHO     Wscript.Echo vbNewLine ^& "  NetName: " ^& ipNetName >>%tmpVbs%
ECHO     Wscript.Echo "  Organization: " ^& ipOrganization >>%tmpVbs%
ECHO     Wscript.Echo "  Country: " ^& ipCountry >>%tmpVbs%
ECHO     Wscript.Echo "  Resolves to: " ^& ipResolvesTo >>%tmpVbs%
ECHO     ipNetName = Replace(ipNetName, ",", ".") >>%tmpVbs%
ECHO     ipOrganization = Replace(ipOrganization, ",", ".") >>%tmpVbs%
ECHO     ipCountry = Replace(ipCountry, ",", ".") >>%tmpVbs%
ECHO     ipResolvesTo = Replace(ipResolvesTo, ",", ".") >>%tmpVbs%
ECHO     objTestIPsCSV.Write ipAddress ^& ";" ^& ipNetName ^& ";" ^& ipOrganization ^& ";" ^& ipCountry ^& ";" ^& ipResolvesTo ^& vbCrLf >>%tmpVbs%
ECHO   End If >>%tmpVbs%
ECHO Loop >>%tmpVbs%
ECHO objTestIPsCSV.Close >>%tmpVbs%
ECHO objIE.Quit >>%tmpVbs%
cscript.exe /NoLogo %tmpVbs%
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
