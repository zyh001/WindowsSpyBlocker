$toolsDir = Split-Path $MyInvocation.MyCommand.Definition
$desktopPath = [Environment]::GetFolderPath("Desktop")
$lnkPath = $desktopPath + "\WindowsSpyBlocker.lnk"
$exePath = Join-Path $toolsDir "WindowsSpyBlocker.exe"

Install-ChocolateyShortcut -shortcutFilePath $lnkPath -targetPath $exePath
