$desktopPath = [Environment]::GetFolderPath("Desktop")
$lnkPath = $desktopPath + "\WindowsSpyBlocker.lnk"

if (Test-Path $lnkPath)
{
    Write-Output "WindowsSpyBlocker: Removing Desktop shortcut file"
    Remove-Item $lnkPath
}
