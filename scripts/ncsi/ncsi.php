<?php

include realpath('..') . '/.bin/util.php';

$currentPath = formatUnixPath(realpath(''));
$basePath = formatUnixPath(realpath('../..'));
$dataPath = $basePath . '/data/ncsi';
$logsPath = $basePath . '/logs';

// exit codes
// 0 > ok
// 1-90 > tasks
// 97 > unknown task
// 98 > previous
// 99 > exit
// 254 > error
// 255 > fatal error

try {
    $config = loadConfig($currentPath . '/ncsi.conf');
    $task = null;
    if (count($argv) == 2 && $argv[1] >= 1 && $argv[1] <= 90) {
        $task = intval($argv[1]);
    }
    menu($task);
    exit(99);
} catch (Exception $ex) {
    echo 'Error: ' . $ex->getMessage() . PHP_EOL;
    exit(255);
}

///////////////////////////////////////////////
///////////////////////////////////////////////

function menu($task, $display = true) {
    if ($display) {
        echo PHP_EOL . '# WindowsSpyBlocker - NCSI';
        echo PHP_EOL . '# https://github.com/crazy-max/WindowsSpyBlocker';
        echo PHP_EOL;
        echo PHP_EOL . '  1 - Apply WindowsSpyBlocker NCSI (local)';
        echo PHP_EOL . '  2 - Apply Microsoft NCSI (local)';
        echo PHP_EOL;
        echo PHP_EOL . '  3 - Apply WindowsSpyBlocker NCSI (remote)';
        echo PHP_EOL . '  4 - Apply Microsoft NCSI (remote)';
        echo PHP_EOL;
        echo PHP_EOL . '  5 - Test Internet connection';
        echo PHP_EOL;
        echo PHP_EOL . '  99 - Exit';
        echo PHP_EOL . PHP_EOL;
    }

    $task = prompt('Choose a task: ');
    
    try {
        switch ($task) {
            case 1:
                procNcsi('WindowsSpyBlocker', false);
                exit(0);
                break;
            case 2:
                procNcsi('Microsoft', false);
                exit(0);
                break;
            case 3:
                procNcsi('WindowsSpyBlocker', true);
                exit(0);
                break;
            case 4:
                procNcsi('Microsoft', true);
                exit(0);
                break;
            case 5:
                procTestConnection();
                exit(0);
                break;
            case 99:
                exit(99);
                break;
            default:
                echo 'Unknown task...';
                exit(97);
                break;
        }
    } catch (Exception $ex) {
        echo 'Error: ' . $ex->getMessage();
        exit(254);
    }
}

function procNcsi($reg, $remote = true) {
    global $basePath, $dataPath, $config;
    echo PHP_EOL;

    if (!$remote) {
        if (!isset($config['regs']['local'][$reg])) {
            throw new Exception('Unknown reg ' . $reg);
        }
        $regPath = $basePath . $config['regs']['local'][$reg];
        if (!file_exists($regPath)) {
            throw new Exception('Reg file not found in ' . $regPath);
        }
    } else {
        if (!isset($config['regs']['remote'][$reg])) {
            throw new Exception('Unknown reg ' . $reg);
        }
        $regUrl = $config['regs']['remote'][$reg];
        $regPath = $dataPath . '/' . preg_replace('/\..+$/', '.tmp', basename($regUrl));
        echo 'Download ' . basename($regUrl) . '.';
        if (download($regUrl, $regPath)) {
            echo ' OK' . PHP_EOL;
        } else {
            throw new Exception('Download failed');
        }
        if (!file_exists($regPath)) {
            throw new Exception('Reg file not found in ' . $regPath);
        }
    }

    // Apply NCSI
    echo 'Applying ' . $regPath;
    exec('regedit /s "' . $regPath . '"', $cmdOutput, $cmdReturn);
    $cmdOutputStr = implode(PHP_EOL, $cmdOutput);
    if ($remote) {
        unlink($regPath);
    }
    if ($cmdReturn != 0) {
        throw new Exception($cmdOutputStr);
    }
}

function procTestConnection() {
    global $currentPath;
    echo PHP_EOL;

    // Web request IPv4
    $ps1 = 'try {' . PHP_EOL;
    $ps1 .= '    if( (Invoke-Webrequest ("http://{0}/{1}" -f (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbeHost,' . PHP_EOL;
    $ps1 .= '                                                (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbePath)' . PHP_EOL;
    $ps1 .= '        ).Content -eq (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbeContent ) {' . PHP_EOL;
    $ps1 .= '        Write-Host "IPv4 web probe succeeded."' . PHP_EOL;
    $ps1 .= '    }' . PHP_EOL;
    $ps1 .= '} catch { # Ignore errors' . PHP_EOL;
    $ps1 .= '    Write-Host "IPv4 web probe failed."' . PHP_EOL;
    $ps1 .= '}' . PHP_EOL . PHP_EOL;

    // Web request IPv6
    $ps1 .= 'try {' . PHP_EOL;
    $ps1 .= '    if( (Invoke-Webrequest ("http://{0}/{1}" -f (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbeHostV6,' . PHP_EOL;
    $ps1 .= '                                               (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbePathV6)' . PHP_EOL;
    $ps1 .= '        ).Content -eq (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveWebProbeContentV6 ) {' . PHP_EOL;
    $ps1 .= '        Write-Host "IPv6 web probe succeeded."' . PHP_EOL;
    $ps1 .= '    }' . PHP_EOL;
    $ps1 .= '} catch { # Ignore errors' . PHP_EOL;
    $ps1 .= '    Write-Host "IPv6 web probe failed."' . PHP_EOL;
    $ps1 .= '}' . PHP_EOL . PHP_EOL;

    // DNS resolution test with IPv4
    $ps1 .= 'if( (Resolve-DnsName -Type A -ErrorAction SilentlyContinue (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveDnsProbeHost).IPAddress -eq' . PHP_EOL;
    $ps1 .= '    (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveDnsProbeContent ) {' . PHP_EOL;
    $ps1 .= '    Write-Host "IPv4 name resolution succeeded."' . PHP_EOL;
    $ps1 .= '} else {' . PHP_EOL;
    $ps1 .= '    Write-Host "IPv4 name resolution failed."' . PHP_EOL;
    $ps1 .= '}' . PHP_EOL . PHP_EOL;

    // DNS resolution test with IPv6
    $ps1 .= 'if( (Resolve-DnsName -Type AAAA -ErrorAction SilentlyContinue (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveDnsProbeHostV6).IPAddress -eq' . PHP_EOL;
    $ps1 .= '    (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet).ActiveDnsProbeContentV6 ) {' . PHP_EOL;
    $ps1 .= '    Write-Host "IPv6 name resolution succeeded."' . PHP_EOL;
    $ps1 .= '} else {' . PHP_EOL;
    $ps1 .= '    Write-Host "IPv6 name resolution failed."' . PHP_EOL;
    $ps1 .= '}' . PHP_EOL;

    $ps1File = $currentPath . '/testConnection.ps1';
    file_put_contents($ps1File, $ps1);
    if (!file_exists($ps1File)) {
        throw new Exception('PS1 file not found in ' . $ps1File);
    }

    system('powershell.exe -executionpolicy remotesigned -File "' . $ps1File . '"');
    unlink($ps1File);
}
