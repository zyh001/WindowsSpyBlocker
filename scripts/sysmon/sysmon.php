<?php

include realpath('..') . '/.bin/util.php';

$currentPath = formatUnixPath(realpath(''));
$binPath = formatUnixPath(realpath('..')) . '/.bin';
$basePath = formatUnixPath(realpath('../..'));
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
    $config = loadConfig($currentPath . '/sysmon.conf');
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
        echo PHP_EOL . '# WindowsSpyBlocker - Sysmon';
        echo PHP_EOL . '# https://github.com/crazy-max/WindowsSpyBlocker';
        echo PHP_EOL;
        echo PHP_EOL . '  1  - Install';
        echo PHP_EOL . '  2  - Uninstall';
        echo PHP_EOL . '  3  - Extract event log';
        echo PHP_EOL . '  99 - Exit';
        echo PHP_EOL . PHP_EOL;
    }

    $task = prompt('Choose a task: ');

    try {
        switch ($task) {
            case 1:
                procInstall();
                exit(0);
                break;
            case 2:
                procUninstall();
                exit(0);
                break;
            case 3:
                procExtractEventLog();
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

function procInstall() {
    global $binPath;

    exec('"' . $binPath . '/Sysmon.exe" -i -accepteula -h md5 -n -l', $cmdOutput, $cmdReturn);
    $cmdOutputStr = implode(PHP_EOL, $cmdOutput);
    if ($cmdReturn != 0) {
        throw new Exception($cmdOutputStr);
    }

    // Set log max size to 1GB
    // https://technet.microsoft.com/en-us/library/cc748849%28v=ws.11%29.aspx
    $logMaxSize = '1073741824';
    exec('wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:' . $logMaxSize, $cmdOutput2, $cmdReturn2);
    if ($cmdReturn2 != 0) {
        throw new Exception(implode(PHP_EOL, $cmdOutput2));
    }
    $cmdOutput2Str = 'Max log size set to ' . $logMaxSize . ' Bytes';

    echo $cmdOutputStr . PHP_EOL . $cmdOutput2Str;
}

function procUninstall() {
    global $binPath;

    exec('"' . $binPath . '/Sysmon.exe" -u', $cmdOutput, $cmdReturn);
    $cmdOutputStr = implode(PHP_EOL, $cmdOutput);
    if ($cmdReturn != 0) {
        throw new Exception($cmdOutputStr);
    }
    echo $cmdOutputStr;

    $evtx = 'C:/Windows/sysnative/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx';
    if (file_exists($evtx)) {
        echo PHP_EOL . 'Remove ' . $evtx . PHP_EOL;
        unlink($evtx);
    }
}

function procExtractEventLog() {
    global $binPath, $logsPath, $config;

    $tmpEvtx = $logsPath . '/sysmon.evtx.tmp';
    $tmpLogParser = $logsPath . '/sysmon-parsed.tmp';

    echo PHP_EOL . 'Clean tmp files...';
    @unlink($tmpEvtx);
    @unlink($tmpLogParser);

    echo PHP_EOL . 'Copy ' . $config['evtxPath'] . '...';
    if (!copy($config['evtxPath'], $tmpEvtx)) {
        throw new Exception('Cannot copy ' . $config['evtxPath'] . ' to ' . $tmpEvtx);
    }

    echo PHP_EOL . 'Extracts events with LogParser...';
    $logParserCmd = ' -i:evt -o:csv';
    $logParserCmd .= ' "SELECT RecordNumber,TO_UTCTIME(TimeGenerated),EventID,SourceName,ComputerName,SID,Strings';
    $logParserCmd .= ' FROM \'' . formatWindowsPath($tmpEvtx) . '\'';
    $logParserCmd .= ' WHERE EventID = \'3\'"';
    exec('"' . $binPath . '/LogParser.exe"' . $logParserCmd, $cmdOutput, $cmdReturn);
    $cmdOutputStr = implode(PHP_EOL, $cmdOutput);
    if ($cmdReturn != 0) {
        throw new Exception($cmdOutputStr);
    }
    file_put_contents($tmpLogParser, $cmdOutputStr);

    echo PHP_EOL . 'Generate CSV files...';
    $nbLines = 0;
    $excluded = array();
    $results = array();
    if (($handle = fopen($tmpLogParser, 'r')) !== false) {
        while (($data = fgetcsv($handle)) !== false) {
            if (count($data) != 7 || $data[2] != '3') {
                continue;
            }
            $nbLines++;

            $strings = explode('|', $data[6]);
            if ($strings[12] == 'true') { // exclude ipv6
                $excluded[] = $strings;
                continue;
            }

            $destIp = getHost($strings[13], $strings[14]);
            if (empty($destIp)) {
                $excluded[] = $strings;
                continue;
            }

            echo PHP_EOL . '  Found ' . strtolower($destIp);
            $results[] = array(
                'date' => $strings[0],
                'process' => $strings[3],
                'protocol' => $strings[5],
                'destIp' => strtolower($destIp),
                'destPort' => intval($strings[15]),
                'destPortName' => trim($strings[16]),
                'whois' => getWhois($destIp, $logsPath)
            );
        }
        fclose($handle);
    }

    echo PHP_EOL . PHP_EOL . 'Lines: ' . $nbLines;
    echo PHP_EOL . 'To process: ' . count($results) . ' (' . count($excluded) . ' excluded)' . PHP_EOL;

    if (count($results) == 0) {
        throw new Exception('No log to process...');
    }

    $csvAll = 'DATE,PROCESS,PROTOCOL,DEST_IP,DEST_PORT,DEST_PORT_NAME,ORGANIZATION,COUNTRY';
    $csvUnique = $csvAll;
    $dups = array();
    foreach ($results as $result) {
        // Hosts stats
        if (!isset($hosts[$result['destIp']])) {
            $hosts[$result['destIp']] = 0;
        }
        $hosts[$result['destIp']]++;

        // CSV all
        $csvAll .= PHP_EOL . $result['date'] .
            ',' . $result['process'] .
            ',' . $result['protocol'] .
            ',' . $result['destIp'] .
            ',' . $result['destPort'] .
            ',' . $result['destPortName'];
        if (is_array($result['whois'])) {
            $csvAll .= ',' . $result['whois']['org'] . ',' . $result['whois']['country'];
        } else {
            $csvAll .= ',,';
        }

        // Check duplicates
        $depRes = $result;
        unset($depRes['date']);
        unset($depRes['destPort']);
        $dup = md5(serialize($depRes));
        if (in_array($dup, $dups)) {
            continue;
        } else {
            $dups[] = $dup;
        }

        // CSV unique
        $csvUnique .= PHP_EOL . $result['date'] .
            ',' . $result['process'] .
            ',' . $result['protocol'] .
            ',' . $result['destIp'] .
            ',' . $result['destPort'] .
            ',' . $result['destPortName'];
        if (is_array($result['whois'])) {
            $csvUnique .= ',' . $result['whois']['org'] . ',' . $result['whois']['country'];
        } else {
            $csvUnique .= ',,';
        }
    }

    $hosts = sortHostsByKey($hosts);
    $csvHostsCount = 'HOST,COUNT,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN';
    foreach ($hosts as $host => $count) {
        $csvHostsCount .= PHP_EOL . $host . ',' . $count;
        $whois = getWhois($host, $logsPath);
        if (is_array($whois)) {
            $csvHostsCount .= ',' . $whois['org'] . ',' . $whois['country'];
        } else {
            $csvHostsCount .= ',,';
        }
        $resolutions = null;
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $resolutions = getResolutions($host, $logsPath);
        }
        if (is_array($resolutions)) {
            $i = 0;
            foreach ($resolutions as $resolution) {
                if ($i == 0) {
                    $csvHostsCount .= ',' . $resolution['date'] . ',' . $resolution['ipOrDomain'];
                } else {
                    $csvHostsCount .= PHP_EOL . ',,,,' . $resolution['date'] . ',' . $resolution['ipOrDomain'];
                }
                $i++;
            }
        } else {
            $csvHostsCount .= ',,';
        }
    }

    $csvHostsCountsFile = $logsPath . '/sysmon-hosts-count.csv';
    echo PHP_EOL . 'Write ' . $csvHostsCountsFile . '...';
    file_put_contents($csvHostsCountsFile, $csvHostsCount);

    $csvUniqueFile = $logsPath . '/sysmon-unique.csv';
    echo PHP_EOL . 'Write ' . $csvUniqueFile . '...';
    file_put_contents($csvUniqueFile, $csvUnique);

    $csvAllFile = $logsPath . '/sysmon-all.csv';
    echo PHP_EOL . 'Write ' . $csvAllFile . '...';
    file_put_contents($csvAllFile, $csvAll);
}

function getHost($destIp, $destHost) {
    global $config, $logsPath;

    foreach ($config['exclude']['ips'] as $ipExpr) {
        if (isIpExpr($destIp, $ipExpr)) {
            return null;
        }
    }
    $host = $destHost;
    if (empty($destHost) && filter_var($destIp, FILTER_VALIDATE_IP)) {
        $resolutions = getResolutions($destIp, $logsPath);
        if (is_array($resolutions)) {
            $host = $resolutions[0]['ipOrDomain'];
        }
    }
    foreach ($config['exclude']['hosts'] as $hostExpr) {
        if (isHostExpr($host, $hostExpr)) {
            return null;
        }
    }
    /*if (!empty($destHost)) {
        $ipReverse = getIpFromReverse($destHost);
        if ($ipReverse != null) {
            $destHost = null;
        }
    }*/

    return !empty($destHost) ? $destHost : $destIp;
}
