<?php

include realpath('..') . '/.bin/util.php';

$currentPath = formatUnixPath(realpath(''));
$binPath = formatUnixPath(realpath('..')) . '/.bin';
$basePath = formatUnixPath(realpath('../..'));
$logsPath = $basePath . '/logs';

try {
    $config = loadConfig($currentPath . '/sysmon.conf');
    if (count($argv) < 2) {
        throw new Exception('Missing main arg');
    }
    call_user_func('process' . ucfirst($argv[1]));
    exit(0);
} catch (Exception $ex) {
    echo 'Error: ' . $ex->getMessage() . PHP_EOL;
    exit(1);
}

function processInstall() {
    global $binPath;

    exec($binPath . '/Sysmon.exe -i -accepteula -h md5 -n -l', $cmdOutput, $cmdReturn);
    $cmdOutputStr = implode(PHP_EOL, $cmdOutput);
    if ($cmdReturn != 0) {
        throw new Exception($cmdOutputStr);
    }

    echo $cmdOutputStr;
}

function processUninstall() {
    global $binPath, $config;

    exec($binPath . '/Sysmon.exe -u', $cmdOutput, $cmdReturn);
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

function processExtractEventLog() {
    global $binPath, $logsPath, $config, $ipWhoisUrl;

    $tmpEvtx = $logsPath . '/sysmon.evtx.tmp';
    $tmpLogParser = $logsPath . '/sysmon-parsed.tmp';

    echo 'Clean tmp files' . PHP_EOL;
    @unlink($tmpEvtx);
    @unlink($tmpLogParser);

    echo 'Copy ' . $config['evtxPath'] . PHP_EOL;
    if (!copy($config['evtxPath'], $tmpEvtx)) {
        throw new Exception('Cannot copy ' . $config['evtxPath'] . ' to ' . $tmpEvtx);
    }

    echo 'Extracts events with LogParser' . PHP_EOL;
    $logParserCmd = '-i:evt -o:csv';
    $logParserCmd .= ' "SELECT RecordNumber,TO_UTCTIME(TimeGenerated),EventID,SourceName,ComputerName,SID,Strings';
    $logParserCmd .= ' FROM \'' . formatWindowsPath($tmpEvtx) . '\'';
    $logParserCmd .= ' WHERE EventID = \'3\'"';
    exec($binPath . '/LogParser.exe ' . $logParserCmd, $cmdOutput, $cmdReturn);
    $cmdOutputStr = implode(PHP_EOL, $cmdOutput);
    if ($cmdReturn != 0) {
        throw new Exception($cmdOutputStr);
    }
    file_put_contents($tmpLogParser, $cmdOutputStr);

    echo 'Generate CSV files' . PHP_EOL;
    $nbLines = 0;
    $ipWhois = array();
    $excluded = array();
    $results = array();
    if (($handle = fopen($tmpLogParser, 'r')) !== false) {
        while (($data = fgetcsv($handle)) !== false) {
            if (count($data) != 7 || $data[2] != '3') {
                continue;
            }
            $nbLines++;

            $strings = explode('|', $data[6]);
            if (!isValidLog($strings[12], $strings[13])) {
                $excluded[] = $strings;
                continue;
            }

            $destIp = !empty($strings[14]) ? $strings[14] : $strings[13];
            if (filter_var($destIp, FILTER_VALIDATE_IP)) {
                if (!isset($ipWhois[$destIp])) {
                    $ipWhois[$destIp] = parseIpWhois(getUrlContent($ipWhoisUrl . $destIp));
                }
                if ($ipWhois[$destIp] != null) {
                    $destIp = $ipWhois[$destIp];
                }
            }

            if (!isValidLog($strings[12], $destIp)) {
                $excluded[] = $strings;
                continue;
            }

            $results[] = array(
                'date' => $strings[0],
                'process' => $strings[3],
                'user' => $strings[4],
                'protocol' => $strings[5],
                'srcIp' => !empty($strings[9]) ? $strings[9] : $strings[8],
                'srcPort' => intval($strings[10]),
                'srcPortName' => trim($strings[11]),
                'destIp' => $destIp,
                'destPort' => intval($strings[15]),
                'destPortName' => trim($strings[16]),
            );
        }
        fclose($handle);
    }

    echo '  Lines: ' . $nbLines . PHP_EOL;
    echo '  To process: ' . count($results) . ' (' . count($excluded) . ' excluded)' . PHP_EOL;

    $csvAll = 'From: ' . $results[0]['date'] . PHP_EOL;
    $csvAll .= 'To: ' . $results[count($results) - 1]['date'] . PHP_EOL;
    $csvAll .= PHP_EOL . 'DATE,PROCESS,USER,PROTOCOL,SRC_IP,SRC_PORT,SRC_PORT_NAME,DEST_IP,DEST_PORT,DEST_PORT_NAME';
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
            ',' . $result['user'] .
            ',' . $result['protocol'] .
            ',' . $result['srcIp'] .
            ',' . $result['srcPort'] .
            ',' . $result['srcPortName'] .
            ',' . $result['destIp'] .
            ',' . $result['destPort'] .
            ',' . $result['destPortName'];

        // Check duplicates
        $depRes = $result;
        unset($depRes['date']);
        unset($depRes['user']);
        unset($depRes['srcIp']);
        unset($depRes['srcPort']);
        unset($depRes['srcPortName']);
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
            ',' . $result['user'] .
            ',' . $result['protocol'] .
            ',' . $result['srcIp'] .
            ',' . $result['srcPort'] .
            ',' . $result['srcPortName'] .
            ',' . $result['destIp'] .
            ',' . $result['destPort'] .
            ',' . $result['destPortName'];
    }

    arsort($hosts);
    $csvHostsCount = 'From: ' . $results[0]['date'] . PHP_EOL;
    $csvHostsCount .= 'To: ' . $results[count($results) - 1]['date'] . PHP_EOL;
    $csvHostsCount .= PHP_EOL . 'HOST,COUNT';
    foreach ($hosts as $host => $count) {
        $csvHostsCount .= PHP_EOL . $host . ',' . $count;
    }

    echo '  Write sysmon-hosts-count.csv...'. PHP_EOL;
    file_put_contents($logsPath . '/sysmon-hosts-count.csv', $csvHostsCount);
    echo '  Write sysmon-unique.csv...'. PHP_EOL;
    file_put_contents($logsPath . '/sysmon-unique.csv', $csvUnique);
    echo '  Write sysmon-all.csv...'. PHP_EOL;
    file_put_contents($logsPath . '/sysmon-all.csv', $csvAll);
}

function isValidLog($ipv6, $destIp) {
    global $config;

    if ($ipv6 == 'true') {
        return false;
    }
    foreach ($config['exclude']['ips'] as $ipExpr) {
        if (isIpExpr($destIp, $ipExpr)) {
            return false;
        }
    }
    foreach ($config['exclude']['hosts'] as $hostExpr) {
        if (isHostExpr($destIp, $hostExpr)) {
            return false;
        }
    }
    return true;
}
