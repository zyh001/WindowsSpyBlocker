<?php

include realpath('..') . '/.bin/util.php';

$currentPath = formatUnixPath(realpath(''));
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
    $config = loadConfig($currentPath . '/wireshark.conf');
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
        echo PHP_EOL . '# WindowsSpyBlocker - Wireshark';
        echo PHP_EOL . '# https://github.com/crazy-max/WindowsSpyBlocker';
        echo PHP_EOL;
        echo PHP_EOL . '  1  - Extract log';
        echo PHP_EOL . '  99 - Exit';
        echo PHP_EOL . PHP_EOL;
    }

    $task = prompt('Choose a task: ');

    try {
        switch ($task) {
            case 1:
                procExtractLog();
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

function procExtractLog() {
    global $logsPath, $config;

    if (!file_exists($config['pcapngPath'])) {
        throw new Exception("pcapng file not found in: " . $config['pcapngPath']);
    }

    if (!file_exists($config['tsharkExe'])) {
        throw new Exception("tshark executable not found in: " . $config['tsharkExe']);
    }

    $tmpIpv4Hosts = $logsPath . '/wireshark-ipv4-hosts.tmp';

    echo PHP_EOL . 'Extract IPv4 Hosts...';
    $ipv4HostsOutput = getTsharkStats('ip_hosts,tree');
    file_put_contents($tmpIpv4Hosts, $ipv4HostsOutput);

    $results = array();
    $excluded = array();
    $handle = fopen($tmpIpv4Hosts, "r");
    if ($handle) {
        while (($line = fgets($handle)) !== false) {
            $lineExp = explode(" ", trim(preg_replace('/\s+/', ' ', $line)));
            if (count($lineExp) != 6 || in_array($lineExp[0], $results)) {
                continue;
            }
            $ip = getHost(strtolower($lineExp[0]));
            if (empty($ip)) {
                $excluded[] = strtolower($lineExp[0]);
                continue;
            }
            $resolutions = getResolutions($ip, $logsPath);
            $whois = getWhois($ip, $logsPath);
            $results[$ip] = array(
                'count' => $lineExp[1],
                'resolutions' => $resolutions,
                'whois' => $whois
            );
        }
        fclose($handle);
    }

    echo PHP_EOL . count($results) . ' found (' . count($excluded) . ' excluded)' . PHP_EOL;

    if (count($results) == 0) {
        throw new Exception('No log to process...');
    }

    $results = sortHostsByKey($results);
    $csv = 'HOST,COUNT,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN';
    foreach ($results as $host => $data) {
        $csv .= PHP_EOL . $host . ',' . $data['count'];
        if (is_array($data['whois'])) {
            $csv .= ',' . $data['whois']['org'] . ',' . $data['whois']['country'];
        } else {
            $csv .= ',,';
        }
        if (is_array($data['resolutions'])) {
            $i = 0;
            foreach ($data['resolutions'] as $resolution) {
                if ($i == 0) {
                    $csv .= ',' . $resolution['date'] . ',' . $resolution['ipOrDomain'];
                } else {
                    $csv .= PHP_EOL . ',,,,' . $resolution['date'] . ',' . $resolution['ipOrDomain'];
                }
                $i++;
            }
        } else {
            $csv .= ',,';
        }
    }

    $csvFile = $logsPath . '/wireshark-hosts-count.csv';
    echo 'Write ' . $csvFile . '...';
    file_put_contents($csvFile, $csv);
}

function getTsharkStats($stat) {
    global $config;

    $tsharkCmd = ' -r "' . $config['pcapngPath'] . '"';
    $tsharkCmd .= ' -q -z ' . $stat;
    exec('"' . $config['tsharkExe'] . '"' . $tsharkCmd, $cmdOutput, $cmdReturn);
    $cmdOutputStr = implode(PHP_EOL, $cmdOutput);
    if ($cmdReturn != 0) {
        throw new Exception($cmdOutputStr);
    }

    return $cmdOutputStr;
}

function getHost($destIp) {
    global $config, $logsPath;

    foreach ($config['exclude']['ips'] as $ipExpr) {
        if (isIpExpr($destIp, $ipExpr)) {
            return null;
        }
    }
    $host = $destIp;
    if (filter_var($destIp, FILTER_VALIDATE_IP)) {
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
    /*if (!filter_var($destIp, FILTER_VALIDATE_IP)) {
        $ipReverse = getIpFromReverse($destIp);
        if ($ipReverse != null) {
            $destIp = $ipReverse;
        }
    }*/

    return $destIp;
}
