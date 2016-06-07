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
    $config = loadConfig($currentPath . '/proxifier.conf');
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
        echo PHP_EOL . '# WindowsSpyBlocker - Proxifier';
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
    echo PHP_EOL . 'Extract log...';

    if (!file_exists($config['logPath'])) {
        throw new Exception('Log file not found in: ' . $config['logPath']);
    }

    $nbLines = 0;
    $excluded = array();
    $results = array();
    $handle = fopen($config['logPath'], 'r');
    if ($handle) {
        while (($line = fgets($handle)) !== false) {
            $nbLines++;
            $line = cleanLine($line);
            if (!isValidLine($line)) {
                $excluded[] = $line;
                continue;
            }

            $lineAr = explode(" ", $line);
            if (count($lineAr) < 3) {
                $excluded[] = $line;
                continue;
            }

            $host = getHost($lineAr);
            if (empty($host)) {
                $excluded[] = $line;
                continue;
            }

            $results[] = array(
                'date' => str_replace('[', '', $lineAr[0]) . ' ' . str_replace(']', '', $lineAr[1]),
                'exe' => $lineAr[2],
                'pid' => intval($lineAr[3]),
                'account' => count($lineAr) == 6 ? $lineAr[4] : null,
                'host' => strtolower($host),
            );
        }
        fclose($handle);
    }

    echo PHP_EOL . 'Lines: ' . $nbLines ;
    echo PHP_EOL . 'To process: ' . count($results) . ' (' . count($excluded) . ' excluded)' . PHP_EOL;

    if (count($results) == 0) {
        throw new Exception('No log to process...');
    }

    $csvAll = 'DATE,EXE,PID,ACCOUNT,HOST';
    $csvUnique = $csvAll;
    $dups = array();
    foreach ($results as $result) {
        // Hosts stats
        if (!isset($hosts[$result['host']])) {
            $hosts[$result['host']] = 0;
        }
        $hosts[$result['host']]++;

        // CSV all
        $csvAll .= PHP_EOL . $result['date'] .
            ',' . $result['exe'] .
            ',' . $result['pid'] .
            ',' . $result['account'] .
            ',' . $result['host'];

        // Check duplicates
        $depRes = $result;
        unset($depRes['date']);
        unset($depRes['pid']);
        $dup = md5(serialize($depRes));
        if (in_array($dup, $dups)) {
            continue;
        } else {
            $dups[] = $dup;
        }

        // CSV unique
        $csvUnique .= PHP_EOL . $result['date'] .
            ',' . $result['exe'] .
            ',' . $result['pid'] .
            ',' . $result['account'] .
            ',' . $result['host'];
    }

    arsort($hosts);
    $csvHostsCount = 'HOST,COUNT';
    foreach ($hosts as $host => $count) {
        $csvHostsCount .= PHP_EOL . $host . ',' . $count;
    }

    $csvHostsCountsFile = $logsPath . '/proxifier-hosts-count.csv';
    echo PHP_EOL . 'Write ' . $csvHostsCountsFile . '...';
    file_put_contents($csvHostsCountsFile, $csvHostsCount);

    $csvUniqueFile = $logsPath . '/proxifier-unique.csv';
    echo PHP_EOL . 'Write ' . $csvUniqueFile . '...';
    file_put_contents($csvUniqueFile, $csvUnique);

    $csvAllFile = $logsPath . '/proxifier-all.csv';
    echo PHP_EOL . 'Write ' . $csvAllFile . '...';
    file_put_contents($csvAllFile, $csvAll);
}

function cleanLine($line) {
    $line = trim(preg_replace('/matching(.*?)rule/i', '', $line));
    $line = trim(preg_replace('/open\sdirectly/i', '', $line));
    $line = trim(preg_replace('/\:\sdirect\sconnection/i', '', $line));
    $line = trim(preg_replace('/\:\sconnection\sblocked/i', '', $line));
    $line = trim(preg_replace('/\serror\s\:\sA\sconnection\srequest\swas\scanceled(.*?)$/i', '', $line));
    $line = trim(preg_replace('/\serror\s\:\sCould\snot\sconnect(.*?)$/i', '', $line));
    $line = trim(preg_replace('/:\sDNS/i', '', $line));
    $line = trim(preg_replace('/\(According\sto\sRules\)/i', '', $line));
    $line = trim(preg_replace('/GetSockName\s\:(.*?)$/i', '', $line));
    $line = trim(preg_replace('/close(.*?)bytes(.*?)sent(.*?)received(.*?)lifetime(.*?)$/i', '', $line));
    $line = trim(preg_replace('/resolve\s/i', '', $line));
    $line = trim(preg_replace('/\*64\s/i', '', $line));
    $line = trim(preg_replace('/\s-\s/i', ' ', $line));
    $line = trim(preg_replace('/\((\d+),\s(.*?)\)/i', '$1 $2', $line));
    $line = trim(preg_replace('/\((\d+)\)/i', '$1', $line));
    return $line;
}

function isValidLine($line) {
    return !contains($line, 'Welcome to Proxifier')
        && !contains($line, 'Profile saved as')
        && !contains($line, 'Log file enabled')
        && !contains($line, 'Traffic log enabled')
        && !contains($line, 'Traffic file disabled')
        && !contains($line, 'Verbose output enabled')
        && !contains($line, 'Log Directory is set to')
        && !contains($line, 'Local CMOS Clock')
        && !contains($line, 'Automatic DNS mode detection')
        && !contains($line, '(IPv6)')
        && !contains($line, 'source socket not found')
        && !contains($line, 'Connections do not originate from the applications')
        && !endWith($line, 'loaded.');
}

function getHost($lineAr) {
    global $config, $logsPath;

    $elt = rtrim($lineAr[count($lineAr) - 1], '.');
    if (contains($elt, ':')) {
        list($elt, $port) = explode(':', $elt);
    }
    if (contains($elt, '\\')) {
        return null;
    }
    foreach ($config['exclude']['ips'] as $ipExpr) {
        if (isIpExpr($elt, $ipExpr)) {
            return null;
        }
    }
    if (filter_var($elt, FILTER_VALIDATE_IP)) {
        $ipWhois = getResolvedIp($elt, $logsPath);
        if ($ipWhois != null) {
            $elt = $ipWhois;
        }
    }
    foreach ($config['exclude']['hosts'] as $hostExpr) {
        if (isHostExpr($elt, $hostExpr)) {
            return null;
        }
    }

    return $elt;
}
