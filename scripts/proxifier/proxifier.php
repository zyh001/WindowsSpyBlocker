<?php

include realpath('..') . '/.bin/util.php';

$currentPath = formatUnixPath(realpath(''));
$basePath = formatUnixPath(realpath('../..'));
$logsPath = $basePath . '/logs';

try {
    $config = loadConfig($currentPath . '/proxifier.conf');
    if (count($argv) < 2) {
        throw new Exception('Missing main arg');
    }
    call_user_func('process' . ucfirst($argv[1]));
    exit(0);
} catch (Exception $ex) {
    echo 'Error: ' . $ex->getMessage() . PHP_EOL;
    exit(1);
}

///////////////////////////////////////////////
///////////////////////////////////////////////

function processExtractLog() {
    global $logsPath, $config;

    $nbLines = 0;
    $excluded = array();
    $results = array();
    $handle = fopen($config['logPath'], "r");
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
                'host' => $host,
            );
        }
        fclose($handle);
    }

    echo 'Lines: ' . $nbLines . PHP_EOL;
    echo 'To process: ' . count($results) . ' (' . count($excluded) . ' excluded)' . PHP_EOL . PHP_EOL;

    $csvAll = 'From: ' . $results[0]['date'] . PHP_EOL;
    $csvAll .= 'To: ' . $results[count($results) - 1]['date'] . PHP_EOL;
    $csvAll .= PHP_EOL . 'DATE,EXE,PID,ACCOUNT,HOST';
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
    $csvHostsCount = 'From: ' . $results[0]['date'] . PHP_EOL;
    $csvHostsCount .= 'To: ' . $results[count($results) - 1]['date'] . PHP_EOL;
    $csvHostsCount .= PHP_EOL . 'HOST,COUNT';
    foreach ($hosts as $host => $count) {
        $csvHostsCount .= PHP_EOL . $host . ',' . $count;
    }

    echo 'Write proxifier-hosts-count.csv...'. PHP_EOL;
    file_put_contents($logsPath . '/proxifier-hosts-count.csv', $csvHostsCount);
    echo 'Write proxifier-unique.csv...'. PHP_EOL;
    file_put_contents($logsPath . '/proxifier-unique.csv', $csvUnique);
    echo 'Write proxifier-all.csv...'. PHP_EOL;
    file_put_contents($logsPath . '/proxifier-all.csv', $csvAll);
}

function cleanLine($line) {
    $line = trim(preg_replace('/matching(.*?)rule/i', '', $line));
    $line = trim(preg_replace('/:\sdirect\sconnection/i', '', $line));
    $line = trim(preg_replace('/:\sconnection\sblocked/i', '', $line));
    $line = trim(preg_replace('/:\sDNS/i', '', $line));
    $line = trim(preg_replace('/\(According\sto\sRules\)/i', '', $line));
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
        && !contains($line, 'Verbose output enabled')
        && !contains($line, 'Log Directory is set to')
        && !contains($line, 'Automatic DNS mode detection')
        && !contains($line, '(IPv6)')
        && !endWith($line, 'loaded.');
}

function getHost($lineAr) {
    global $config;

    $elt = rtrim($lineAr[count($lineAr) - 1], '.');
    if (contains($elt, ':')) {
        list($elt, $port) = explode(':', $elt);
    }
    if (contains($elt, '\\')) {
        return null;
    }
    foreach ($config['exclude']['ips'] as $ipExpr) {
        if (isIpExpr($elt, $ipExpr)) {
            return false;
        }
    }
    foreach ($config['exclude']['hosts'] as $hostExpr) {
        if (isHostExpr($elt, $hostExpr)) {
            return false;
        }
    }

    return $elt;
}
