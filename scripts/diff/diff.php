<?php

include realpath('..') . '/.bin/util.php';

$currentPath = formatUnixPath(realpath(''));
$basePath = formatUnixPath(realpath('../..'));
$dataPath = $basePath . '/data';
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
    $config = loadConfig($currentPath . '/diff.conf');
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

function menu($task = null, $display = true) {
    global $config;

    if ($display) {
        echo PHP_EOL . '# WindowsSpyBlocker - Diff';
        echo PHP_EOL . '# https://github.com/crazy-max/WindowsSpyBlocker';
        echo PHP_EOL;
        $i = 1;
        foreach ($config['os'] as $key => $name) {
            echo PHP_EOL . '  ' . $i . '  - ' . $name;
            $i++;
        }
        echo PHP_EOL;
        echo PHP_EOL . '  99 - Exit';
        echo PHP_EOL . PHP_EOL;
    }

    if ($task == null) {
        $task = prompt('Choose a task: ');
    }
    try {
        $i = 1;
        foreach ($config['os'] as $key => $name) {
            if ($task == $i) {
                menuDiff($i, $key);
                return;
            }
            $i++;
        }
        switch ($task) {
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

function menuDiff($prevTask, $os, $display = true) {
    global $config;
    echo PHP_EOL;

    if ($display) {
        echo '# Diff for ' . $config['os'][$os];
        echo PHP_EOL;
        echo PHP_EOL . '  1  - All';
        echo PHP_EOL;
        echo PHP_EOL . '  2  - Proxifier';
        echo PHP_EOL . '  3  - Sysmon';
        echo PHP_EOL . '  4  - Wireshark';
        echo PHP_EOL;
        echo PHP_EOL . '  98 - Previous';
        echo PHP_EOL . '  99 - Exit';
        echo PHP_EOL . PHP_EOL;
    }

    $task = prompt('Choose a task: ');

    try {
        switch ($task) {
            case 1:
                procAll($os);
                exit($prevTask);
                break;
            case 2:
                procProxifier($os);
                exit($prevTask);
                break;
            case 3:
                procSysmon($os);
                exit($prevTask);
                break;
            case 4:
                procWireshark($os);
                exit($prevTask);
                break;
            case 98:
                exit(98);
            case 99:
                exit(99);
                break;
            default:
                echo 'Unknown task...';
                exit($prevTask);
                break;
        }
    } catch (Exception $ex) {
        echo 'Error: ' . $ex->getMessage() . PHP_EOL;
        exit($prevTask);
    }
}

function procAll($os) {
    global $logsPath;

    $resultsFile = $logsPath . '/' . $os . '/diff-all.csv';
    $reverseResultsFile = $logsPath . '/' . $os . '/diff-all-reverse.csv';

    if (!file_exists($logsPath . '/' . $os)) {
        mkdir($logsPath . '/' . $os);
    } else {
        @unlink($resultsFile);
        @unlink($reverseResultsFile);
    }

    $diffs = getDiffs($os);
    $result = array();
    $result = array_unique(array_merge($result, procSysmon($os, $diffs)));
    $result = array_unique(array_merge($result, procProxifier($os, $diffs)));
    $result = array_unique(array_merge($result, procWireshark($os, $diffs)));

    if (empty($result)) {
        echo PHP_EOL . 'No diff found...';
        return;
    }

    $hosts = sortHosts($result);
    $csv = 'HOST,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN';
    foreach ($hosts as $host) {
        $csv .= PHP_EOL . $host;
        $whois = getWhois($host, $logsPath);
        if (is_array($whois)) {
            $csv .= ',' . $whois['org'] . ',' . $whois['country'];
        } else {
            $csv .= ',,';
        }
        $resolutions = null;
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $resolutions = getResolutions($host, $logsPath);
        }
        if (is_array($resolutions)) {
            $i = 0;
            foreach ($resolutions as $resolution) {
                if ($i == 0) {
                    $csv .= ',' . $resolution['date'] . ',' . $resolution['ipOrDomain'];
                } else {
                    $csv .= PHP_EOL . ',,,' . $resolution['date'] . ',' . $resolution['ipOrDomain'];
                }
                $i++;
            }
        } else {
            $csv .= ',,';
        }
    }

    echo PHP_EOL . 'Write results to ' . $resultsFile . '...';
    file_put_contents($resultsFile, $csv);

    $reverseResult = array();
    foreach ($result as $host) {
        $ipReverse = getIpFromReverse($host);
        if ($ipReverse != null && !in_array($ipReverse, $diffs)) {
            $reverseResult[] = $ipReverse;
        }
    }

    if (empty($reverseResult)) {
        echo PHP_EOL . 'No reverse diff found...';
        return;
    }

    $hosts = sortHosts($reverseResult);
    $csv = 'HOST,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN';
    foreach ($hosts as $host) {
        $csv .= PHP_EOL . $host;
        $whois = getWhois($host, $logsPath);
        if (is_array($whois)) {
            $csv .= ',' . $whois['org'] . ',' . $whois['country'];
        } else {
            $csv .= ',,';
        }
        $resolutions = null;
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $resolutions = getResolutions($host, $logsPath);
        }
        if (is_array($resolutions)) {
            $i = 0;
            foreach ($resolutions as $resolution) {
                if ($i == 0) {
                    $csv .= ',' . $resolution['date'] . ',' . $resolution['ipOrDomain'];
                } else {
                    $csv .= PHP_EOL . ',,,' . $resolution['date'] . ',' . $resolution['ipOrDomain'];
                }
                $i++;
            }
        } else {
            $csv .= ',,';
        }
    }

    echo PHP_EOL . 'Write reverse results to ' . $reverseResultsFile . '...';
    file_put_contents($reverseResultsFile, $csv);
}

function procSysmon($os, $diffs = null) {
    return hostsCountCsv($os, 'Sysmon', $diffs);
}

function procProxifier($os, $diffs = null) {
    return hostsCountCsv($os, 'Proxifier', $diffs);
}

function procWireshark($os, $diffs = null) {
    return hostsCountCsv($os, 'Wireshark', $diffs);
}

function hostsCountCsv($os, $name, $diffs = null) {
    global $logsPath;
    $result = array();
    $all = $diffs != null;
    $diffs = $diffs != null ? $diffs : getDiffs($os);

    $resultsFile = $logsPath . '/' . $os . '/diff-' . strtolower($name) . '.csv';
    if (!file_exists($logsPath . '/' . $os)) {
        mkdir($logsPath . '/' . $os);
    } else {
        @unlink($resultsFile);
    }

    $csv = $logsPath . '/' . $os . '/' . strtolower($name) . '-hosts-count.csv';
    if (!file_exists($csv)) {
        return $result;
        //echo $all ? PHP_EOL : '';
        //throw new Exception('CSV file not found: ' . $csv);
    }

    if (($handle = fopen($csv, 'r')) !== false) {
        while (($data = fgetcsv($handle)) !== false) {
            if (empty($data[0]) || $data[0] == 'HOST') {
                continue;
            }
            $data[0] = strtolower($data[0]);
            if (!in_array($data[0], $diffs)) {
                $result[] = $data[0];
            }
        }
        fclose($handle);
    }
    echo PHP_EOL . count($result) . ' diff(s) found for ' . $name;

    if ($all || count($result) == 0) {
        return $result;
    }
    if (empty($result)) {
        echo PHP_EOL . 'No diff found...';
        return null;
    }

    $hosts = sortHosts($result);
    $csv = 'HOST,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN';
    foreach ($hosts as $host) {
        $csv .= PHP_EOL . $host;
        $whois = getWhois($host);
        if (is_array($whois)) {
            $csv .= ',' . $whois['org'] . ',' . $whois['country'];
        } else {
            $csv .= ',,';
        }
        $resolutions = null;
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $resolutions = getResolutions($host, $logsPath);
        }
        if (is_array($resolutions)) {
            $i = 0;
            foreach ($resolutions as $resolution) {
                if ($i == 0) {
                    $csv .= ',' . $resolution['date'] . ',' . $resolution['ipOrDomain'];
                } else {
                    $csv .= PHP_EOL . ',,,' . $resolution['date'] . ',' . $resolution['ipOrDomain'];
                }
                $i++;
            }
        } else {
            $csv .= ',,';
        }
    }

    echo PHP_EOL . 'Write results to ' . $resultsFile . '...';
    file_put_contents($resultsFile, $csv);
}

function getDiffs($os) {
    global $basePath, $config;

    $result = array();
    $data = $config['data'][$os];
    foreach ($data as $dataFile) {
        $handle = fopen($basePath . $dataFile, 'r');
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                $line = str_replace('0.0.0.0 ', '', trim($line));
                if (empty($line) || contains($line, '#')) {
                    continue;
                }
                if (contains($line, '-')) {
                    $lineAr = explode('-', $line);
                    if (count($lineAr) == 2 && filter_var($lineAr[0], FILTER_VALIDATE_IP) && filter_var($lineAr[1], FILTER_VALIDATE_IP)) {
                        $result = array_merge($result, array_map('long2ip', range(ip2long($lineAr[0]), ip2long($lineAr[1]))));
                    } else {
                        $result[] = $line;
                    }
                } else {
                    $result[] = $line;
                }
            }
            fclose($handle);
        }
    }

    echo PHP_EOL . 'Load ' . count($result) . ' diffs to process...' . PHP_EOL;
    return $result;
}
