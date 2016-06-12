<?php

include realpath('..') . '/.bin/util.php';

$currentPath = formatUnixPath(realpath(''));
$basePath = formatUnixPath(realpath('../..'));
$dataPath = $basePath . '/data/firewall';
$logsPath = $basePath . '/logs';
$rulesPrefix = 'windowsSpyBlocker';

// exit codes
// 0 > ok
// 1-90 > tasks
// 97 > unknown task
// 98 > previous
// 99 > exit
// 254 > error
// 255 > fatal error

try {
    $config = loadConfig($currentPath . '/firewall.conf');
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
        echo PHP_EOL . '# WindowsSpyBlocker - Firewall';
        echo PHP_EOL . '# https://github.com/crazy-max/WindowsSpyBlocker';
        echo PHP_EOL;
        $i = 1;
        foreach ($config['os'] as $key => $name) {
            echo PHP_EOL . '  ' . $i . '  - ' . $name;
            $i++;
        }
        echo PHP_EOL;
        echo PHP_EOL . '  10 - Remove rules';
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
                menuAddRules($i, $key);
                return;
            }
            $i++;
        }
        switch ($task) {
            case 10:
                procRemoveRules();
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
        echo 'Error: ' . $ex->getMessage() . PHP_EOL;
        exit(254);
    }
}

function menuAddRules($prevTask, $os, $display = true) {
    global $config;
    echo PHP_EOL;

    if ($display) {
        echo '# Firewall rules for ' . $config['os'][$os];
        echo PHP_EOL;
        $i = 1;
        foreach ($config['rules']['local'][$os] as $rulePath) {
            $type = pathinfo($rulePath, PATHINFO_FILENAME);
            echo PHP_EOL . '  ' . $i . '  - Add ' . $type . ' rules (local)';
            $i++;
        }
        echo PHP_EOL;
        foreach ($config['rules']['remote'][$os] as $ruleUrl) {
            $type = pathinfo($ruleUrl, PATHINFO_FILENAME);
            echo PHP_EOL . '  ' . $i . '  - Add ' . $type . ' rules (remote)';
            $i++;
        }
        echo PHP_EOL;
        echo PHP_EOL . '  20 - Test IPs (local)';
        echo PHP_EOL . '  21 - Test IPs (remote)';
        echo PHP_EOL;
        echo PHP_EOL . '  98 - Previous';
        echo PHP_EOL . '  99 - Exit';
        echo PHP_EOL . PHP_EOL;
    }

    $task = prompt('Choose a task: ');

    try {
        $i = 1;
        foreach ($config['rules']['local'][$os] as $rule) {
            if ($task == $i) {
                procAddRules($os, $rule, false);
                exit($prevTask);
            }
            $i++;
        }
        foreach ($config['rules']['remote'][$os] as $rule) {
            if ($task == $i) {
                procAddRules($os, $rule, true);
                exit($prevTask);
            }
            $i++;
        }
        switch ($task) {
            case 20:
                procTestIps($os, false);
                exit($prevTask);
                break;
            case 21:
                procTestIps($os, true);
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

function procAddRules($os, $pathOrUrl, $remote = true) {
    global $basePath, $dataPath;
    echo PHP_EOL;

    $type = pathinfo($pathOrUrl, PATHINFO_FILENAME);
    if (!$remote) {
        $rulePath = $basePath . $pathOrUrl;
        if (!file_exists($rulePath)) {
            throw new Exception('Rule file not found in ' . $rulePath);
        }
    } else {
        $ruleUrl = $pathOrUrl;
        $rulePath = $dataPath . '/' . preg_replace('/\..+$/', '.tmp', basename($ruleUrl));
        echo 'Download ' . basename($ruleUrl) . '.';
        if (download($ruleUrl, $rulePath)) {
            echo ' OK' . PHP_EOL;
        } else {
            throw new Exception('Download failed');
        }
        if (!file_exists($rulePath)) {
            throw new Exception('Rule file not found in ' . $rulePath);
        }
    }

    // Remove rules
    removeRules($os, $type);

    // Add rules
    $ips = array();
    $handle = fopen($rulePath, 'r');
    if ($handle) {
        while (($line = fgets($handle)) !== false) {
            $line = trim($line);
            if (contains($line, '-')) {
                $lineAr = explode('-', $line);
                if (count($lineAr) != 2) {
                    continue;
                }
                if (!filter_var($lineAr[0], FILTER_VALIDATE_IP) || !filter_var($lineAr[1], FILTER_VALIDATE_IP)) {
                    continue;
                }
                $ips[] = $line;
            } else if (!filter_var($line, FILTER_VALIDATE_IP)) {
                continue;
            } else {
                $ips[] = $line;
            }
        }
        fclose($handle);
    }
    if ($remote) {
        unlink($rulePath);
    }

    if (empty($ips)) {
        throw new Exception('No IPs found in ' . $rulePath);
    }

    echo PHP_EOL . 'Add ' . count($ips) . ' rules...';
    $prefix = getPrefix($os, $type);
    foreach ($ips as $ip) {
        echo PHP_EOL . '  ' . $prefix . $ip;
        $netsh = 'netsh advfirewall firewall add rule';
        $netsh .= ' name="' . $prefix . $ip . '"';
        $netsh .= ' dir=out protocol=any action=block';
        $netsh .= ' remoteip=' . $ip;
        exec($netsh, $cmdOutput, $cmdReturn);
        $cmdOutputStr = implode(PHP_EOL, $cmdOutput);
        if ($cmdReturn != 0) {
            throw new Exception($cmdOutputStr);
        }
    }
}

function procRemoveRules() {
    echo PHP_EOL;
    removeRules();
}

function procTestIps($os, $remote = true) {
    global $basePath, $logsPath, $config;

    if (!file_exists($logsPath . '/' . $os)) {
        mkdir($logsPath . '/' . $os);
    }

    $ipsFiles = array();
    if (!$remote) {
        foreach ($config['rules']['local'][$os] as $rulePath) {
            $type = pathinfo($rulePath, PATHINFO_FILENAME);
            $finalPath = $basePath . $rulePath;
            if (!file_exists($finalPath)) {
                echo 'Rule file not found in ' . $finalPath . PHP_EOL;
            } else {
                $ipsFiles[$type] = $finalPath;
            }
        }
    } else {
        foreach ($config['rules']['remote'][$os] as $ruleUrl) {
            $type = pathinfo($ruleUrl, PATHINFO_FILENAME);
            $finalPath = $logsPath . '/' . $os . '/' . preg_replace('/\..+$/', '.tmp', basename($ruleUrl));
            echo 'Download ' . $type . '.';
            if (download($ruleUrl, $finalPath)) {
                echo ' OK' . PHP_EOL;
            } else {
                throw new Exception('Download failed');
            }
            if (!file_exists($finalPath)) {
                echo 'Rule file not found in ' . $finalPath . PHP_EOL;
            } else {
                $ipsFiles[$type] = $finalPath;
            }
        }
    }

    foreach ($ipsFiles as $ipsFile) {
        $ips = array();
        $type = pathinfo($ipsFile, PATHINFO_FILENAME);

        $handle = fopen($ipsFile, 'r');
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                $line = trim($line);
                if (contains($line, '-')) {
                    $lineAr = explode('-', $line);
                    if (count($lineAr) != 2) {
                        continue;
                    }
                    if (!filter_var($lineAr[0], FILTER_VALIDATE_IP) || !filter_var($lineAr[1], FILTER_VALIDATE_IP)) {
                        continue;
                    }
                    //TODO: Manage ip range
                    //$ips = array_merge($ips, array_map('long2ip', range(ip2long($lineAr[0]), ip2long($lineAr[1]))));
                } else if (!filter_var($line, FILTER_VALIDATE_IP)) {
                    continue;
                } else {
                    $ips[] = $line;
                }
            }
            fclose($handle);
        }

        $results = array();
        echo PHP_EOL . 'Process ' . $type . ' (' . count($ips) . ' IPs)' . PHP_EOL;
        foreach ($ips as $ip) {
            echo '  Checking ' . $ip . '...' . PHP_EOL;
            $results[$ip] = getTestIpResult($ip);
            echo '    Organization: ' . $results[$ip]['org'] . PHP_EOL;
            echo '    Country: ' . $results[$ip]['country'] . PHP_EOL;
            /*if (is_array($results[$ip]['resolutions'])) {
                echo '    Resolved date: ' . $results[$ip]['resolutions'][0]['date'] . PHP_EOL;
                echo '    Resolved domain: ' . $results[$ip]['resolutions'][0]['ipOrDomain'] . PHP_EOL;
            } else {
                echo '    Resolved date: ' . PHP_EOL;
                echo '    Resolved domain: ' . PHP_EOL;
            }*/
            if (is_array($results[$ip]['resolutions'])) {
                echo '    Resolutions:' . PHP_EOL;
                foreach ($results[$ip]['resolutions'] as $resolutions) {
                    echo '      ' . $resolutions['date'] . ' - ' . $resolutions['ipOrDomain'] . PHP_EOL;
                }
            } else {
                echo '    Resolutions:' . PHP_EOL;
            }
        }

        $csvFile = $logsPath . '/' . $os . '/firewall-test-' . $type . '.csv';
        echo 'Write ' . $csvFile . '...'. PHP_EOL;
        $csv = 'IP,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN';
        foreach ($results as $ip => $result) {
            $csv .= PHP_EOL . $ip . ',' . $result['org'] . ',' . $result['country'];
            if (is_array($results[$ip]['resolutions'])) {
                //$csv .= ',' . $results[$ip]['resolutions'][0]['date'] . ',' . $results[$ip]['resolutions'][0]['ipOrDomain'];
                $i = 0;
                foreach ($results[$ip]['resolutions'] as $resolutions) {
                    if ($i == 0) {
                        $csv .= ',' . $resolutions['date'] . ',' . $resolutions['ipOrDomain'];
                    } else {
                        $csv .= PHP_EOL . ',,,' . $resolutions['date'] . ',' . $resolutions['ipOrDomain'];
                    }
                    $i++;
                }
            } else {
                $csv .= ',,';
            }
        }
        file_put_contents($csvFile, $csv);

        if ($remote) {
            unlink($ipsFile);
        }
    }
}

///////////////////////////////////////////////
///////////////////////////////////////////////

function getPrefix($os = null, $type = null) {
    global $rulesPrefix;
    $prefix = $rulesPrefix;
    if ($os != null) {
        $prefix .= ucfirst($os);
    }
    if ($type != null) {
        $prefix .= ucfirst($type);
    }
    return $prefix;
}

function removeRules($os = null, $type = null) {
    $prefix = getPrefix($os, $type);

    echo 'Remove rules starting with ' . $prefix;
    $objFirewall = new COM('HNetCfg.FwPolicy2');
    $objCurrentProfiles = $objFirewall->CurrentProfileTypes;
    $objRules = $objFirewall->Rules;
    foreach ($objRules as $objRule) {
        if ($objRule->Profiles == 0 || $objCurrentProfiles == 0) {
            continue;
        }
        if (startWith($objRule->Name, $prefix)) {
            echo PHP_EOL . '  ' . $objRule->Name;
            $objFirewall->Rules->Remove($objRule->Name);
        }
    }

    return true;
}

function getTestIpResult($ip) {
    global $logsPath;

    $whois = getWhois($ip, $logsPath);
    $resolutions = getResolutions($ip, $logsPath);

    return array(
        'org' => isset($whois['org']) ? $whois['org'] : null,
        'country' => isset($whois['country']) ? $whois['country'] : null,
        'resolutions' => $resolutions,
    );
}
