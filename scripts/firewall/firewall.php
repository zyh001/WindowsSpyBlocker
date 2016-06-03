<?php

include realpath('..') . '/.bin/util.php';

$currentPath = formatUnixPath(realpath(''));
$basePath = formatUnixPath(realpath('../..'));
$dataPath = $basePath . '/data/firewall';
$logsPath = $basePath . '/logs';
$rulesPrefix = 'windowsSpyBlocker';

try {
    $config = loadConfig($currentPath . '/firewall.conf');
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

function processTestIps() {
    global $argv, $currentPath, $basePath, $dataPath, $logsPath, $config, $dnsQueryUrl, $ipWhoisUrl;

    if (count($argv) != 3) {
        throw new Exception('Missing args');
    }

    $remoteIps = true;
    $ipsFiles = array();
    if ($argv[2] == 'local') {
        $remoteIps = false;
        foreach ($config['rules']['local'] as $name => $path) {
            $ipsFiles[$name] = $basePath . $path;
            if (!file_exists($ipsFiles[$name])) {
                throw new Exception('Rule file not found in ' . ipsFiles[$name]);
            }
        }
    } else {
        echo PHP_EOL;
        foreach ($config['rules']['remote'] as $name => $url) {
            $ipsFiles[$name] = $logsPath . '/' . preg_replace('/\..+$/', '.tmp', basename($url));
            echo 'Download ' . basename($url) . '.';
            if (download($url, $ipsFiles[$name])) {
                echo ' OK' . PHP_EOL;
            } else {
                throw new Exception('Download failed');
            }
            if (!file_exists(ipsFiles[$name])) {
                throw new Exception('Rule file not found in ' . ipsFiles[$name]);
            }
        }
    }

    foreach ($ipsFiles as $name => $ipsFile) {
        $ips = array();
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
                    //$ips[] = $line;
                } else if (!filter_var($line, FILTER_VALIDATE_IP)) {
                    continue;
                } else {
                    $ips[] = $line;
                }
            }
            fclose($handle);
        }

        $results = array();
        echo PHP_EOL . 'Process ' . $name . ' (' . count($ips) . ' IPs)' . PHP_EOL;
        foreach ($ips as $ip) {
            echo 'Checking ' . $ip . '...' . PHP_EOL;
            if (contains($ip, '-')) {
                $ipRangeAr = explode('-', $ip);
                $ipsRange = array_map('long2ip', range(ip2long($ipRangeAr[0]), ip2long($ipRangeAr[1])));

                $dnsQueryContents = getMultiUrlContent($dnsQueryUrl, $ipsRange);
                $ipWhoisContents = getMultiUrlContent($ipWhoisUrl, $ipsRange);
                foreach ($ipsRange as $ipRange) {
                    $results[$ipRange] = getTestIpsResult($dnsQueryContents[$ipRange], $ipWhoisContents[$ipRange]);
                }
            } else {
                $dnsQueryContent = getUrlContent($dnsQueryUrl . $ip);
                $ipWhoisContent = getUrlContent($ipWhoisUrl . $ip);
                $results[$ip] = getTestIpsResult($dnsQueryContent, $ipWhoisContent);

                echo '  NetName: ' . $results[$ip]['netName'] . PHP_EOL;
                echo '  Organization: ' . $results[$ip]['organization'] . PHP_EOL;
                echo '  Country: ' . $results[$ip]['country'] . PHP_EOL;
                echo '  Resolves to: ' . $results[$ip]['resolveTo'] . PHP_EOL;
            }
        }

        echo 'Write firewall-test-' . $name . '.csv...'. PHP_EOL;
        $csv = 'IP,NETNAME,ORGANIZATION,COUNTRY,DNS RESOLVE';
        foreach ($results as $ip => $result) {
            $csv .= PHP_EOL . $ip .
                ',' . str_replace(',', '.', $result['netName']) .
                ',' . str_replace(',', '.', $result['organization']) .
                ',' . str_replace(',', '.', $result['country']) .
                ',' . str_replace(',', '.', $result['resolveTo']);
        }
        file_put_contents($logsPath . '/firewall-test-' . $name . '.csv', $csv);

        if ($remoteIps) {
            unlink($ipsFile);
        }
    }
}

function processAddRules() {
    global $argv, $basePath, $dataPath, $config;

    if (count($argv) != 4) {
        throw new Exception('Missing args');
    }

    $rule = $argv[2];
    $ruleExp = explode('_', $rule, 2);
    $rulePath = null;
    $remote = $argv[3] == 'remote';

    if ($argv[3] == 'local') {
        if (!isset($config['rules']['local'][$rule])) {
            throw new Exception('Unknown rule ' . $rule);
        }
        $rulePath = $basePath . '/' . $config['rules']['local'][$rule];
        if (!file_exists($rulePath)) {
            throw new Exception('Rule file not found in ' . $rulePath);
        }
    } elseif ($argv[3] == 'remote') {
        if (!isset($config['rules']['remote'][$rule])) {
            throw new Exception('Unknown rule ' . $rule);
        }
        $ruleUrl = $config['rules']['remote'][$rule];
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
    } else {
        throw new Exception('Unknown type ' . $argv[3]);
    }

    // Remove rules
    removeRules($ruleExp[0], $ruleExp[1]);

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
        echo PHP_EOL . 'WARNING: No IPs found';
        return;
    }

    echo PHP_EOL . 'Add ' . count($ips) . ' rules...';
    $prefix = getPrefix($ruleExp[0], $ruleExp[1]);
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

function processRemoveRules() {
    removeRules();
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

function getTestIpsResult($dnsQuery, $ipWhois) {
    $dnsQuery = parseDnsQuery($dnsQuery);
    $ipWhois = parseIpWhois($ipWhois);

    return array(
        'netName' => $dnsQuery['netName'],
        'organization' => $dnsQuery['organization'],
        'country' => $dnsQuery['country'],
        'resolveTo' => $ipWhois,
    );
}

function getMultiUrlContent($baseUrl, $ips) {
    $curly = array();
    $data = array();
    $mh = curl_multi_init();
    foreach ($ips as $ip) {
        $curly[$ip] = curl_init();
        curl_setopt_array($curly[$ip], array(
            CURLOPT_URL => $baseUrl . $ip,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_TIMEOUT => 30
        ));
        curl_multi_add_handle($mh, $curly[$ip]);
    }

    $running = null;
    do {
        curl_multi_exec($mh, $running);
    } while ($running > 0);

    foreach($curly as $ip => $c) {
        $data[$ip] = curl_multi_getcontent($c);
        curl_multi_remove_handle($mh, $c);
    }

    curl_multi_close($mh);
    return $data;
}
