<?php

$dnsQueryUrl = 'https://dnsquery.org/ipwhois,request/';
$ipWhoisUrl = 'http://www.webyield.net/cgi-bin/ipwhois.cgi?addr=';

function loadConfig($path) {
    if (!file_exists($path)) {
        throw new Exception('Conf file not found in ' . $path);
    }

    $config = json_decode(file_get_contents($path), true);
    //var_dump($config);

    $configError = json_last_error();
    if ($configError > 0) {
        $configErrorStr = '  ' . basename($path) . ' error - ';
        switch ($configError) {
            case JSON_ERROR_DEPTH:
                $configErrorStr .= ' Maximum stack depth exceeded';
                break;
            case JSON_ERROR_STATE_MISMATCH:
                $configErrorStr .= ' Underflow or the modes mismatch';
                break;
            case JSON_ERROR_CTRL_CHAR:
                $configErrorStr .= ' Unexpected control character found';
                break;
            case JSON_ERROR_SYNTAX:
                $configErrorStr .= ' Syntax error, malformed JSON';
                break;
            case JSON_ERROR_UTF8:
                $configErrorStr .= ' Malformed UTF-8 characters, possibly incorrectly encoded';
                break;
            default:
                $configErrorStr .= ' Unknown error';
                break;
        }
        throw new Exception($configErrorStr);
    }

    return $config;
}

function getUrlContent($url) {
    $ch = null;
    $data = false;

    try {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        $data = curl_exec($ch);

        // validate CURL status
        if (curl_errno($ch)) {
            throw new Exception("Curl error " . curl_error($ch), 500);
        }

        // validate HTTP status code
        $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($status_code != 200) {
            throw new Exception("HTTP error " . $status_code, 500);
        }
    } catch (Exception $ex) {
        if ($ch != null) curl_close($ch);
        throw new Exception($ex);
    } finally {
        if ($ch != null) {
            curl_close($ch);
            $ch = null;
        }
    }

    return $data;
}

function download($src, $dest) {
    $rh = fopen($src, 'rb');
    $wh = fopen($dest, 'w+b');
    if (!$rh || !$wh) {
        return false;
    }

    while (!feof($rh)) {
        if (fwrite($wh, fread($rh, 4096)) === FALSE) {
            return false;
        }
        echo '.';
        flush();
    }

    fclose($rh);
    fclose($wh);
    return true;
}

function parseDnsQuery($text) {
    $result = array(
        'netName' => null,
        'organization' => null,
        'country' => null
    );

    if (empty($text) || $text === false) {
        return $result;
    }

    $lines = explode("\n", $text);
    foreach ($lines as $line) {
        $line = trim($line);

        $lineExp = explode(':', $line, 2);
        if (count($lineExp) != 2) {
            continue;
        }

        $lineKey = trim(strtoupper($lineExp[0]));
        if ($lineKey == 'NETNAME') {
            $result['netName'] = trim($lineExp[1]);
        } elseif ($lineKey == 'AUT-NUM') {
            $result['netName'] = trim($lineExp[1]);
        } elseif ($lineKey == 'ORGANIZATION') {
            $result['organization'] = trim($lineExp[1]);
        } elseif ($lineKey == 'DESCR') {
            $result['organization'] = trim($lineExp[1]);
        } elseif ($lineKey == 'OWNER') {
            $result['organization'] = trim($lineExp[1]);
        } elseif ($lineKey == 'COUNTRY') {
            $result['country'] = trim($lineExp[1]);
        }
    }

    return $result;
}

function parseIpWhois($html) {
    if (empty($html) || $html === false) {
        return null;
    }

    try {
        $dom = new DOMDocument;
        $dom->loadHTML($html);

        $p = $dom->getElementsByTagName('p');
        if (!$p instanceof DOMNodeList) {
            return null;
        }

        $content = $p[1]->textContent;
        //var_dump($content);

        $resolveTo = explode(':', $content);
        if (count($resolveTo) != 2) {
            return null;
        }

        $result = str_replace('no reverse DNS for this IP', '', trim($resolveTo[1]));
        return !empty($result) ? $result : null;
    } catch (Exception $ex) {
        echo 'Error: ' . $ex->getMessage() . PHP_EOL;
        return null;
    }
}

function getIpFromReverse($host) {
    if (preg_match('/\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/i', $host, $matches) !== 1) {
        return null;
    }
    $ip = str_replace('-', '.', $matches[0]);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return null;
    }
    return $ip;
}

function getResolvedIp($ip, $logsPath) {
    global $ipWhoisUrl;

    $resolvedIps = array();
    $resolvedFile = $logsPath . '/resolved.tmp';
    $currentTime = time();

    if (file_exists($resolvedFile)) {
        $diffTime = $currentTime - filectime($resolvedFile);
        if ($diffTime > 172800) {
            unlink($resolvedFile);
        } else {
            $handle = fopen($resolvedFile, 'r');
            if ($handle) {
                while (($line = fgets($handle)) !== false) {
                    $line = trim($line);
                    if (empty($line)) {
                        continue;
                    }
                    $lineAr = explode(' ', $line);
                    $resolvedIps[$lineAr[0]] = count($lineAr) == 2 ? $lineAr[1] : null;
                }
                fclose($handle);
            }
            if (array_key_exists($ip, $resolvedIps)) {
                return $resolvedIps[$ip];
            }
        }
    }

    $resolvedIps[$ip] = parseIpWhois(getUrlContent($ipWhoisUrl . $ip));

    uksort($resolvedIps, 'cmpIp');
    $resolvedIpsStr = '';
    foreach ($resolvedIps as $aIp => $aResolved) {
        $resolvedIpsStr .= $aIp . ' ' . $aResolved . PHP_EOL;
    }
    file_put_contents($resolvedFile, $resolvedIpsStr);

    return $resolvedIps[$ip];
}

function cmpIp($a, $b) {
    $aip = sprintf('%u', ip2long($a));
    $bip = sprintf('%u', ip2long($b));
    return $aip > $bip;
}

function sortHosts($hosts) {
    if (empty($hosts)) {
        return array();
    }

    $resultIps = array();
    $resultDomains = array();
    foreach ($hosts as $host) {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $resultIps[] = $host;
        } else {
            $resultDomains[] = $host;
        }
    }

    usort($resultIps, 'cmpIp');
    sort($resultDomains);
    return array_merge($resultIps, $resultDomains);
}

function isIpExpr($ip, $expr) {
    $ips = array();
    if (contains($expr, '-')) {
        $exprExp = explode('-', $expr);
        if (count($exprExp) != 2) {
            return false;
        }
        if (!filter_var($exprExp[0], FILTER_VALIDATE_IP) || !filter_var($exprExp[1], FILTER_VALIDATE_IP)) {
            return false;
        }
        $ips = array_merge($ips, array_map('long2ip', range(ip2long($exprExp[0]), ip2long($exprExp[1]))));
    } else if (!filter_var($expr, FILTER_VALIDATE_IP)) {
        return false;
    } else {
        $ips[] = $expr;
    }
    return in_array($ip, $ips);
}

function isHostExpr($host, $expr) {
    return preg_match('/^' . str_replace('*', '(.*?)', $expr) . '$/i', $host, $matches) === 1;
}

function contains($string, $search) {
    if (!empty($string) && !empty($search)) {
        $result = stripos($string, $search);
        if ($result !== false) {
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

function startWith($string, $search) {
    $length = strlen($search);
    return (substr($string, 0, $length) === $search);
}

function endWith($string, $search) {
    $length = strlen($search);
    $start  = $length * -1;
    return (substr($string, $start) === $search);
}

function formatWindowsPath($path) {
    return str_replace('/', '\\', $path);
}

function formatUnixPath($path) {
    return str_replace('\\', '/', $path);
}

function prompt($prompt) {
    echo $prompt;
    $handle = fopen('php://stdin', 'r');
    return trim(fgets($handle));
}
