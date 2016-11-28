<?php

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

function getWhois($ipOrDomain, $logsPath) {
    $res = array();
    $resFile = $logsPath . '/whois.tmp';
    $cacheTime = 172800;
    $currentTime = time();
    $isIp = filter_var($ipOrDomain, FILTER_VALIDATE_IP);

    if (file_exists($resFile)) {
        $diffTime = $currentTime - filectime($resFile);
        if ($diffTime > $cacheTime) {
            unlink($resFile);
        } else {
            $handle = fopen($resFile, 'r');
            if ($handle) {
                while (($line = fgets($handle)) !== false) {
                    $line = trim($line);
                    if (empty($line)) {
                        continue;
                    }
                    $lineAr = explode(' ', $line, 2);
                    $res[$lineAr[0]] = count($lineAr) == 2 ? $lineAr[1] : null;
                }
                fclose($handle);
            }
            if (array_key_exists($ipOrDomain, $res)) {
                return json_decode($res[$ipOrDomain], true);
            }
        }
    } else {
        touch($resFile);
    }

    $whoisRes = null;
    if ($isIp) {
        // IpInfo
        $tmp = parseIpInfo($ipOrDomain);
        if (!isset($tmp['org']) || empty($tmp['org'])) {
            // DnsQuery
            $tmp = parseDnsQuery($ipOrDomain);
            if (!isset($tmp['org']) || empty($tmp['org'])) {
                // WhoisXmlApi
                // FIXME: WhoisXmlApi limited to 50 requests per IP
                $tmp = parseWhoisXmlApi($ipOrDomain);
                if (isset($tmp['org']) && !empty($tmp['org'])) {
                    $whoisRes = array(
                        'src' => 'WhoisXmlApi',
                        'org' => str_replace(',', '.', $tmp['org']),
                        'country' => $tmp['country']
                    );
                }
            } else {
                $whoisRes = array(
                    'src' => 'DnsQuery',
                    'org' => str_replace(',', '.', $tmp['org']),
                    'country' => $tmp['country']
                );
            }
        } else {
            $whoisRes = array(
                'src' => 'IpInfo',
                'org' => str_replace(',', '.', $tmp['org']),
                'country' => $tmp['country']
            );
        }
    } else {
        // DnsQuery
        $tmp = parseDnsQuery($ipOrDomain);
        if (!isset($tmp['org']) || empty($tmp['org'])) {
            // WhoisXmlApi
            // FIXME: WhoisXmlApi limited to 50 requests per IP
            $tmp = parseWhoisXmlApi($ipOrDomain);
            if (isset($tmp['org']) && !empty($tmp['org'])) {
                $whoisRes = array(
                    'src' => 'WhoisXmlApi',
                    'org' => str_replace(',', '.', $tmp['org']),
                    'country' => $tmp['country']
                );
            }
        } else {
            $whoisRes = array(
                'src' => 'DnsQuery',
                'org' => str_replace(',', '.', $tmp['org']),
                'country' => $tmp['country']
            );
        }
    }

    if (!empty($whoisRes)) {
        $res[$ipOrDomain] = json_encode($whoisRes);
    } else {
        $res[$ipOrDomain] = null;
    }

    $res = sortHostsByKey($res);
    $resStr = '';
    foreach ($res as $aIpOrDomain => $json) {
        $resStr .= $aIpOrDomain . ' ' . $json . PHP_EOL;
    }
    file_put_contents($resFile, $resStr);

    return json_decode($res[$ipOrDomain], true);
}

function parseDnsQuery($ipOrDomain) {
    $result = null;
    if (empty($ipOrDomain)) {
        return $result;
    }

    $url = 'https://dnsquery.org/ipwhois,request/' . $ipOrDomain;
    $content = getUrlContent($url);
    if (empty($content) || $content === false) {
        return $result;
    }

    if (preg_match('/\sresolving\sto(.*?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"/i', $content, $matches) === 1) {
        if (isset($matches[2])) {
            return parseDnsQuery($matches[2]);
        }
    }

    $result['ip'] = $ipOrDomain;
    $lines = explode("\n", $content);
    foreach ($lines as $line) {
        $line = trim($line);

        $lineExp = explode(':', $line, 2);
        if (count($lineExp) != 2) {
            continue;
        }

        $lineKey = trim(strtoupper($lineExp[0]));
        if ($lineKey == 'NAME') {
            $result['org'] = trim($lineExp[1]);
        } elseif (!isset($result['org']) && $lineKey == 'ORGANIZATION') {
            $result['org'] = trim($lineExp[1]);
        } elseif (!isset($result['org']) && $lineKey == 'DESCR') {
            $result['org'] = trim($lineExp[1]);
        } elseif (!isset($result['org']) && $lineKey == 'OWNER') {
            $result['org'] = trim($lineExp[1]);
        } elseif ($lineKey == 'COUNTRY') {
            $result['country'] = trim($lineExp[1]);
        }
    }

    return $result;
}

function parseWhoisXmlApi($ipOrDomain) {
    $result = null;
    if (empty($ip)) {
        return $result;
    }

    $url = 'http://www.whoisxmlapi.com/whoisserver/WhoisService?outputFormat=JSON&domainName=' . $ipOrDomain;
    $content = getUrlContent($url);
    if (empty($content) || $content === false) {
        return $result;
    }

    $jsonDec = json_decode($content, true);
    $jsonError = json_last_error();
    if ($jsonError > 0) {
        $jsonErrorStr = '  WhoisXmlApi json error - ';
        switch ($jsonError) {
            case JSON_ERROR_DEPTH:
                $jsonErrorStr .= ' Maximum stack depth exceeded';
                break;
            case JSON_ERROR_STATE_MISMATCH:
                $jsonErrorStr .= ' Underflow or the modes mismatch';
                break;
            case JSON_ERROR_CTRL_CHAR:
                $jsonErrorStr .= ' Unexpected control character found';
                break;
            case JSON_ERROR_SYNTAX:
                $jsonErrorStr .= ' Syntax error, malformed JSON';
                break;
            case JSON_ERROR_UTF8:
                $jsonErrorStr .= ' Malformed UTF-8 characters, possibly incorrectly encoded';
                break;
            default:
                $jsonErrorStr .= ' Unknown error';
                break;
        }
        throw new Exception($jsonErrorStr);
    }

    if (isset($jsonDec['ErrorMessage']) || !isset($jsonDec['WhoisRecord']) || !isset($jsonDec['WhoisRecord']['registrant'])) {
        return $result;
    }

    $org = $jsonDec['WhoisRecord']['registrant']['organization'];
    if (isset($jsonDec['WhoisRecord']['registrant']['name'])) {
        $org = $jsonDec['WhoisRecord']['registrant']['name'];
    }

    return array(
        'org' => $org,
        'country' => $jsonDec['WhoisRecord']['registrant']['country']
    );
}

function getResolutions($ipOrDomain, $logsPath) {
    $res = array();
    $resFile = $logsPath . '/resolutions.tmp';
    $cacheTime = 172800;
    $currentTime = time();

    if (file_exists($resFile)) {
        $diffTime = $currentTime - filectime($resFile);
        if ($diffTime > $cacheTime) {
            unlink($resFile);
        } else {
            $handle = fopen($resFile, 'r');
            if ($handle) {
                while (($line = fgets($handle)) !== false) {
                    $line = trim($line);
                    if (empty($line)) {
                        continue;
                    }
                    $lineAr = explode(' ', $line, 2);
                    $res[$lineAr[0]] = count($lineAr) == 2 ? $lineAr[1] : null;
                }
                fclose($handle);
            }
            if (array_key_exists($ipOrDomain, $res)) {
                return json_decode($res[$ipOrDomain], true);
            }
        }
    } else {
        touch($resFile);
    }

    $resolutionsRes = array();
    if (filter_var($ipOrDomain, FILTER_VALIDATE_IP)) {
        // IpInfo
        $tmp = parseIpInfo($ipOrDomain);
        if (!isset($tmp['hostname']) || empty($tmp['hostname'])) {
            // WebYield Resolve IP
            $tmp = parseWebYieldResolveIp($ipOrDomain);
            if (!empty($tmp)) {
                $tmp = array(
                    'src' => 'WebYield',
                    'date' => null,
                    'ipOrDomain' => $tmp
                );
            }
        } else {
            $tmp = array(
                'src' => 'IpInfo',
                'date' => null,
                'ipOrDomain' => $tmp['hostname']
            );
        }

        if (!empty($tmp)) {
            $resolutionsRes[] = $tmp;
        }

        $tcRes = parseThreatCrowd($ipOrDomain);
        if (!empty($tcRes)) {
            foreach ($tcRes as $resIpOrDomain => $resDate) {
                if (isset($tmp['ipOrDomain']) && $tmp['ipOrDomain'] == $resIpOrDomain) {
                    continue;
                }
                $resolutionsRes[] = array(
                    'src' => 'ThreatCrowd',
                    'date' => $resDate,
                    'ipOrDomain' => $resIpOrDomain
                );
            }
        }
    } else {
        // DnsQuery
        $tmp = parseDnsQuery($ipOrDomain);
        if (isset($tmp['ip']) && !empty($tmp['ip'])) {
            $tmp = array(
                'src' => 'DnsQuery',
                'date' => null,
                'ipOrDomain' => $tmp['ip']
            );
        }

        if (!empty($tmp)) {
            $resolutionsRes[] = $tmp;
        }

        $tcRes = parseThreatCrowd($ipOrDomain);
        if (!empty($tcRes)) {
            foreach ($tcRes as $resIpOrDomain => $resDate) {
                if (isset($tmp['ipOrDomain']) && $tmp['ipOrDomain'] == $resIpOrDomain) {
                    continue;
                }
                $resolutionsRes[] = array(
                    'src' => 'ThreatCrowd',
                    'date' => $resDate,
                    'ipOrDomain' => $resIpOrDomain
                );
            }
        }
    }

    if (!empty($resolutionsRes)) {
        $res[$ipOrDomain] = json_encode($resolutionsRes);
    } else {
        $res[$ipOrDomain] = null;
    }

    $res = sortHostsByKey($res);
    $resStr = '';
    foreach ($res as $aIpOrDomain => $json) {
        $resStr .= $aIpOrDomain . ' ' . $json . PHP_EOL;
    }
    file_put_contents($resFile, $resStr);

    return json_decode($res[$ipOrDomain], true);
}

function parseIpInfo($ip) {
    $result = null;
    if (empty($ip)) {
        return $result;
    }

    $url = 'http://ipinfo.io/' . $ip . '/json';
    $content = getUrlContent($url);
    if (empty($content) || $content === false) {
        return $result;
    }

    $jsonDec = json_decode($content, true);
    $jsonError = json_last_error();
    if ($jsonError > 0) {
        $jsonErrorStr = '  IpInfo json error - ';
        switch ($jsonError) {
            case JSON_ERROR_DEPTH:
                $jsonErrorStr .= ' Maximum stack depth exceeded';
                break;
            case JSON_ERROR_STATE_MISMATCH:
                $jsonErrorStr .= ' Underflow or the modes mismatch';
                break;
            case JSON_ERROR_CTRL_CHAR:
                $jsonErrorStr .= ' Unexpected control character found';
                break;
            case JSON_ERROR_SYNTAX:
                $jsonErrorStr .= ' Syntax error, malformed JSON';
                break;
            case JSON_ERROR_UTF8:
                $jsonErrorStr .= ' Malformed UTF-8 characters, possibly incorrectly encoded';
                break;
            default:
                $jsonErrorStr .= ' Unknown error';
                break;
        }
        throw new Exception($jsonErrorStr);
    }

    if (!isset($jsonDec['ip'])) {
        return $result;
    }

    return array(
        'hostname' => isset($jsonDec['hostname']) && $jsonDec['hostname'] != 'No Hostname' ? $jsonDec['hostname'] : null,
        'country' => isset($jsonDec['country']) ? $jsonDec['country'] : null,
        'org' => isset($jsonDec['org']) ? $jsonDec['org'] : null,
    );
}

function parseWebYieldResolveIp($ip) {
    $result = null;
    if (empty($ip)) {
        return $result;
    }

    $url = 'http://www.webyield.net/cgi-bin/ipwhois.cgi?addr=' . $ip;
    $content = getUrlContent($url);
    if (empty($content) || $content === false) {
        return $result;
    }

    try {
        $dom = new DOMDocument;
        $dom->loadHTML($content);

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
        return null;
    }
}

function parseThreatCrowd($ipOrDomain) {
    $result = null;
    if (empty($ipOrDomain)) {
        return $result;
    }

    $isIp = filter_var($ipOrDomain, FILTER_VALIDATE_IP);

    $url = 'https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=' . $ipOrDomain;
    if (!$isIp) {
        $url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=' . $ipOrDomain;
    }

    $content = getUrlContent($url);
    if (empty($content) || $content === false) {
        return $result;
    }

    $jsonDec = json_decode($content, true);
    $jsonError = json_last_error();
    if ($jsonError > 0) {
        $jsonErrorStr = '  ThreatCrowd json error - ';
        switch ($jsonError) {
            case JSON_ERROR_DEPTH:
                $jsonErrorStr .= ' Maximum stack depth exceeded';
                break;
            case JSON_ERROR_STATE_MISMATCH:
                $jsonErrorStr .= ' Underflow or the modes mismatch';
                break;
            case JSON_ERROR_CTRL_CHAR:
                $jsonErrorStr .= ' Unexpected control character found';
                break;
            case JSON_ERROR_SYNTAX:
                $jsonErrorStr .= ' Syntax error, malformed JSON';
                break;
            case JSON_ERROR_UTF8:
                $jsonErrorStr .= ' Malformed UTF-8 characters, possibly incorrectly encoded';
                break;
            default:
                $jsonErrorStr .= ' Unknown error';
                break;
        }
        throw new Exception($jsonErrorStr);
    }

    if (intval($jsonDec['response_code']) != 1) {
        return $result;
    }

    foreach ($jsonDec['resolutions'] as $resolutions) {
        $key = !$isIp ? $resolutions['ip_address'] : $resolutions['domain'];
        if ($key == '-') {
            continue;
        }
        $result[$key] = $resolutions['last_resolved'];
    }
    if (is_array($result)) {
        arsort($result);
    }

    return $result;
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

function sortHostsByKey($hosts) {
    if (empty($hosts)) {
        return array();
    }

    $resultIps = array();
    $resultDomains = array();
    foreach ($hosts as $host => $value) {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $resultIps[$host] = $value;
        } else {
            $resultDomains[$host] = $value;
        }
    }

    uksort($resultIps, 'cmpIp');
    ksort($resultDomains);
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
    $preg = preg_match('/^' . str_replace('*', '(.*?)', $expr) . '$/i', $host, $matches);
    return $preg === 1;
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
