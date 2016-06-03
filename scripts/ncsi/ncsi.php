<?php

include realpath('..') . '/.bin/util.php';

$currentPath = formatUnixPath(realpath(''));
$basePath = formatUnixPath(realpath('../..'));
$dataPath = $basePath . '/data/ncsi';
$logsPath = $basePath . '/logs';

try {
    $config = loadConfig($currentPath . '/ncsi.conf');
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

function processApplyNcsi() {
    global $argv, $basePath, $dataPath, $config;

    if (count($argv) != 4) {
        throw new Exception('Missing args');
    }

    $reg = $argv[2];
    $regPath = null;
    $remote = $argv[3] == 'remote';

    if ($argv[3] == 'local') {
        if (!isset($config['regs']['local'][$reg])) {
            throw new Exception('Unknown reg ' . $reg);
        }
        $regPath = $basePath . '/' . $config['regs']['local'][$reg];
        if (!file_exists($regPath)) {
            throw new Exception('Reg file not found in ' . $regPath);
        }
    } elseif ($argv[3] == 'remote') {
        if (!isset($config['regs']['remote'][$reg])) {
            throw new Exception('Unknown reg ' . $reg);
        }
        $regUrl = $config['regs']['remote'][$reg];
        $regPath = $dataPath . '/' . preg_replace('/\..+$/', '.tmp', basename($regUrl));
        echo 'Download ' . basename($regUrl) . '.';
        if (download($regUrl, $regPath)) {
            echo ' OK' . PHP_EOL;
        } else {
            throw new Exception('Download failed');
        }
        if (!file_exists($regPath)) {
            throw new Exception('Reg file not found in ' . $regPath);
        }
    } else {
        throw new Exception('Unknown type ' . $argv[3]);
    }

    // Apply NCSI
    echo 'Applying ' . $regPath;
    exec('regedit /s "' . $regPath . '"', $cmdOutput, $cmdReturn);
    $cmdOutputStr = implode(PHP_EOL, $cmdOutput);
    if ($remote) {
        unlink($regPath);
    }
    if ($cmdReturn != 0) {
        throw new Exception($cmdOutputStr);
    }
}
