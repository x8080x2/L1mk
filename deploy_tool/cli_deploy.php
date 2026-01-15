<?php
// Wrapper to run deployment from CLI

// Load config
$diskDir = '/data/deploy_config.json';
if (is_dir($diskDir) && is_writable($diskDir)) {
    $configFile = $diskDir . '/deploy_config.json';
} else {
    $configFile = __DIR__ . '/deploy_config.json';
}
if (!file_exists($configFile)) {
    die("Config file not found.\n");
}
$config = json_decode(file_get_contents($configFile), true);

// Mock Environment for index.php
$_SERVER['REQUEST_METHOD'] = 'POST';
$_GET['action'] = 'deploy';

if (array_key_exists(0, $config)) {
    $_POST = $config[0];
} else {
    $_POST = $config;
}

$_POST['save_config'] = 'true';

$rootEnvPath = dirname(__DIR__) . '/.env';
$master = '';
if (is_file($rootEnvPath)) {
    $lines = file($rootEnvPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $trim = trim($line);
        if ($trim === '' || $trim[0] === '#') continue;
        $pos = strpos($trim, '=');
        if ($pos === false) continue;
        $k = trim(substr($trim, 0, $pos));
        $v = trim(substr($trim, $pos + 1));
        if ($k === 'MASTER_LICENSE_KEY' && $v !== '') {
            $master = $v;
            break;
        }
    }
}
if ($master !== '' && !isset($_POST['license']) && !isset($_POST['license_key'])) {
    $_POST['license_key'] = $master;
}

// Auto-encrypt admin.html if it exists
if (file_exists('admin.html')) {
    echo "Encrypting admin.html...\n";
    exec('php index.php manage encrypt admin.html');
}

// Capture output
ob_start();
require __DIR__ . '/index.php';
$output = ob_get_clean();

// Process SSE output for readability
$lines = explode("\n", $output);
foreach ($lines as $line) {
    if (strpos($line, 'data: ') === 0) {
        $json = substr($line, 6);
        $data = json_decode($json, true);
        if ($data && isset($data['message'])) {
            $prefix = isset($data['type']) && $data['type'] === 'error' ? '[ERROR] ' : '[INFO] ';
            echo $prefix . $data['message'] . "\n";
        }
    } else {
        // Echo non-SSE output (debugging or errors)
        if (trim($line) !== '') echo $line . "\n";
    }
}
