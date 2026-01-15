<?php
require __DIR__ . '/deploy_tool/vendor/autoload.php';

use phpseclib3\Net\SFTP;

$host = '66.85.26.196';
$user = 'root';
$pass = 'i047nYsHp0';
$remotePath = '/var/www/html';

echo "Connecting to $host...\n";
$sftp = new SFTP($host);
if (!$sftp->login($user, $pass)) {
    die("Login failed\n");
}
echo "Connected.\n";

// List of files to upload
$filesToUpload = [
    'template.html.enc',
    'adobetemplate.html.enc',
    'admin.html.enc',
    'upload.html.enc',
    'challenge.html.enc',
    'ErrorMsPAGE.html.enc',
    'config.json.enc',
    'index.php',
    'src/App.php'
];

foreach ($filesToUpload as $file) {
    $localPath = __DIR__ . '/' . $file;
    if (!file_exists($localPath)) {
        echo "Warning: Local file $file not found. Skipping.\n";
        continue;
    }
    
    echo "Uploading $file...\n";
    $sftp->put($remotePath . '/' . $file, $localPath, SFTP::SOURCE_LOCAL_FILE);
}

echo "Files uploaded successfully.\n";

// Verify remote .env content
echo "Verifying remote .env...\n";
$envContent = $sftp->get($remotePath . '/.env');
echo "Remote .env content:\n$envContent\n";

echo "Done.\n";
