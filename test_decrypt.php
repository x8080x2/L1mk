<?php
require 'src/App.php';

$key = '96c426c96303f9fdc8fd6224767e4313';
$method = 'AES-256-CBC';
$ivLength = openssl_cipher_iv_length($method);

$files = glob('*.enc');

foreach ($files as $file) {
    echo "Checking $file... ";
    $content = file_get_contents($file);
    if (strlen($content) < $ivLength) {
        echo "Too short\n";
        continue;
    }

    $iv = substr($content, 0, $ivLength);
    $encrypted = substr($content, $ivLength);
    $decrypted = openssl_decrypt($encrypted, $method, $key, 0, $iv);

    if ($decrypted === false) {
        echo "FAILED\n";
    } else {
        echo "SUCCESS (" . strlen($decrypted) . " bytes)\n";
    }
}
