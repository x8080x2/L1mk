<?php
// router.php for local development
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Let PHP's built-in server handle deploy_tool directly
if (strpos($path, '/deploy_tool') === 0) {
    return false;
}

$file = dirname(__DIR__) . $path;

// Serve existing files and directories directly
if (file_exists($file)) {
    // If it's a directory, let the built-in server handle the index file lookup
    if (is_dir($file)) {
        return false;
    }
    // If it's a file, serve it
    return false;
}

// Otherwise, route through the main application
require_once dirname(__DIR__) . '/index.php';
