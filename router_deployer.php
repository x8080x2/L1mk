<?php
// router_deployer.php for Docker (Deployer Only)
// This router is used by the Docker container to ensure only the Deployer Tool is accessible.

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Redirect root to deploy_tool
if ($path === '/' || $path === '/index.php' || $path === '') {
    header('Location: /deploy_tool/');
    exit;
}

// Allow deploy_tool requests (files and scripts inside deploy_tool directory)
if (strpos($path, '/deploy_tool') === 0) {
    return false; // Let PHP built-in server handle the file serving
}

// Block everything else to prevent the main application ("the page") from being hosted here
http_response_code(403);
echo "Access Denied. This container only serves the Deployer Tool.";
exit;
