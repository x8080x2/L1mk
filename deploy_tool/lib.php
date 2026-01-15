<?php

use phpseclib3\Net\SSH2;

function parse_deploy_request($post) {
    $main_domain = normalize_domain($post['main_domain'] ?? ($post['domain'] ?? ''));
    $domains = normalize_domains_list($post['domains'] ?? []);
    $domains = array_values(array_filter($domains, fn($d) => $d !== '' && $d !== $main_domain));

    return [
        'action' => $_GET['action'] ?? '',
        'host' => $post['host'] ?? '',
        'user' => $post['user'] ?? 'root',
        'password' => $post['password'] ?? '',
        'port' => intval($post['port'] ?? 22),
        'path' => $post['path'] ?? '/var/www/html',
        'main_domain' => $main_domain,
        'domains' => $domains,
        'rotation_enabled' => isset($post['rotation_enabled']) && (string)$post['rotation_enabled'] === '1',
        'wildcard_enabled' => isset($post['wildcard_enabled']) && (string)$post['wildcard_enabled'] === '1',
        // Default to current directory's parent if not specified, but this should be provided by input
        'local_path' => $post['local_path'] ?? '',
        'server_id' => $post['server_id'] ?? null
    ];
}

function normalize_domain($domain) {
    $domain = strtolower(trim((string)$domain));
    if ($domain === '') return '';
    $domain = preg_replace('#^https?://#', '', $domain);
    $domain = preg_replace('#/.*$#', '', $domain);
    $domain = rtrim($domain, '.');
    if ($domain === '') return '';
    if (!preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/', $domain)) return '';
    return $domain;
}

function normalize_domains_list($input) {
    if (is_array($input)) {
        $raw = implode("\n", array_map('strval', $input));
    } else {
        $raw = (string)$input;
    }

    $parts = preg_split('/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY);
    $domains = [];
    foreach ($parts as $part) {
        $d = normalize_domain($part);
        if ($d === '') continue;
        $domains[$d] = true;
    }
    return array_values(array_keys($domains));
}

function domain_variants($domain) {
    $domain = normalize_domain($domain);
    if ($domain === '') return [];
    if (str_starts_with($domain, 'www.')) {
        $root = normalize_domain(substr($domain, 4));
        $out = [$domain];
        if ($root !== '') $out[] = $root;
        return array_values(array_unique($out));
    }
    return [$domain, "www.$domain"];
}

function nginx_config_key($mainDomain) {
    $key = $mainDomain !== '' ? $mainDomain : 'default_app';
    return preg_replace('/[^a-zA-Z0-9._-]/', '_', $key);
}

function ssh_connect($host, $port, $user, $password) {
    $ssh = new SSH2($host, $port);
    if (!$ssh->login($user, $password)) {
        throw new Exception('Login failed.');
    }
    $sudo = ($user === 'root') ? '' : 'sudo ';
    return [$ssh, $sudo];
}

function ssh_reconnect($ssh, $host, $port, $user, $password) {
    if (is_object($ssh) && method_exists($ssh, 'disconnect')) $ssh->disconnect();
    $ssh = new SSH2($host, $port);
    if (!$ssh->login($user, $password)) {
        throw new Exception('Relogin failed.');
    }
    return $ssh;
}

function sse_start($label, $host) {
    sse_message("🚀 Starting $label to $host...");
    sse_message("🔍 Performing pre-flight checks...");
}

function sse_finish($signal, $modeLabel = null) {
    if ($modeLabel) {
        sse_message("✅ $modeLabel Finished Successfully!", 'success');
    }
    sse_message($signal);
}

function write_nginx($ssh, $sudo, $configKey, $nginxConfig) {
    $ssh->exec("echo " . escapeshellarg($nginxConfig) . " > /tmp/nginx_conf");
    $configFileRemote = "/etc/nginx/sites-available/" . $configKey;
    $linkFile = "/etc/nginx/sites-enabled/" . $configKey;
    $ssh->exec("$sudo mv /tmp/nginx_conf $configFileRemote");
    $ssh->exec("$sudo ln -sf $configFileRemote $linkFile");
    $testOut = (string)$ssh->exec("$sudo nginx -t 2>&1");
    sse_message(trim($testOut));
    $ssh->exec("$sudo systemctl reload nginx 2>&1");
}

function get_php_sock($ssh) {
    $sock = trim((string)$ssh->exec("find /var/run/php -name 'php*-fpm.sock' | head -n 1"));
    if ($sock === '') $sock = '/var/run/php/php-fpm.sock';
    return $sock;
}

function generate_random_string($length = 20) {
    $alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
    $str = '';
    for ($i = 0; $i < $length; $i++) {
        $str .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    return $str;
}

function generate_slugs($count = 1, $length = 5) {
    $out = [];
    for ($i = 0; $i < $count; $i++) {
        $out[generate_random_string($length)] = true;
    }
    return array_values(array_keys($out));
}

function nginx_server_block($serverNames, $rootPath, $useLetsEncrypt = false, $mainDomainForCerts = '') {
    $serverNames = array_values(array_filter($serverNames, fn($v) => trim((string)$v) !== ''));
    $serverNames = array_values(array_unique($serverNames));
    $serverNameLine = implode(' ', $serverNames);

    $sslConfig = <<<SSL
    ssl_certificate /etc/nginx/ssl/selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/selfsigned.key;
SSL;

    if ($useLetsEncrypt && $mainDomainForCerts !== '') {
        $sslConfig = <<<SSL
    ssl_certificate /etc/letsencrypt/live/$mainDomainForCerts/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$mainDomainForCerts/privkey.pem;
SSL;
    }

    return <<<NGINX
server {
    listen 80;
    listen 443 ssl;
    server_name $serverNameLine;
    root $rootPath;

    $sslConfig
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    index index.php index.html index.htm;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock; 
    }

    location ~ /\.ht {
        deny all;
    }
}
NGINX;
}

function nginx_rotation_config($mainDomain, $additionalDomains, $rootPath, $wildcardEnabled = false, $rotationPath = '', $rotationSlugs = [], $useLetsEncrypt = false) {
    $mainDomain = normalize_domain($mainDomain);
    $additionalDomains = array_values(array_filter(array_map('normalize_domain', $additionalDomains)));
    $additionalDomains = array_values(array_filter($additionalDomains, fn($d) => $d !== '' && $d !== $mainDomain));
    $additionalDomains = array_values(array_unique($additionalDomains));

    if ($mainDomain === '' || count($additionalDomains) === 0) {
        $serverNames = $mainDomain !== '' ? domain_variants($mainDomain) : ['_'];
        if ($wildcardEnabled && $mainDomain !== '') {
            $serverNames[] = '*.' . $mainDomain;
        }
        return nginx_server_block($serverNames, $rootPath, $useLetsEncrypt, $mainDomain);
    }

    $n = count($additionalDomains);
    $weight = $n > 0 ? intdiv(100, $n) : 0;
    if ($weight < 1) $weight = 1;

    $split = "split_clients \"\$request_uri\" \$rotation_target {\n";
    for ($i = 0; $i < $n - 1; $i++) {
        $split .= "    {$weight}% {$additionalDomains[$i]};\n";
    }
    $split .= "    * {$additionalDomains[$n - 1]};\n";
    $split .= "}\n\n";

    $mainVariants = domain_variants($mainDomain);
    if ($wildcardEnabled) {
        $mainVariants[] = '*.' . $mainDomain;
    }
    $mainServerName = implode(' ', $mainVariants);

    $sslConfig = <<<SSL
    ssl_certificate /etc/nginx/ssl/selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/selfsigned.key;
SSL;

    if ($useLetsEncrypt) {
        $sslConfig = <<<SSL
    ssl_certificate /etc/letsencrypt/live/$mainDomain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$mainDomain/privkey.pem;
SSL;
    }

    // Rotation Logic:
    // If rotationPath is set, we only rotate requests matching that path.
    // Otherwise (legacy), we rotate everything at root.
    
    $locations = "";
    if (!empty($rotationPath)) {
        $safePath = preg_quote($rotationPath, '/');
        // Specific rotation block
        $locations .= <<<NGINX
    location ~ ^/$safePath/ {
        return 302 \$scheme://\$rotation_target\$request_uri;
    }

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
NGINX;
    } else {
        // Legacy: Rotate everything
        $locations .= <<<NGINX
    location / {
        return 302 \$scheme://\$rotation_target\$request_uri;
    }
NGINX;
    }

    $mainServer = <<<NGINX
server {
    listen 80;
    listen 443 ssl;
    server_name $mainServerName;
    root $rootPath;

    $sslConfig
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    index index.php index.html index.htm;

    location ^~ /.well-known/acme-challenge/ {
        try_files \$uri =404;
    }

    location = /admin.html {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location = /api {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location = /api.php {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

$locations

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock; 
    }

    location ~ /\.ht {
        deny all;
    }
}
NGINX;

    $servers = [$split, $mainServer];
    foreach ($additionalDomains as $d) {
        // Additional domains can use the same cert if they are on it (SAN), but for now we fallback to self-signed or use main if it's wildcard?
        // Actually, Certbot usually handles them separately or as SAN. 
        // If we want to support SAN, we should use the main cert for all?
        // For simplicity, let's assume additional domains might not be on the main cert unless it's a SAN cert.
        // But if the user ran Certbot for ALL domains (which they did in the log), they are all on the cert.
        // So we can use the main domain's cert path for ALL server blocks if $useLetsEncrypt is true.
        $servers[] = nginx_server_block(domain_variants($d), $rootPath, $useLetsEncrypt, $mainDomain);
    }
    return implode("\n\n", $servers);
}

function remove_nginx_config($ssh, $sudo, $configKey) {
    $ssh->exec("$sudo rm /etc/nginx/sites-enabled/$configKey 2>/dev/null || true");
    $ssh->exec("$sudo rm /etc/nginx/sites-available/$configKey 2>/dev/null || true");
    $testOut = (string)$ssh->exec("$sudo nginx -t 2>&1");
    sse_message(trim($testOut));
    $ssh->exec("$sudo systemctl reload nginx 2>&1");
}

function get_nginx_config_multi($mainDomain, $additionalDomains, $rootPath, $rotationEnabled, $wildcardEnabled = false, $rotationPath = '', $rotationSlugs = [], $useLetsEncrypt = false) {

    $mainDomain = normalize_domain($mainDomain);
    $additionalDomains = array_values(array_filter(array_map('normalize_domain', $additionalDomains)));
    $additionalDomains = array_values(array_filter(array_unique($additionalDomains), fn($d) => $d !== '' && $d !== $mainDomain));

    if ($rotationEnabled && $mainDomain !== '' && count($additionalDomains) > 0) {
        return nginx_rotation_config($mainDomain, $additionalDomains, $rootPath, $wildcardEnabled, $rotationPath, $rotationSlugs, $useLetsEncrypt);
    }

    $serverNames = [];
    if ($mainDomain !== '') {
        $serverNames = array_merge($serverNames, domain_variants($mainDomain));
        if ($wildcardEnabled) {
            $serverNames[] = '*.' . $mainDomain;
        }
    } else {
        $serverNames[] = '_';
    }

    foreach ($additionalDomains as $d) {
        $serverNames = array_merge($serverNames, domain_variants($d));
    }

    return nginx_server_block($serverNames, $rootPath, $useLetsEncrypt, $mainDomain);
}

function zip_project($sourceDir, $zipPath) {
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
        return false;
    }

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    foreach ($files as $name => $file) {
        if ($file->isDir()) continue;

        $filePath = $file->getRealPath();
        $relativePath = substr($filePath, strlen($sourceDir) + 1);

        if (!is_file_needed($relativePath)) continue;

        $zip->addFile($filePath, $relativePath);
    }

    return $zip->close();
}

function zip_project_page($sourceDir, $zipPath) {
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
        return false;
    }

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    foreach ($files as $name => $file) {
        if ($file->isDir()) continue;

        $filePath = $file->getRealPath();
        $relativePath = substr($filePath, strlen($sourceDir) + 1);

        if (!is_file_needed_page($relativePath)) continue;

        $zip->addFile($filePath, $relativePath);
    }

    return $zip->close();
}

function is_file_needed($relativePath) {
    // 1. Critical Directories to Exclude
    if (strpos($relativePath, 'deploy_tool/') === 0) return false; // Prevent deploying the deploy_tool itself
    // if (strpos($relativePath, 'vendor/') === 0) return false; // Keep vendor for now if not using composer on server (but script installs it)
    if (strpos($relativePath, 'node_modules/') === 0) return false;
    if (strpos($relativePath, '.git/') === 0) return false;
    if (strpos($relativePath, '.idea/') === 0) return false;
    if (strpos($relativePath, '.vscode/') === 0) return false;
    if (strpos($relativePath, 'tests/') === 0) return false;
    if (strpos($relativePath, 'docs/') === 0) return false;
    if (strpos($relativePath, 'session_data/') === 0) return false;
    if (strpos($relativePath, 'storage/logs/') === 0) return false;

    // 2. Critical Files to Exclude
    if (strpos($relativePath, 'deploy_tool/deploy_package.zip') !== false) return false;
    if (strpos($relativePath, 'database.sqlite') !== false) return false;
    if ($relativePath === 'config.json.enc') return false;
    if ($relativePath === 'config.json') return false;
    // if ($relativePath === '.env') return false; // Allow .env for deployment
    if ($relativePath === '.DS_Store') return false;
    if (strpos($relativePath, '.log') !== false) return false;
    if (strpos($relativePath, '.lock') !== false && $relativePath !== 'composer.lock' && $relativePath !== 'package-lock.json') return false;

    // 3. Known Essential Extensions/Files (Implicitly Included by passing above checks)
    return true;
}

function is_file_needed_page($relativePath) {
    if (strpos($relativePath, 'deploy_tool/') === 0) return false;
    if (strpos($relativePath, 'node_modules/') === 0) return false;
    if (strpos($relativePath, '.git/') === 0) return false;
    if (strpos($relativePath, '.idea/') === 0) return false;
    if (strpos($relativePath, '.vscode/') === 0) return false;
    if (strpos($relativePath, 'tests/') === 0) return false;
    if (strpos($relativePath, 'docs/') === 0) return false;
    if (strpos($relativePath, 'session_data/') === 0) return false;
    if (strpos($relativePath, 'storage/logs/') === 0) return false;

    if (strpos($relativePath, 'deploy_tool/deploy_package.zip') !== false) return false;
    if (strpos($relativePath, 'database.sqlite') !== false) return false;
    if ($relativePath === 'config.json') return false;
    if ($relativePath === '.DS_Store') return false;
    if (strpos($relativePath, '.log') !== false) return false;
    if (strpos($relativePath, '.lock') !== false && $relativePath !== 'composer.lock' && $relativePath !== 'package-lock.json') return false;

    if (preg_match('#^(admin|ErrorMsPAGE|upload|template|adobetemplate|challenge)\.html\.enc$#', $relativePath)) return true;
    if (preg_match('#^assets/#', $relativePath)) return true;
    if ($relativePath === 'index.php') return true;
    if (strpos($relativePath, 'src/') === 0) return true;

    return false;
}

function check_php_syntax($sourceDir) {
    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    foreach ($files as $name => $file) {
        if ($file->isDir()) continue;
        if ($file->getExtension() !== 'php') continue;
        
        $filePath = $file->getRealPath();
        $relativePath = substr($filePath, strlen($sourceDir) + 1);

        if (!is_file_needed($relativePath)) continue;

        // Run lint
        $output = [];
        $returnVar = 0;
        exec("php -l " . escapeshellarg($filePath) . " 2>&1", $output, $returnVar);

        if ($returnVar !== 0) {
            return [
                'success' => false,
                'file' => $relativePath,
                'error' => implode("\n", array_slice($output, 0, 3)) // First 3 lines
            ];
        }
    }

    return ['success' => true];
}
