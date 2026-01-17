<?php
/**
 * L1mk Deployer - Single File Application
 * 
 * Logic consolidated and streamlined.
 * 
 * @author L1mk
 * @version 2.2
 */

require __DIR__ . '/vendor/autoload.php';

use phpseclib3\Net\SSH2;
use phpseclib3\Net\SFTP;

ini_set('memory_limit', '512M');
set_time_limit(0);

class Deployer
{
    private $serverConfig = [];
    private $currentLicense = '';
    private $isMaster = false;

    public function __construct()
    {
        $this->loadConfig();
    }

    public function run()
    {
        if (php_sapi_name() === 'cli-server') {
            $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
            if (preg_match('/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|woff|ttf|eot|map)$/i', $path)) {
                return false; 
            }
        }

        if (php_sapi_name() === 'cli') {
            $this->runCliMode();
            return;
        }

        if (!$this->validateLicense()) return;

        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $action = $_GET['action'] ?? '';

        if ($method === 'POST' && $action !== '') {
            $this->handleApi($action);
        } else {
            $this->renderDashboard();
        }
    }

    private function runCliMode()
    {
        $configFile = $this->deployConfigFilePath();
        if (!file_exists($configFile)) {
            echo "Config file not found: $configFile\n";
            exit(1);
        }
        $config = json_decode(file_get_contents($configFile), true);
        $data = array_key_exists(0, $config) ? $config[0] : $config;
        $data['save_config'] = 'true';
        
        $master = $this->getMasterKey();
        if ($master !== '' && !isset($data['license']) && !isset($data['license_key'])) {
            $data['license_key'] = $master;
        }

        // Fake REQUEST variables for the API handler
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_GET['action'] = 'deploy';
        $_POST = $data; 

        if (!$this->validateLicense()) {
            echo "[ERROR] License validation failed.\n";
            exit(1);
        }

        $this->handleApi('deploy');
    }

    private function handleApi($action)
    {
        $jsonActions = ['add_server', 'delete_server', 'save_server', 'get_servers', 'test_connection', 'list_domains', 'list_managed_domains', 'domain_status'];
        if (!in_array($action, $jsonActions)) {
            header('Content-Type: text/event-stream');
            header('Cache-Control: no-cache');
            header('Connection: keep-alive');
        } else {
            header('Content-Type: application/json');
        }

        $req = $this->parseDeployRequest($_POST);
        extract($req);

        // Get rotation config for existing server if applicable
        $rotation_slugs = [];
        $rotation_path = '';
        if (!empty($server_id)) {
            foreach ($this->serverConfig as $s) {
                if (($s['id'] ?? '') === $server_id) {
                    $rotation_slugs = $s['rotation_slugs'] ?? [];
                    $rotation_path = $s['rotation_path'] ?? '';
                    break;
                }
            }
        }

        try {
            switch ($action) {
                case 'get_servers':
                    $this->apiGetServers();
                    break;
                case 'test_connection':
                    $this->connectSsh($host, $port, $user, $password);
                    $this->jsonResponse('success', 'Connection successful!');
                    break;
                case 'view_logs':
                    $this->apiViewLogs($host, $port, $user, $password, $path);
                    break;
                case 'verify_structure':
                    $this->apiVerifyStructure($req);
                    break;
                case 'puppeteer_install':
                    $this->apiPuppeteerInstall($host, $port, $user, $password, $path);
                    break;
                case 'list_domains':
                    $this->apiListDomains($host, $port, $user, $password);
                    break;
                case 'list_managed_domains':
                    $this->apiListManagedDomains($host, $port, $user, $password, $main_domain);
                    break;
                case 'domain_status':
                    $this->apiDomainStatus($host, $port, $user, $password, $main_domain, $domains);
                    break;
                case 'add_server':
                    $this->apiAddServer($req);
                    break;
                case 'delete_server':
                    $this->apiDeleteServer($_POST['server_id'] ?? '');
                    break;
                case 'save_server':
                    $this->apiSaveServer($req, $rotation_path);
                    break;
                case 'apply_domains':
                    $this->apiApplyDomains($req, $rotation_path, $rotation_slugs);
                    break;
                case 'remove_domains_only':
                    $this->apiRemoveDomainsOnly($host, $port, $user, $password, $main_domain);
                    break;
                case 'update_page':
                    $this->deployPackage($req, 'Page Update', true);
                    break;
                case 'update_code':
                    $this->deployPackage($req, 'Code Update', false);
                    break;
                case 'deploy':
                case 'update':
                    $this->apiDeploy($req, $action, $rotation_path, $rotation_slugs);
                    break;
                case 'ssl':
                    $this->apiSsl($req);
                    break;
                case 'delete_uninstall':
                    $this->apiDeleteUninstall($req);
                    break;
                default:
                    $this->jsonResponse('error', 'Unknown action');
            }
        } catch (Exception $e) {
             if (headers_sent()) {
                 $this->sseMessage("Error: " . $e->getMessage(), 'error');
             } else {
                 $this->jsonResponse('error', $e->getMessage());
             }
        }
        exit;
    }

    // --- Streamlined API Methods ---

    private function apiViewLogs($host, $port, $user, $password, $path) {
        [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
        $logs = ['deploy.log', 'project.log', 'worker.log', 'puppeteer.log'];
        $cmd = "cd " . escapeshellarg($path);
        foreach ($logs as $log) {
            $cmd .= " && printf '=== $log ===\\n' && if [ -f $log ]; then tail -n 1000 $log; else echo '$log not found'; fi && printf '\\n'";
        }
        $cmd .= " && printf '=== Processes ===\\n'";
        $cmd .= " && (ps aux | grep 'php index.php worker' | grep -v grep || echo 'php index.php worker not running')";
        $cmd .= " && (ps aux | grep 'node consolidated.js' | grep -v grep || echo 'node consolidated.js not running') && printf '\\n'";
        $cmd .= " && printf '=== Disk Usage (project) ===\\n' && (du -sh . 2>/dev/null || echo 'du not available') && printf '\\n'";
        $cmd .= " && printf '=== Chrome / Puppeteer Install Info ===\\n'";
        $cmd .= " && echo 'node_modules/puppeteer:' && if [ -d node_modules/puppeteer ]; then ls -R node_modules/puppeteer 2>/dev/null | head -n 50; else echo 'node_modules/puppeteer NOT FOUND'; fi";
        $cmd .= " && echo '\\npuppeteer_chrome:' && if [ -d puppeteer_chrome ]; then ls -R puppeteer_chrome 2>/dev/null | head -n 50; else echo 'puppeteer_chrome NOT FOUND'; fi";
        $cmd .= " && echo '\\nchrome-* under project:' && (find . -maxdepth 8 -type d \\( -name 'chrome-linux64' -o -name 'chrome-*' \\) 2>/dev/null | head -n 20 || find .. -maxdepth 8 -type d \\( -name 'chrome-linux64' -o -name 'chrome-*' \\) 2>/dev/null | head -n 20 || echo 'none')";
        $cmd .= " && printf '\\n=== Summary ===\\n'";
        $cmd .= " && if ps aux | grep 'php index.php worker' | grep -v grep >/dev/null 2>&1; then echo 'Worker: running'; else echo 'Worker: not running'; fi";
        $cmd .= " && if ps aux | grep 'node consolidated.js' | grep -v grep >/dev/null 2>&1; then echo 'Puppeteer process: running'; else echo 'Puppeteer process: not running'; fi";
        $cmd .= " && if [ -d node_modules/puppeteer ]; then echo 'Puppeteer package: PRESENT'; else echo 'Puppeteer package: NOT FOUND'; fi";
        $cmd .= " && if { find . -maxdepth 8 -type d -name 'chrome-linux64' 2>/dev/null | head -n 1; find .. -maxdepth 8 -type d -name 'chrome-linux64' 2>/dev/null | head -n 1; } | grep -q .; then echo 'Chrome binary: FOUND'; else echo 'Chrome binary: NOT FOUND'; fi";
        $output = (string)$ssh->exec($sudo . "sh -lc " . escapeshellarg($cmd));
        $this->jsonResponse('success', '', ['logs' => $output]);
    }

    private function apiVerifyStructure($req) {
        extract($req);
        $this->sseStart("Structure Verification", "$user@$host");
        
        $target = $main_domain ?: $host;
        $url = "https://$target/api.php?action=get_structure";
        
        $this->sseMessage("🔍 Querying API: $url");
        
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        // curl_close is automatically handled in PHP 8.0+ for CurlHandle objects, but we keep it for older versions or explicit cleanup.
        // However, 'curl_close' is deprecated message usually appears if $ch is a CurlHandle (PHP 8.0+).
        // To suppress, we can unset it or check if it's a resource.
        unset($ch);
        
        if ($code !== 200) {
            $this->sseMessage("❌ Request Failed (HTTP $code). Error: $err", 'error');
            return;
        }
        
        $json = json_decode($resp, true);
        if (!$json || !isset($json['ok']) || !$json['ok']) {
             $this->sseMessage("❌ Invalid API Response: " . substr($resp, 0, 200), 'error');
             return;
        }
        
        $files = $json['structure'] ?? [];
        $count = count($files);
        $this->sseMessage("✅ Retrieved file list: $count items found.");
        
        // Critical File Check
        $required = ['src/App.php', 'api.php', 'index.php', 'consolidated.js'];
        $paths = array_column($files, 'path');
        $missing = [];
        
        foreach ($required as $r) {
            if (!in_array($r, $paths)) $missing[] = $r;
        }
        
        if ($missing) {
            $this->sseMessage("⚠️ MISSING CRITICAL FILES: " . implode(', ', $missing), 'error');
        } else {
            $this->sseMessage("✅ All critical files present.");
        }
        
        // Optional: Permissions check for App.php
        foreach ($files as $f) {
            if ($f['path'] === 'src/App.php') {
                $this->sseMessage("ℹ️ src/App.php size: {$f['size']} bytes, perms: {$f['perms']}");
            }
        }

        $this->sseFinish("DONE_VERIFY", "Verification");
    }

    private function apiPuppeteerInstall($host, $port, $user, $password, $path) {
        $this->sseStart('Puppeteer Install', "$user@$host");
        try {
            [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
            $rootPath = rtrim($path, '/');
            $projectRoot = rtrim(dirname($rootPath), '/');
            $cacheDir = $projectRoot . '/.cache/puppeteer';
            $installCmd = "cd " . escapeshellarg($rootPath) .
                          " && mkdir -p " . escapeshellarg($cacheDir) .
                          " && HOME=" . escapeshellarg($projectRoot) .
                          " PUPPETEER_CACHE_DIR=" . escapeshellarg($cacheDir) .
                          " npx puppeteer browsers install chrome";
            $ssh->exec($sudo . "sh -lc " . escapeshellarg($installCmd));
            $chromeCmd = $this->getChromeFallbackCommand($projectRoot);
            $ssh->exec($sudo . $chromeCmd);
            if (method_exists($ssh, 'disconnect')) $ssh->disconnect();
            $this->sseFinish('DONE_PUPPETEER_INSTALL', 'Puppeteer Install');
        } catch (Exception $e) {
            $this->sseMessage('Error: ' . $e->getMessage(), 'error');
        }
    }

    private function apiListDomains($host, $port, $user, $password) {
        [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
        $cmd = $sudo . "sh -lc " . escapeshellarg("awk '/server_name/{for(i=2;i<=NF;i++) print \$i}' /etc/nginx/sites-enabled/* 2>/dev/null | tr -d ';' | sort -u");
        $this->processDomainListOutput($ssh->exec($cmd));
    }

    private function apiListManagedDomains($host, $port, $user, $password, $main_domain) {
        [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
        $configKey = $this->nginxConfigKey($main_domain);
        $cmd = $sudo . "sh -lc " . escapeshellarg("if [ -f /etc/nginx/sites-enabled/$configKey ]; then awk '/server_name/{for(i=2;i<=NF;i++) print \$i}' /etc/nginx/sites-enabled/$configKey; fi");
        $this->processDomainListOutput($ssh->exec($cmd), ['config_key' => $configKey]);
    }

    private function processDomainListOutput($raw, $extra = []) {
        $lines = preg_split('/\r?\n/', trim((string)$raw));
        $domainsOut = [];
        foreach ($lines as $line) {
            $d = $this->normalizeDomain(str_replace(';', '', $line));
            if ($d !== '' && $d !== '_') $domainsOut[$d] = true;
        }
        $domainsOut = array_values(array_keys($domainsOut));
        sort($domainsOut);
        $this->jsonResponse('success', '', array_merge(['domains' => $domainsOut], $extra));
    }

    private function apiDomainStatus($host, $port, $user, $password, $main_domain, $domains) {
        $targets = array_unique(array_filter(array_merge([$main_domain], $domains), fn($d) => $d !== ''));
        
        // External Check (Parallel)
        $mh = curl_multi_init();
        $handles = [];
        foreach ($targets as $d) {
            foreach (['http', 'https'] as $proto) {
                $ch = curl_init("$proto://$d");
                curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_NOBODY => true, CURLOPT_TIMEOUT => 5, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => false, CURLOPT_FOLLOWLOCATION => true]);
                curl_multi_add_handle($mh, $ch);
                $handles["$proto://$d"] = ['ch' => $ch, 'domain' => $d, 'proto' => $proto];
            }
        }
        
        $active = null;
        do { $mrc = curl_multi_exec($mh, $active); } while ($mrc == CURLM_CALL_MULTI_PERFORM);
        while ($active && $mrc == CURLM_OK) { if (curl_multi_select($mh) != -1) { do { $mrc = curl_multi_exec($mh, $active); } while ($mrc == CURLM_CALL_MULTI_PERFORM); } }

        $results = [];
        foreach ($handles as $h) {
            $info = curl_getinfo($h['ch']);
            $results[$h['domain']][$h['proto']] = $info['http_code'];
            if ($info['primary_ip']) $results[$h['domain']]['ip'] = $info['primary_ip'];
            curl_multi_remove_handle($mh, $h['ch']);
        }

        // Internal Check
        $localCodes = [];
        try {
            [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
            $cmdList = [];
            foreach ($targets as $d) $cmdList[] = "echo \"$d:$(curl -Is -o /dev/null -w '%{http_code}' -H 'Host: $d' http://127.0.0.1 --max-time 2 || echo 0)\"";
            $rawOut = (string)$ssh->exec($sudo . "sh -c " . escapeshellarg(implode('; ', $cmdList)));
            foreach (explode("\n", trim($rawOut)) as $line) {
                if (strpos($line, ':') !== false) {
                    [$d, $c] = explode(':', trim($line), 2);
                    $localCodes[$d] = intval($c);
                }
            }
        } catch (Exception $e) { unset($e); }

        $out = [];
        foreach ($targets as $d) {
            $http = $results[$d]['http'] ?? 0;
            $https = $results[$d]['https'] ?? 0;
            $local = $localCodes[$d] ?? 0;
            $dnsIp = $results[$d]['ip'] ?? gethostbyname($d);
            $primary = $https > 0 ? $https : $http;
            $publicLive = ($primary >= 200 && $primary < 400);
            $localLive = ($local >= 200 && $local < 400);
            $out[] = [
                'domain' => $d,
                'dns_ip' => $dnsIp === $d ? '' : $dnsIp,
                'matches_host' => ($dnsIp !== $d && $dnsIp === $host),
                'http_code' => $http,
                'https_code' => $https,
                'local_code' => $local,
                'live' => $publicLive,
                'local_live' => $localLive
            ];
        }
        $this->jsonResponse('success', '', ['statuses' => $out]);
    }

    private function apiGetServers() {
        $srvs = $this->serverConfig;
        if ($this->currentLicense && !$this->isMaster) {
            $srvs = array_values(array_filter($srvs, fn($s) => ($s['license_key'] ?? '') === $this->currentLicense));
        }
        $this->jsonResponse('success', '', ['servers' => $srvs]);
    }

    private function apiAddServer($req) {
        extract($req);
        if ($this->currentLicense !== '' && !$this->isMaster) {
            $activeCount = 0;
            foreach ($this->serverConfig as $srv) {
                if (($srv['license_key'] ?? '') === $this->currentLicense) $activeCount++;
            }
            if ($activeCount >= 1) $this->jsonResponse('error', 'License limit reached (1 VPS per license).');
        }

        // Check for duplicates
        foreach ($this->serverConfig as $srv) {
            if (($srv['host'] ?? '') === $host && ($srv['path'] ?? '') === $path) {
                $this->jsonResponse('error', 'Server with this Host and Path already exists.');
                return;
            }
        }

        $this->connectSsh($host, $port, $user, $password); // Verify connection
        
        $rotation_slugs = [];
        $rotation_path = '';
        if ($rotation_enabled) {
            [$usedSlugs, $usedPaths] = $this->getUsedIdentifiers($this->serverConfig);
            $rotation_slugs = [$this->findUniqueString($usedSlugs, 5)];
            $rotation_path = $this->findUniqueString($usedPaths, 20);
        }

        $newServer = array_merge($req, [
            'id' => uniqid('srv_'),
            'license_key' => $this->currentLicense,
            'rotation_slugs' => $rotation_slugs,
            'rotation_path' => $rotation_path
        ]);
        // Remove transient API fields
        unset($newServer['action'], $newServer['server_id']);
        
        $this->serverConfig[] = $newServer;
        $this->saveConfig($this->serverConfig);
        $this->jsonResponse('success', 'Server added successfully.', ['server' => $newServer]);
    }

    private function apiDeleteServer($id) {
        $this->serverConfig = array_values(array_filter($this->serverConfig, fn($s) => ($s['id'] ?? '') !== $id));
        $this->saveConfig($this->serverConfig);
        $this->jsonResponse('success', 'Server deleted.');
    }

    private function apiSaveServer($req, $rotation_path) {
        extract($req);
        $id = $_POST['server_id'] ?? '';
        foreach ($this->serverConfig as &$srv) {
            if (($srv['id'] ?? '') === $id) {
                $srv = array_merge($srv, [
                    'host' => $host, 'user' => $user, 'password' => $password, 'port' => $port,
                    'path' => $path, 'main_domain' => $main_domain, 'domains' => $domains,
                    'rotation_enabled' => $rotation_enabled, 'wildcard_enabled' => $wildcard_enabled,
                    'local_path' => $local_path
                ]);
                unset($srv['domain']); // cleanup old key

                if ($rotation_enabled) {
                    [$usedSlugs, $usedPaths] = $this->getUsedIdentifiers($this->serverConfig);
                    if (empty($srv['rotation_slugs'])) $srv['rotation_slugs'] = [$this->findUniqueString($usedSlugs, 5)];
                    if (empty($srv['rotation_path'])) {
                        $srv['rotation_path'] = !empty($rotation_path) ? $rotation_path : $this->findUniqueString($usedPaths, 20);
                    }
                }
                break;
            }
        }
        $this->saveConfig($this->serverConfig);
        $this->jsonResponse('success', 'Server updated.');
    }

    private function apiApplyDomains($req, $rotation_path, $rotation_slugs) {
        extract($req);
        
        // Auto-save the new domain configuration
        if (!empty($server_id)) {
            foreach ($this->serverConfig as &$srv) {
                if (($srv['id'] ?? '') === $server_id) {
                    $srv['main_domain'] = $main_domain;
                    $srv['domains'] = $domains;
                    $srv['wildcard_enabled'] = $wildcard_enabled;
                    break;
                }
            }
            $this->saveConfig($this->serverConfig);
        }

        $this->sseMessage("🌐 Applying domains to Nginx...");
        try {
            [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
            $this->applyNginxConfig($ssh, $sudo, $main_domain, $domains, $path, $rotation_enabled, $wildcard_enabled, $rotation_path, $rotation_slugs);
            $this->sseFinish("DONE_APPLY_DOMAINS", "Domain Update");
        } catch (Exception $e) {
            $this->sseMessage("❌ Apply domains error: " . $e->getMessage(), 'error');
        }
    }

    private function apiRemoveDomainsOnly($host, $port, $user, $password, $main_domain) {
        $this->sseMessage("🧹 Removing managed domains from Nginx...");
        try {
            [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
            $ssh->exec("$sudo rm /etc/nginx/sites-enabled/VERIFY_TEST_REFLECTION.COM /etc/nginx/sites-available/VERIFY_TEST_REFLECTION.COM 2>/dev/null || true");
            $this->removeNginxConfig($ssh, $sudo, $this->nginxConfigKey($main_domain));
            $this->sseFinish("DONE_REMOVE_DOMAINS", "Domain Removal");
        } catch (Exception $e) {
            $this->sseMessage("❌ Remove domains error: " . $e->getMessage(), 'error');
        }
    }

    private function deployPackage($req, $label, $isPageUpdate) {
        extract($req);
        $this->sseStart($label, "$user@$host");
        
        $baseDir = rtrim($local_path, '/');
        $sourceDir = $baseDir . '/MA';
        if (!is_dir($sourceDir)) {
            $this->sseMessage("❌ Local MA directory does not exist: $sourceDir", 'error');
            return;
        }

        $zipFile = __DIR__ . '/deploy_package.zip';
        $this->sseMessage("📦 Zipping assets...");
        if (!$this->zipProject($sourceDir, $zipFile, $isPageUpdate)) {
            $this->sseMessage("❌ Failed to zip assets.", 'error');
            return;
        }

        try {
            $this->sseMessage("🔌 Connecting and Uploading...");
            [$sshUpload, $sudoUpload] = $this->connectSsh($host, $port, $user, $password);
            $sftp = new SFTP($host, $port);
            if (!$sftp->login($user, $password)) throw new Exception("SFTP Login failed.");
            
            $sshUpload->exec($sudoUpload . "mkdir -p " . escapeshellarg($path));
            if (!$sftp->put($path . '/deploy_package.zip', $zipFile, SFTP::SOURCE_LOCAL_FILE)) {
                throw new Exception("Upload failed.");
            }

            if (method_exists($sshUpload, 'disconnect')) $sshUpload->disconnect();
            unset($sftp, $sshUpload, $sudoUpload);

            $this->sseMessage("⚙️ Extracting and setting permissions...");
            [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
            $maPath = rtrim($path, '/');
            $commands = [
                "cd " . escapeshellarg($path) . " && unzip -o deploy_package.zip",
                "rm " . escapeshellarg($path) . "/deploy_package.zip",
            ];
            $commands = array_merge($commands, $this->getDeployCoreCommands($path, $maPath));
            $ssh->exec($sudo . implode('; ', $commands));
            if (method_exists($ssh, 'disconnect')) $ssh->disconnect();

            $this->sseMessage("🔄 Restarting worker...");
            [$sshWorker, $sudoWorker] = $this->connectSsh($host, $port, $user, $password);
            $this->restartWorker($sshWorker, $sudoWorker, $path, $user);
            if (method_exists($sshWorker, 'disconnect')) $sshWorker->disconnect();

            $this->sseMessage("⚙️ Ensuring Puppeteer Chrome cache (fallback)...");
            [$sshChrome, $sudoChrome] = $this->connectSsh($host, $port, $user, $password);
            $rootPath = rtrim($path, '/');
            $projectRoot = rtrim(dirname($rootPath), '/');
            $chromeCmd = $this->getChromeFallbackCommand($projectRoot);
            $sshChrome->exec($sudoChrome . $chromeCmd);
            if (method_exists($sshChrome, 'disconnect')) $sshChrome->disconnect();

            unlink($zipFile);
            $this->sseFinish("DONE_DEPLOY", $label);

        } catch (Exception $e) {
            $this->sseMessage("❌ Error: " . $e->getMessage(), 'error');
            if (file_exists($zipFile)) unlink($zipFile);
        }
    }

    private function apiDeploy($req, $action, $rotation_path, $rotation_slugs) {
        extract($req);
        $label = ($action === 'update') ? 'Update' : 'Deployment';
        $this->sseStart($label, "$user@$host");
        
        $baseDir = rtrim($local_path, '/');
        $sourceDir = $baseDir . '/MA';
        if (!is_dir($sourceDir)) {
            $this->sseMessage("❌ Invalid MA dir: $sourceDir", 'error');
            return;
        }

        $zipFile = __DIR__ . '/deploy_package.zip';
        $this->sseMessage("📦 Zipping project...");
        if (!$this->zipProject($sourceDir, $zipFile, false)) { $this->sseMessage("❌ Zip failed.", 'error'); return; }

        try {
            [$sshUpload, $sudoUpload] = $this->connectSsh($host, $port, $user, $password);
            $sftp = new SFTP($host, $port);
            if (!$sftp->login($user, $password)) throw new Exception("SFTP Login failed.");
            
            $this->sseMessage("⬆️ Uploading...");
            $sshUpload->exec($sudoUpload . "mkdir -p " . escapeshellarg($path));
            if (!$sftp->put($path . '/deploy_package.zip', $zipFile, SFTP::SOURCE_LOCAL_FILE)) throw new Exception("Upload failed.");

            if (method_exists($sshUpload, 'disconnect')) $sshUpload->disconnect();
            unset($sftp, $sshUpload, $sudoUpload);
            
            $this->sseMessage("⚙️ Configuring remote (files)...");
            $envPayload = $this->getRemoteEnvPayload();
            [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
            $maPath = rtrim($path, '/');
            $commands = [
                "cd " . escapeshellarg($path) . " && rm -f src/App.php && unzip -o deploy_package.zip && rm deploy_package.zip",
                "cd " . escapeshellarg($path) . " && if [ ! -f config.json.enc ]; then cp config.example.json config.json.enc 2>/dev/null || true; fi",
                "echo " . escapeshellarg(base64_encode(json_encode(['main_domain' => $main_domain, 'rotation_path' => $rotation_path, 'rotation_slugs' => $rotation_slugs]))) . " | base64 -d > " . escapeshellarg($path) . "/deployment.json",
                "chmod 644 " . escapeshellarg($path) . "/deployment.json",
            ];
            $commands = array_merge($commands, $this->getDeployCoreCommands($path, $maPath));
            $ssh->exec($sudo . implode('; ', $commands));

            $this->sseMessage("⚙️ Configuring remote (env)...");
            if ($envPayload) {
                $ssh->exec("printf %s " . escapeshellarg($envPayload) . " | base64 -d > " . escapeshellarg($path . '/.env'));
            }

            if (method_exists($ssh, 'disconnect')) $ssh->disconnect();

            $this->sseMessage("⚙️ Configuring remote (worker)...");
            [$sshWorker, $sudoWorker] = $this->connectSsh($host, $port, $user, $password);
            $this->restartWorker($sshWorker, $sudoWorker, $path, $user);
            if (method_exists($sshWorker, 'disconnect')) $sshWorker->disconnect();

            // Force PHP Restart (Separate Connection)
            $this->sseMessage("🔄 Reloading PHP-FPM...");
            try {
                [$sshPhp, $sudoPhp] = $this->connectSsh($host, $port, $user, $password);
                $sshPhp->exec("$sudoPhp systemctl reload php*-fpm || $sudoPhp service php*-fpm reload || $sudoPhp kill -USR2 $(pgrep -o php-fpm) || true");
                if (method_exists($sshPhp, 'disconnect')) $sshPhp->disconnect();
            } catch (Exception $e) {
                $this->sseMessage("⚠️ PHP Reload Warning: " . $e->getMessage(), 'warning');
            }

            $this->sseMessage("⚙️ Configuring remote (nginx)...");
            [$sshNginx, $sudoNginx] = $this->connectSsh($host, $port, $user, $password);
            $this->applyNginxConfig($sshNginx, $sudoNginx, $main_domain, $domains, $path, $rotation_enabled, $wildcard_enabled, $rotation_path, $rotation_slugs);
            
            // Force PHP-FPM Reload to clear OPcache
            $this->sseMessage("🔄 Reloading PHP-FPM...");
            $sshNginx->exec("$sudoNginx service php8.3-fpm reload || $sudoNginx service php8.2-fpm reload || $sudoNginx service php8.1-fpm reload || $sudoNginx service php8.0-fpm reload || $sudoNginx service php7.4-fpm reload || $sudoNginx kill -USR2 $(pgrep -o php-fpm) || true");
            
            $checkUrl = "http://localhost" . ($rotation_enabled && $rotation_path ? "/$rotation_path/{$rotation_slugs[0]}" : "/");
            $this->sseMessage("⚙️ Configuring remote (health)...");
            [$sshHealth, $sudoHealth] = $this->connectSsh($host, $port, $user, $password);
            unset($sudoHealth); // Unused
            $httpCode = trim($sshHealth->exec("curl -s -o /dev/null -w '%{http_code}' " . escapeshellarg($checkUrl)));
            if ($httpCode >= 200 && $httpCode < 400) {
                $this->sseMessage("✅ Health Check Passed ($httpCode)");

                $this->sseMessage("⚙️ Ensuring Puppeteer Chrome cache (fallback)...");
                [$sshChrome, $sudoChrome] = $this->connectSsh($host, $port, $user, $password);
                $rootPath = rtrim($path, '/');
                $projectRoot = rtrim(dirname($rootPath), '/');
                $chromeCmd = $this->getChromeFallbackCommand($projectRoot);
                $sshChrome->exec($sudoChrome . $chromeCmd);
                if (method_exists($sshChrome, 'disconnect')) $sshChrome->disconnect();
            } else {
                $this->sseMessage("⚠️ Health Check Warning ($httpCode)", 'warning');
            }

            $this->sseFinish("DONE_DEPLOY", $label);

        } catch (Exception $e) {
            $this->sseMessage("❌ Error: " . $e->getMessage(), 'error');
        } finally {
            if (file_exists($zipFile)) unlink($zipFile);
        }
    }

    private function apiSsl($req) {
        extract($req);
        $this->sseMessage("🔒 Starting Certbot...");
        try {
            [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
            if ($main_domain === '') throw new Exception("No main domain.");

            if (!$ssh->exec("command -v certbot")) {
                $this->sseMessage("Installing Certbot...");
                $ssh->exec("$sudo apt-get update && DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y certbot python3-certbot-nginx");
            }

            $ssh->exec("$sudo rm /etc/nginx/sites-enabled/VERIFY_TEST_REFLECTION.COM /etc/nginx/sites-available/VERIFY_TEST_REFLECTION.COM 2>/dev/null || true");

            $certDomains = array_unique(array_filter(array_merge([$main_domain], $domains), fn($d) => $d !== ''));
            $certNames = [];
            foreach ($certDomains as $d) {
                foreach ($this->domainVariants($d) as $v) $certNames[] = $v;
            }
            $certNames = array_unique($certNames);
            
            $args = implode(' ', array_map(fn($n) => "-d " . escapeshellarg($n), $certNames));
            $this->sseMessage("Requesting certs for: " . implode(', ', $certNames));
            
            $ssh->setTimeout(120);
            $out = (string)$ssh->exec("$sudo certbot --nginx $args --non-interactive --agree-tos --register-unsafely-without-email --redirect");
            $this->sseMessage($out);
            
            $this->sseFinish("DONE_SSL", "SSL Setup");
        } catch (Exception $e) {
            $this->sseMessage("❌ SSL Error: " . $e->getMessage(), 'error');
        }
    }

    private function apiDeleteUninstall($req) {
        extract($req);
        $this->sseMessage("⚠️ Starting cleanup...");
        try {
            // Phase 1: Stop processes
            [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
            $ssh->exec("$sudo pkill -f 'php index.php worker' || true; $sudo pkill -f 'node .*consolidated.js' || true");
            if (method_exists($ssh, 'disconnect')) $ssh->disconnect();
            
            // Phase 2: Remove Nginx
            [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
            $cmds = [];
            $keys = [];
            $cmds[] = "$sudo rm /etc/nginx/sites-enabled/VERIFY_TEST_REFLECTION.COM /etc/nginx/sites-available/VERIFY_TEST_REFLECTION.COM 2>/dev/null || true";
            if ($main_domain) $keys[] = $this->nginxConfigKey($main_domain);
            foreach ($domains as $d) if ($d) $keys[] = $this->nginxConfigKey($d);
            
            foreach (array_unique($keys) as $k) {
                $cmds[] = "$sudo rm /etc/nginx/sites-enabled/$k /etc/nginx/sites-available/$k 2>/dev/null || true";
            }
            if ($cmds) {
                $cmds[] = "$sudo nginx -t && $sudo systemctl reload nginx";
                $ssh->exec(implode('; ', $cmds));
            }
            if (method_exists($ssh, 'disconnect')) $ssh->disconnect();
            
            // Phase 3: Delete files and certs
            [$ssh, $sudo] = $this->connectSsh($host, $port, $user, $password);
            $this->sseMessage("🗑️ Deleting files and caches...");
            $cleanupCmd = "rm -rf " . escapeshellarg($path);
            if ($main_domain) $cleanupCmd .= "; $sudo certbot delete --cert-name " . escapeshellarg($main_domain) . " --non-interactive || true";
            foreach ($domains as $d) if ($d) $cleanupCmd .= "; $sudo certbot delete --cert-name " . escapeshellarg($d) . " --non-interactive || true";
            $cleanupCmd .= "; $sudo rm -rf /root/.cache /root/.npm || true";

            $ssh->exec($cleanupCmd);
            if (method_exists($ssh, 'disconnect')) $ssh->disconnect();

            $this->sseFinish("DONE_CLEANUP", "Uninstall");
        } catch (Exception $e) {
            $this->sseMessage("❌ Error: " . $e->getMessage(), 'error');
        }
    }

    // --- Helpers ---

    private function getDeployCoreCommands($path, $maPath) {
        $p = escapeshellarg($path);
        $maReal = rtrim($maPath, '/');
        $m = escapeshellarg($maReal);
        $projectRoot = rtrim(dirname($maReal), '/');
        $cache = escapeshellarg($projectRoot . '/puppeteer_chrome');
        $home = escapeshellarg($projectRoot);
        return [
            "touch $p/deploy.log $p/puppeteer.log $p/worker.log $p/project.log",
            "echo \"--- Deploy Start: $(date) ---\" >> $p/deploy.log",
            "echo \"--- Deploy Start: $(date) ---\" >> $p/project.log",
            "echo \"--- Puppeteer Log Init ---\" >> $p/puppeteer.log",
            "echo \"--- Puppeteer Log Init ---\" >> $p/project.log",
            "echo \"--- Worker Log Init ---\" >> $p/worker.log",
            "echo \"--- Worker Log Init ---\" >> $p/project.log",
            "chown -R www-data:www-data $p",
            "chmod -R 755 $p",
            "mkdir -p $p/session_data && chmod -R 777 $p/session_data",
            "touch $p/database.sqlite && chown www-data:www-data $p/database.sqlite && chmod 666 $p/database.sqlite",
            "cd $m && if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 && [ -f package.json ]; then HOME=$home npm install --production || HOME=$home npm install; fi",
            "cd $m && mkdir -p $cache && HOME=$home PUPPETEER_CACHE_DIR=$cache npx puppeteer browsers install chrome || true"
        ];
    }

    private function getChromeFallbackCommand($rootPath) {
        $rootPath = rtrim($rootPath, '/');
        return "cd " . escapeshellarg($rootPath) .
               " && { mkdir -p " . escapeshellarg($rootPath . '/puppeteer_chrome') .
               " ; z=\$(find puppeteer_chrome -maxdepth 3 -type f -name '*-chrome-linux64.zip' | head -n1);" .
               " if [ -n \"\$z\" ]; then v=\$(basename \"\$z\" '-chrome-linux64.zip');" .
               " mkdir -p puppeteer_chrome/chrome/\"\$v\";" .
               " unzip -o \"\$z\" -d puppeteer_chrome/chrome/\"\$v\" && rm -f \"\$z\" || true; fi;" .
               " find puppeteer_chrome -maxdepth 3 -type f -name '*-chrome-linux64.zip' -delete || true; } >> " .
               escapeshellarg($rootPath . '/puppeteer.log') . " 2>&1";
    }

    private function connectSsh($host, $port, $user, $password) {
        $ssh = new SSH2($host, $port);
        if (!$ssh->login($user, $password)) throw new Exception("SSH Login failed.");
        return [$ssh, ($user === 'root' ? '' : 'sudo ')];
    }

    private function restartWorker($ssh, $sudo, $path, $user) {
        $maPath = rtrim($path, '/');
        $base = "cd " . escapeshellarg($maPath) . " && $sudo pkill -f 'php index.php worker' || true;";
        $run = "cd " . escapeshellarg($maPath) . " && { echo '--- Worker Restart: $(date) ---'; " . ($user === 'root' ? "" : "sudo -u www-data ") . "nohup php index.php worker > project.log 2>&1 < /dev/null & echo 'WORKER_START_EXIT:$?'; } >> project.log 2>&1";
        $ssh->exec($base . ' ' . $run);
    }

    private function applyNginxConfig($ssh, $sudo, $main, $domains, $path, $rot, $wild, $rotPath, $rotSlugs) {
        $useLe = false;
        if ($main) {
            $check = $ssh->exec("if [ -f /etc/letsencrypt/live/" . escapeshellarg($main) . "/fullchain.pem ]; then echo 'Y'; fi");
            if (trim($check) === 'Y') { $useLe = true; $this->sseMessage("ℹ️ Using existing Let's Encrypt certs."); }
        }

        if (!$useLe) $this->setupSslSelfSigned($ssh, $sudo);

        $config = $this->getNginxConfigMulti($main, $domains, $path, $rot, $wild, $rotPath, $rotSlugs, $useLe);
        $sock = trim((string)$ssh->exec("find /var/run/php -name 'php*-fpm.sock' | head -n 1")) ?: '/var/run/php/php-fpm.sock';
        $config = str_replace('/var/run/php/php-fpm.sock', $sock, $config);

        $key = $this->nginxConfigKey($main);
        $this->writeNginx($ssh, $sudo, $key, $config);
        
        // Clean old aliases if they differ
        foreach ($domains as $d) {
            if ($d && ($ak = $this->nginxConfigKey($d)) !== $key) {
                $ssh->exec("$sudo rm /etc/nginx/sites-enabled/$ak /etc/nginx/sites-available/$ak 2>/dev/null || true");
            }
        }
        if (!$main) $ssh->exec("$sudo rm /etc/nginx/sites-enabled/default 2>/dev/null || true");
    }

    private function setupSslSelfSigned($ssh, $sudo) {
        $ssh->exec("$sudo mkdir -p /etc/nginx/ssl");
        if (trim($ssh->exec("if [ -f /etc/nginx/ssl/selfsigned.crt ]; then echo 'Y'; fi")) !== 'Y') {
            $this->sseMessage("🔑 Generating self-signed cert...");
            $ssh->exec("$sudo apt-get install -y openssl");
            $ssh->exec("$sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/selfsigned.key -out /etc/nginx/ssl/selfsigned.crt -subj '/C=US/ST=State/L=City/O=Organization/CN=localhost'");
        }
    }

    private function getRemoteEnvPayload() {
        $keys = ['APP_ENV', 'ENC_KEY', 'MASTER_LICENSE_KEY'];
        $lines = [];
        $rootEnv = dirname(__DIR__) . '/.env';
        $fileEnv = is_file($rootEnv) ? parse_ini_file($rootEnv) : [];
        foreach ($keys as $k) {
            $v = getenv($k) ?: ($fileEnv[$k] ?? '');
            if ($v) $lines[] = "$k=$v";
        }
        return $lines ? base64_encode(implode("\n", $lines) . "\n") : '';
    }

    private function zipProject($sourceDir, $zipPath, $isPageUpdate) {
        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) return false;
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY);
        foreach ($files as $file) {
            if ($file->isDir()) continue;
            $rel = substr($file->getRealPath(), strlen($sourceDir) + 1);
            if ($this->isFileNeeded($rel, $isPageUpdate)) $zip->addFile($file->getRealPath(), $rel);
        }
        return $zip->close();
    }

    private function isFileNeeded($rel, $isPageUpdate) {
        unset($isPageUpdate); // Unused
        $ignorePrefixes = ['.git/', '.idea/', '.vscode/', 'session_data/'];
        foreach ($ignorePrefixes as $p) {
            if (strpos($rel, $p) === 0) return false;
        }
        if ($rel === 'database.sqlite') return false;
        if (substr($rel, -4) === '.log') return false;
        if ($rel === '.DS_Store') return false;
        return true;
    }

    private function jsonResponse($status, $message, $data = []) {
        echo json_encode(array_merge(['status' => $status, 'message' => $message], $data));
    }

    private function sseStart($label, $target) {
        $this->sseMessage("🚀 Starting $label to $target...");
    }

    private function sseFinish($signal, $label = null) {
        if ($label) $this->sseMessage("✅ $label Finished Successfully!", 'success');
        $this->sseMessage($signal);
    }

    private function sseMessage($msg, $type = 'info') {
        echo "data: " . json_encode(['message' => $msg, 'type' => $type, 'time' => date('H:i:s')]) . "\n\n";
        if (ob_get_level() > 0) ob_flush();
        flush();
    }

    private function getMasterKey() {
        $k = getenv('MASTER_LICENSE_KEY');
        if (!$k && is_file($f = dirname(__DIR__) . '/.env')) {
            $p = parse_ini_file($f);
            $k = $p['MASTER_LICENSE_KEY'] ?? '';
        }
        return $k ?: '8080';
    }

    private function validateLicense() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start([
                'cookie_lifetime' => 86400 * 30, // Cookie lasts 30 days
                'gc_maxlifetime' => 10800 // Session data lasts 3 hours (3 * 3600)
            ]);
        }

        // Check inactivity (3 hours)
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 10800)) {
            session_unset();
            session_destroy();
        }
        $_SESSION['last_activity'] = time();

        $key = trim($_POST['license'] ?? $_POST['license_key'] ?? $_SESSION['license_key'] ?? '');
        
        // Logout logic
        if (($_GET['action'] ?? '') === 'logout') {
            session_destroy();
            header("Location: ?");
            exit;
        }

        $master = $this->getMasterKey();
        
        $valid = ($master && $key && hash_equals($master, $key));
        if (!$valid && $key && is_file($db = dirname(__DIR__) . '/license_bot.db')) {
            try {
                $pdo = new PDO('sqlite:' . $db);
                $stmt = $pdo->prepare('SELECT status, expires_at FROM licenses WHERE license_key = ? LIMIT 1');
                $stmt->execute([$key]);
                $row = $stmt->fetch();
                if ($row && $row['status'] === 'active' && $row['expires_at'] > gmdate('c')) $valid = true;
            } catch (Exception $e) { unset($e); }
        }
        
        $this->currentLicense = $key;
        if ($valid) {
            if ($master && hash_equals($master, $key)) $this->isMaster = true;
            $_SESSION['license_key'] = $key; // Save to session
            return true;
        }

        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_GET['action'])) {
            $this->jsonResponse('error', 'License required');
        } else {
            $this->renderLogin();
        }
        return false;
    }

    private function loadConfig() {
        $f = $this->deployConfigFilePath();
        if (is_file($f)) {
            $d = json_decode(file_get_contents($f), true);
            $this->serverConfig = (is_array($d) && isset($d[0])) ? $d : (is_array($d) ? [$d] : []);
        }
    }

    private function saveConfig($d) {
        file_put_contents($this->deployConfigFilePath(), json_encode(array_values($d), JSON_PRETTY_PRINT));
    }

    private function deployConfigFilePath() {
        return (is_dir('/data') && is_writable('/data')) ? '/data/deploy_config.json' : __DIR__ . '/deploy_config.json';
    }

    private function getUsedIdentifiers($servers) {
        $s = []; $p = [];
        foreach ($servers as $srv) {
            foreach ($srv['rotation_slugs'] ?? [] as $x) $s[$x] = true;
            if (!empty($srv['rotation_path'])) $p[$srv['rotation_path']] = true;
        }
        return [$s, $p];
    }

    private function findUniqueString($used, $len) {
        do { $s = $this->generateRandomString($len); } while (isset($used[$s]));
        return $s;
    }

    private function generateRandomString($len) {
        return substr(str_shuffle('abcdefghijklmnopqrstuvwxyz0123456789'), 0, $len);
    }

    private function normalizeDomain($d) {
        $d = preg_replace('#^https?://|/.*$#', '', strtolower(trim((string)$d)));
        return preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/', $d) ? $d : '';
    }

    private function domainVariants($d) {
        $d = $this->normalizeDomain($d);
        if (!$d) return [];
        return str_starts_with($d, 'www.') ? [$d, substr($d, 4)] : [$d, "www.$d"];
    }

    private function nginxConfigKey($d) {
        return preg_replace('/[^a-zA-Z0-9._-]/', '_', $d ?: 'default_app');
    }

    private function writeNginx($ssh, $sudo, $key, $conf) {
        $ssh->exec("echo " . escapeshellarg($conf) . " > /tmp/nginx_conf");
        $ssh->exec("$sudo mv /tmp/nginx_conf /etc/nginx/sites-available/$key");
        $ssh->exec("$sudo ln -sf /etc/nginx/sites-available/$key /etc/nginx/sites-enabled/$key");
        $ssh->exec("$sudo nginx -t && $sudo systemctl reload nginx");
    }

    private function removeNginxConfig($ssh, $sudo, $key) {
        $ssh->exec("$sudo rm /etc/nginx/sites-enabled/$key /etc/nginx/sites-available/$key 2>/dev/null");
        $ssh->exec("$sudo nginx -t && $sudo systemctl reload nginx");
    }

    private function getNginxConfigMulti($main, $add, $root, $rot, $wild, $rotPath, $rotSlugs, $useLe) {
        unset($rotSlugs); // Unused
        $main = $this->normalizeDomain($main);
        $add = array_unique(array_filter(array_map([$this, 'normalizeDomain'], $add), fn($d) => $d && $d !== $main));

        if ($rot && $main && $add) {
            // Rotation Logic
            $weight = count($add) > 0 ? max(1, intdiv(100, count($add))) : 100;
            $split = "split_clients \"\$request_uri\" \$rotation_target {\n";
            foreach (array_slice($add, 0, -1) as $d) $split .= "    {$weight}% $d;\n";
            if ($last = end($add)) $split .= "    * $last;\n";
            $split .= "}\n\n";

            $loc = $rotPath ? "    location ~ ^/" . preg_quote($rotPath, '/') . "/ { return 302 \$scheme://\$rotation_target\$request_uri; }\n    location / { try_files \$uri \$uri/ /index.php?\$query_string; }" : "    location / { return 302 \$scheme://\$rotation_target\$request_uri; }";
            
            $blocks = [$split, $this->nginxBlock($main, $root, $useLe, $wild, $loc)];
            foreach ($add as $d) $blocks[] = $this->nginxBlock($d, $root, $useLe);
            return implode("\n\n", $blocks);
        }

        // Standard Logic
        $names = array_unique(array_merge($this->domainVariants($main), ($wild && $main) ? ["*.$main"] : []));
        foreach ($add as $d) $names = array_merge($names, $this->domainVariants($d));
        return $this->nginxBlock(implode(' ', $names), $root, $useLe && $main);
    }

    private function nginxBlock($names, $root, $useLe, $wild = false, $customLoc = '') {
        unset($wild); // Unused
        $ssl = $useLe ? 
            "    ssl_certificate /etc/letsencrypt/live/" . explode(' ', $names)[0] . "/fullchain.pem;\n    ssl_certificate_key /etc/letsencrypt/live/" . explode(' ', $names)[0] . "/privkey.pem;" : 
            "    ssl_certificate /etc/nginx/ssl/selfsigned.crt;\n    ssl_certificate_key /etc/nginx/ssl/selfsigned.key;";
        
        $loc = $customLoc ?: "    location / { try_files \$uri \$uri/ /index.php?\$query_string; }";
        
        return <<<NGINX
server {
    listen 80;
    listen 443 ssl;
    server_name $names;
    root $root;
$ssl
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    index index.php index.html index.htm;
    location ^~ /.well-known/acme-challenge/ { try_files \$uri =404; }
$loc
    location ~ \.php$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:/var/run/php/php-fpm.sock; }
    location ~ /\.ht { deny all; }
}
NGINX;
    }

    public function parseDeployRequest($post) {
        return [
            'action' => $_GET['action'] ?? '',
            'host' => $post['host'] ?? '',
            'user' => $post['user'] ?? 'root',
            'password' => $post['password'] ?? '',
            'port' => intval($post['port'] ?? 22),
            'path' => $post['path'] ?? '/var/www/html',
            'main_domain' => $this->normalizeDomain($post['main_domain'] ?? ''),
            'domains' => $this->normalizeDomainsList($post['domains'] ?? []),
            'rotation_enabled' => ($post['rotation_enabled'] ?? '0') === '1',
            'wildcard_enabled' => ($post['wildcard_enabled'] ?? '0') === '1',
            'local_path' => $post['local_path'] ?? '',
            'server_id' => $post['server_id'] ?? null,
            'license_key' => trim($post['license'] ?? $post['license_key'] ?? '')
        ];
    }

    private function normalizeDomainsList($in) {
        $arr = is_array($in) ? $in : preg_split('/[\s,]+/', (string)$in, -1, PREG_SPLIT_NO_EMPTY);
        return array_values(array_unique(array_filter(array_map([$this, 'normalizeDomain'], $arr))));
    }

    private function renderLogin() {
        header('Content-Type: text/html; charset=UTF-8');
        echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Login</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{margin:0;background:#020617;color:#e5e7eb;font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh}.card{background:#020617;border:1px solid #1f2937;border-radius:.75rem;padding:2rem;width:100%;max-width:360px;box-shadow:0 20px 40px rgba(0,0,0,.5)}.btn{width:100%;padding:.75rem;border-radius:.5rem;border:none;background:#6366f1;color:#fff;font-weight:600;cursor:pointer;margin-top:1rem}.input{width:100%;padding:.75rem;border-radius:.5rem;border:1px solid #374151;background:#020617;color:#fff;box-sizing:border-box}</style></head><body><div class="card"><h3>L1mk Deployer</h3><p style="color:#9ca3af;font-size:.9rem">Enter license key to continue.</p><form method="post"><input name="license" class="input" placeholder="License Key" required><button class="btn">Unlock</button></form></div></body></html>';
    }

    private function renderDashboard() {
        header('Content-Type: text/html; charset=UTF-8');
        $lic = htmlspecialchars($this->currentLicense);
        
        ?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>L1mk Deployer</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        mono: ['"JetBrains Mono"', 'monospace'],
                        sans: ['Inter', 'sans-serif']
                    },
                    colors: {
                        brand: {
                            500: '#3b82f6', // More standard blue
                            600: '#2563eb',
                            900: '#1e3a8a',
                        },
                        slate: {
                            850: '#151f32', // Custom dark
                            950: '#020617',
                        }
                    }
                }
            }
        }
    </script>
    <style type="text/tailwindcss">
        .custom-scrollbar::-webkit-scrollbar { width: 6px; height: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #475569; }
        .glass { background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(10px); }
        /* .btn-icon { @apply p-2 rounded-lg hover:bg-white/5 text-slate-400 hover:text-white transition-colors; } */
    </style>
</head>
<body class="h-screen flex overflow-hidden bg-slate-950 text-slate-200 font-sans selection:bg-brand-500/30">

    <!-- Sidebar -->
    <aside class="w-72 bg-slate-900/50 border-r border-white/5 flex flex-col shrink-0 transition-all duration-300" id="sidebar">
        <div class="h-16 flex items-center px-4 border-b border-white/5 gap-3">
            <div class="w-8 h-8 rounded bg-brand-600 flex items-center justify-center font-bold text-white shadow-lg shadow-brand-500/20">L</div>
            <div class="flex flex-col">
                <span class="font-bold text-sm tracking-tight">ClosedPages</span>
                <span class="text-[10px] text-slate-500 font-mono uppercase tracking-wider">Deployer</span>
            </div>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-1" id="server-list">
            <!-- Server Items injected here -->
        </div>

        <div class="p-3 border-t border-white/5 bg-slate-900/30">
            <button onclick="showView('add-server')" class="w-full flex items-center justify-center gap-2 py-2.5 bg-brand-600 hover:bg-brand-500 text-white rounded-lg font-medium text-sm transition shadow-lg shadow-brand-500/10 group">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="group-hover:scale-110 transition-transform"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                <span>Add Server</span>
            </button>
        </div>
        
        <?php if ($lic): ?>
        <div class="px-4 py-2 text-[10px] text-slate-600 font-mono text-center border-t border-white/5">
            <?php echo $lic; ?> • <a href="?action=logout" class="hover:text-red-400">Logout</a>
        </div>
        <?php endif; ?>
    </aside>

    <!-- Main Content -->
    <main class="flex-1 flex flex-col min-w-0 bg-slate-950 relative">
        <!-- Top Bar -->
        <header class="h-16 flex items-center justify-between px-6 border-b border-white/5 bg-slate-950/80 backdrop-blur z-10">
            <div class="flex items-center gap-4">
                 <h2 id="page-title" class="text-lg font-semibold text-slate-100">Dashboard</h2>
            </div>
            <div class="flex items-center gap-3">
                <div id="connection-status" class="hidden text-xs px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Connected</div>
            </div>
        </header>

        <!-- Views Container -->
        <div class="flex-1 overflow-hidden relative">
            
            <!-- Welcome View -->
            <div id="view-home" class="absolute inset-0 p-8 flex flex-col items-center justify-center text-center opacity-100 transition-opacity duration-300">
                <div class="w-16 h-16 bg-slate-900 rounded-2xl flex items-center justify-center mb-6 border border-white/5">
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="text-slate-600"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
                </div>
                <h3 class="text-xl font-bold text-slate-200 mb-2">Select a Server</h3>
                <p class="text-slate-500 max-w-sm">Choose a server from the sidebar to manage deployments, or add a new VPS to get started.</p>
            </div>

            <!-- Add Server View -->
            <div id="view-add-server" class="hidden absolute inset-0 overflow-y-auto custom-scrollbar p-6">
                <div class="max-w-2xl mx-auto">
                    <h2 class="text-2xl font-bold mb-6">Connect New VPS</h2>
                    <form id="addServerForm" class="bg-slate-900/50 border border-white/5 p-6 rounded-xl space-y-5">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                            <div class="space-y-1.5">
                                <label class="text-xs font-bold text-slate-500 uppercase">IP Address</label>
                                <input type="text" name="host" required class="w-full bg-black/40 border border-slate-700 rounded-lg px-4 py-2.5 text-sm focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none transition-all" placeholder="1.2.3.4">
                            </div>
                            <div class="space-y-1.5">
                                <label class="text-xs font-bold text-slate-500 uppercase">SSH Port</label>
                                <input type="number" name="port" value="22" class="w-full bg-black/40 border border-slate-700 rounded-lg px-4 py-2.5 text-sm outline-none focus:border-brand-500 transition-all" placeholder="22">
                            </div>
                        </div>
                        
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                            <div class="space-y-1.5">
                                <label class="text-xs font-bold text-slate-500 uppercase">Username</label>
                                <input type="text" name="user" value="root" required class="w-full bg-black/40 border border-slate-700 rounded-lg px-4 py-2.5 text-sm outline-none focus:border-brand-500 transition-all" placeholder="root">
                            </div>
                            <div class="space-y-1.5">
                                <label class="text-xs font-bold text-slate-500 uppercase">Password</label>
                                <input type="password" name="password" required class="w-full bg-black/40 border border-slate-700 rounded-lg px-4 py-2.5 text-sm outline-none focus:border-brand-500 transition-all" placeholder="••••••••">
                            </div>
                        </div>

                        <div class="space-y-1.5">
                            <label class="text-xs font-bold text-slate-500 uppercase">Main Domain</label>
                            <input type="text" name="main_domain" class="w-full bg-black/40 border border-slate-700 rounded-lg px-4 py-2.5 text-sm outline-none focus:border-brand-500 transition-all" placeholder="example.com">
                        </div>

                        <div class="space-y-1.5">
                            <label class="text-xs font-bold text-slate-500 uppercase">Additional Domains</label>
                            <textarea name="domains" rows="3" class="w-full bg-black/40 border border-slate-700 rounded-lg px-4 py-2.5 text-sm outline-none focus:border-brand-500 transition-all" placeholder="one.com&#10;two.com"></textarea>
                        </div>
                        
                        <div class="flex items-center gap-3 p-3 bg-black/20 rounded-lg border border-white/5">
                            <input type="checkbox" name="wildcard_enabled" value="1" id="wildcard_new" class="w-4 h-4 rounded bg-slate-800 border-slate-600 text-brand-500 focus:ring-offset-0 focus:ring-0">
                            <label for="wildcard_new" class="text-sm text-slate-300 select-none">Enable Wildcard Subdomains (*.domain.com)</label>
                        </div>

                        <input type="hidden" name="rotation_enabled" value="1">
                        <input type="hidden" name="local_path" value="<?php echo htmlspecialchars(__DIR__); ?>">
                        <input type="hidden" name="path" value="/var/www/html">
                        <?php if ($lic): ?><input type="hidden" name="license_key" value="<?php echo $lic; ?>"><?php endif; ?>
                        
                        <div class="pt-2 flex gap-3">
                            <button type="button" onclick="showView('home')" class="flex-1 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-medium text-sm transition">Cancel</button>
                            <button type="submit" class="flex-[2] py-2.5 bg-brand-600 hover:bg-brand-500 text-white rounded-lg font-bold text-sm transition shadow-lg shadow-brand-500/20">Connect & Add Server</button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Deploy View -->
            <div id="view-deploy" class="hidden absolute inset-0 flex flex-col lg:flex-row">
                
                <!-- Left Panel: Config -->
                <div class="w-full lg:w-[400px] xl:w-[450px] border-b lg:border-b-0 lg:border-r border-white/5 bg-slate-900/30 flex flex-col overflow-y-auto custom-scrollbar">
                    <form id="deployForm" class="flex-1 flex flex-col p-6 space-y-6">
                        <input type="hidden" name="server_id" id="deploy_server_id">
                        <?php if ($lic): ?><input type="hidden" name="license_key" value="<?php echo $lic; ?>"><?php endif; ?>

                        <!-- Connection Info Group -->
                        <div class="space-y-4">
                            <div class="flex items-center justify-between">
                                <h3 class="text-sm font-bold text-slate-400 uppercase tracking-wider">Connection</h3>
                                <button type="button" id="testBtn" class="text-[10px] bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded text-slate-400 border border-slate-700">Test Ping</button>
                            </div>
                            <div class="grid grid-cols-1 gap-3">
                                <div class="relative">
                                    <span class="absolute left-3 top-2.5 text-slate-600"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg></span>
                                    <input type="text" name="host" id="deploy_host" class="w-full pl-9 bg-black/40 border border-slate-700 rounded-md py-2 text-xs text-slate-300 font-mono" placeholder="Host">
                                </div>
                                <div class="grid grid-cols-2 gap-3">
                                    <input type="text" name="user" id="deploy_user" class="bg-black/40 border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-300 font-mono" placeholder="User">
                                    <input type="password" name="password" id="deploy_password" class="bg-black/40 border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-300 font-mono" placeholder="Password">
                                </div>
                            </div>
                            <input type="hidden" name="port" id="deploy_port" value="22">
                        </div>

                        <hr class="border-white/5">

                        <!-- Domains Group -->
                        <div class="space-y-4">
                            <h3 class="text-sm font-bold text-slate-400 uppercase tracking-wider">Domains</h3>
                            <div class="space-y-3">
                                <div>
                                    <label class="text-[10px] text-slate-500 mb-1 block">Main Domain</label>
                                    <input type="text" name="main_domain" id="deploy_main_domain" class="w-full bg-black/40 border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-300 font-mono focus:border-brand-500 outline-none">
                                </div>
                                
                                <div>
                                    <label class="text-[10px] text-slate-500 mb-1 block">Additional Domains</label>
                                    <textarea name="domains" id="deploy_domains" class="hidden"></textarea>
                                    <div class="flex gap-2 mb-2">
                                        <input id="new_domain_input" class="flex-1 bg-black/40 border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-300 font-mono" placeholder="Add domain..." onkeydown="if(event.key==='Enter'){event.preventDefault();addDomainPill()}">
                                        <button type="button" onclick="addDomainPill()" class="px-3 bg-slate-800 hover:bg-slate-700 rounded-md border border-slate-700 text-slate-300 transition">+</button>
                                    </div>
                                    <div id="domain_pills" class="flex flex-wrap gap-1.5 min-h-[30px]"></div>
                                </div>

                                <div class="flex items-center gap-2">
                                    <input type="checkbox" name="wildcard_enabled" id="deploy_wildcard_enabled" value="1" class="rounded bg-slate-800 border-slate-600 text-brand-500">
                                    <label for="deploy_wildcard_enabled" class="text-xs text-slate-400">Enable Wildcard (*.domain)</label>
                                </div>
                            </div>
                        </div>

                        <!-- Status Group -->
                        <div class="bg-black/20 rounded-lg p-3 border border-white/5 space-y-2">
                            <div class="flex items-center justify-between">
                                <span class="text-[10px] font-bold text-slate-500 uppercase">Live Status</span>
                                <button type="button" id="checkStatusBtn" class="text-[10px] text-brand-400 hover:text-brand-300">Refresh</button>
                            </div>
                            <div id="deployActiveDomains" class="flex flex-wrap gap-1.5 min-h-[20px] text-xs text-slate-500 italic">
                                Ready to check
                            </div>
                        </div>

                        <input type="hidden" name="local_path" id="deploy_local_path" value="<?php echo htmlspecialchars(__DIR__); ?>">
                        <input type="hidden" name="path" value="/var/www/html">

                        <!-- Actions -->
                        <div class="pt-4 mt-auto space-y-3">
                            <button type="submit" id="deployBtn" class="w-full py-3 bg-brand-600 hover:bg-brand-500 text-white rounded-lg font-bold text-sm shadow-lg shadow-brand-500/20 transition-all active:scale-[0.98]">
                                🚀 Full Deploy
                            </button>
                            
                            <div class="grid grid-cols-2 gap-2">
                                <button type="button" id="updateCodeBtn" class="py-2 bg-slate-800 hover:bg-slate-700 text-blue-300 border border-blue-500/20 rounded-lg text-xs font-medium transition">
                                    Update Code Only
                                </button>
                                <button type="button" id="applyDomainsBtn" class="py-2 bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-emerald-500/20 rounded-lg text-xs font-medium transition">
                                    Update Domains
                                </button>
                            </div>

                            <div class="grid grid-cols-2 gap-2 pt-2">
                                <button type="button" id="toolSslBtn" class="py-1.5 bg-slate-900/50 hover:bg-slate-800 text-purple-300 border border-purple-500/20 rounded text-[10px] transition">
                                    🔒 SSL Certs
                                </button>
                                <button type="button" id="removeDomainsBtn" class="py-1.5 bg-slate-900/50 hover:bg-slate-800 text-orange-300 border border-orange-500/20 rounded text-[10px] transition">
                                    🧹 Clean Nginx
                                </button>
                            </div>
                            
                            <div class="flex justify-between pt-2 border-t border-white/5">
                                <button type="button" id="saveBtn" class="text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg>
                                    Save Config
                                </button>
                                <button type="button" id="adminPanelBtn" class="text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1">
                                    Open Admin
                                    <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                                </button>
                            </div>
                        </div>
                    </form>
                </div>

                <!-- Right Panel: Logs -->
                <div class="flex-1 flex flex-col bg-black/50 min-h-0">
                    <!-- Terminal Tabs/Header -->
                    <div class="h-10 flex items-center justify-between px-4 bg-black/40 border-b border-white/5">
                        <div class="flex gap-4 text-xs font-mono">
                            <button id="tab-deploy" onclick="switchTerminalTab('deploy')" class="text-slate-300 font-bold border-b-2 border-brand-500 py-2.5 transition-colors">Deployment Log</button>
                            <button id="tab-logs" onclick="switchTerminalTab('logs')" class="text-slate-600 py-2.5 hover:text-slate-400 transition-colors">Application Logs</button>
                        </div>
                        <div class="flex items-center gap-2">
                             <span id="term-status" class="text-[10px] text-emerald-500 flex items-center gap-1.5">
                                <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> Ready
                             </span>
                             <div class="h-4 w-px bg-white/10 mx-1"></div>
                             <button type="button" id="viewLogsBtn" class="text-[10px] text-slate-400 hover:text-white flex items-center gap-1">
                                <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                                Fetch Logs
                             </button>
                             <button type="button" id="verifyStructBtn" class="text-[10px] text-slate-400 hover:text-white">Verify Files</button>
                             <button type="button" id="copyLogsBtn" class="text-[10px] text-slate-400 hover:text-white">Copy</button>
                        </div>
                    </div>

                    <!-- Terminal Output -->
                    <div class="flex-1 p-0 overflow-hidden relative group flex flex-col">
                        <!-- Primary Terminal -->
                        <div id="terminal" class="custom-scrollbar flex-1 w-full p-4 overflow-y-auto font-mono text-xs text-slate-300 space-y-1 pb-10 selection:bg-brand-500/40">
                            <div class="text-slate-600 italic">Select a server and action to start...</div>
                        </div>
                        
                        <!-- Log View (Tabbed) -->
                        <div id="log-terminal-container" class="absolute inset-0 bg-slate-900/90 hidden flex flex-col z-10 w-full h-full">
                             <div class="px-3 py-1 bg-black/40 text-[10px] text-slate-500 font-mono border-b border-white/5 flex justify-between shrink-0">
                                <span>REMOTE LOGS</span>
                             </div>
                             <div id="log-terminal" class="custom-scrollbar flex-1 p-3 overflow-y-auto font-mono text-[11px] text-slate-400 whitespace-pre-wrap break-all w-full"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        let servers = [];
        let logStreamTimer = null;
        let activeServerId = null;

        function switchTerminalTab(tab) {
            const term = document.getElementById('terminal');
            const logContainer = document.getElementById('log-terminal-container');
            const tabDeploy = document.getElementById('tab-deploy');
            const tabLogs = document.getElementById('tab-logs');

            if (tab === 'deploy') {
                term.classList.remove('hidden');
                logContainer.classList.add('hidden');
                
                // Style: Active Deploy
                tabDeploy.className = 'text-slate-300 font-bold border-b-2 border-brand-500 py-2.5 transition-colors';
                tabLogs.className = 'text-slate-600 py-2.5 hover:text-slate-400 transition-colors';
            } else {
                term.classList.add('hidden');
                logContainer.classList.remove('hidden');
                
                // Style: Active Logs
                tabLogs.className = 'text-slate-300 font-bold border-b-2 border-brand-500 py-2.5 transition-colors';
                tabDeploy.className = 'text-slate-600 py-2.5 hover:text-slate-400 transition-colors';
                
                // Trigger fetch if empty or just because
                refreshLogs();
                startLogStream();
            }
        }

        async function loadServers() {
            try {
                const res = await fetch('?action=get_servers', { method: 'POST' });
                const json = await res.json();
                if(json.status === 'success') {
                    servers = json.servers || [];
                    renderServerList();
                }
            } catch(e) {}
        }

        function showView(id) {
            document.querySelectorAll('[id^="view-"]').forEach(el => el.classList.add('hidden'));
            const view = document.getElementById('view-' + id);
            if(view) view.classList.remove('hidden');
            
            if(id === 'home') {
                document.getElementById('page-title').textContent = 'Dashboard';
                activeServerId = null;
                updateSidebarActiveState();
            } else if (id === 'add-server') {
                document.getElementById('page-title').textContent = 'Add Server';
                activeServerId = null;
                updateSidebarActiveState();
            }
            // renderServerList is called by loadServers or manually if needed, but loadServers is better
        }

        function updateSidebarActiveState() {
            document.querySelectorAll('.server-item').forEach(el => {
                el.classList.remove('bg-brand-600', 'text-white', 'shadow-md');
                el.classList.add('text-slate-400', 'hover:bg-white/5', 'hover:text-slate-200');
                if(el.dataset.id === activeServerId) {
                    el.classList.remove('text-slate-400', 'hover:bg-white/5', 'hover:text-slate-200');
                    el.classList.add('bg-brand-600', 'text-white', 'shadow-md');
                }
            });
        }

        function renderServerList() {
            const list = document.getElementById('server-list');
            list.innerHTML = '';
            
            if(servers.length === 0) {
                list.innerHTML = '<div class="text-center py-8 px-2 text-xs text-slate-600">No servers yet.<br>Click "Add Server"</div>';
                return;
            }

            servers.forEach((s) => {
                const el = document.createElement('div');
                // Styling for sidebar item
                const isActive = s.id === activeServerId;
                const baseClasses = 'server-item cursor-pointer rounded-lg px-3 py-2.5 mb-1 transition-all group flex items-center justify-between';
                const activeClasses = isActive ? 'bg-brand-600 text-white shadow-md' : 'text-slate-400 hover:bg-white/5 hover:text-slate-200';
                
                el.className = `${baseClasses} ${activeClasses}`;
                el.dataset.id = s.id;
                el.onclick = () => openDeploy(s.id);
                
                el.innerHTML = `
                    <div class="flex flex-col overflow-hidden">
                        <span class="font-medium text-xs truncate font-mono">${s.host}</span>
                        <span class="text-[10px] opacity-60 truncate">${s.main_domain || 'No domain'}</span>
                    </div>
                    <button onclick="event.stopPropagation(); deleteServer('${s.id}')" class="opacity-0 group-hover:opacity-100 p-1 hover:bg-red-500/20 hover:text-red-400 rounded transition">
                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                    </button>
                `;
                list.appendChild(el);
            });
        }

        function openDeploy(id) {
            const s = servers.find(x => x.id === id);
            if (!s) return;
            
            activeServerId = id;
            updateSidebarActiveState();

            // Populate basic fields
            document.getElementById('deploy_server_id').value = s.id || '';
            document.getElementById('deploy_host').value = s.host || '';
            document.getElementById('deploy_user').value = s.user || 'root';
            document.getElementById('deploy_port').value = s.port || 22;
            document.getElementById('deploy_password').value = s.password || '';
            document.getElementById('deploy_main_domain').value = s.main_domain || '';
            document.getElementById('deploy_wildcard_enabled').checked = !!s.wildcard_enabled;
            
            // Populate domains
            const dArea = document.getElementById('deploy_domains');
            let dList = s.domains || [];
            if (typeof dList === 'string') dList = [dList];
            if (dArea) dArea.value = Array.isArray(dList) ? dList.join('\n') : '';
            renderPills();
            
            document.getElementById('page-title').textContent = s.host;
            
            // Reset UI states
            document.getElementById('terminal').innerHTML = '<div class="text-slate-600 italic mt-2">Ready to deploy to ' + s.host + '</div>';
            document.getElementById('log-terminal').textContent = '';
            document.getElementById('log-terminal-container').classList.add('hidden');
            document.getElementById('deployActiveDomains').innerHTML = 'Ready to check';
            
            showView('deploy');
            
            // Auto check
            if (typeof checkDomainStatusAuto === 'function') {
                checkDomainStatusAuto();
            }
        }

        function renderPills() {
            const dArea = document.getElementById('deploy_domains');
            const pills = document.getElementById('domain_pills');
            const arr = dArea.value.split('\n').filter(x => x.trim());
            pills.innerHTML = '';
            arr.forEach(d => {
                const p = document.createElement('span');
                p.className = 'px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-[10px] flex items-center gap-1 text-slate-300';
                p.innerHTML = `${d} <button type="button" onclick="removeDomain('${d}')" class="hover:text-red-400 ml-1">×</button>`;
                pills.appendChild(p);
            });
        }

        function addDomainPill() {
            const inp = document.getElementById('new_domain_input');
            const val = inp.value.trim();
            if(!val) return;
            const dArea = document.getElementById('deploy_domains');
            const arr = dArea.value.split('\n').filter(x => x.trim());
            if(!arr.includes(val)) {
                arr.push(val);
                dArea.value = arr.join('\n');
                renderPills();
            }
            inp.value = '';
        }

        window.removeDomain = (d) => {
            const dArea = document.getElementById('deploy_domains');
            const arr = dArea.value.split('\n').filter(x => x.trim());
            dArea.value = arr.filter(x => x !== d).join('\n');
            renderPills();
        };

        // Form Handlers
        const api = async (action, body) => {
            const fd = new FormData();
            for(const k in body) fd.append(k, body[k]);
            const res = await fetch('?action=' + action, { method: 'POST', body: fd });
            return res.json();
        };

        document.getElementById('addServerForm').onsubmit = async (e) => {
            e.preventDefault();
            const fd = new FormData(e.target);
            const btn = e.target.querySelector('button[type="submit"]');
            const origText = btn.textContent;
            btn.textContent = 'Connecting...';
            btn.disabled = true;
            
            try {
                const res = await fetch('?action=add_server', { method: 'POST', body: fd });
                const json = await res.json();
                if(json.status === 'success') {
                    await loadServers();
                    e.target.reset();
                    if(json.server && json.server.id) openDeploy(json.server.id);
                } else {
                    alert(json.message);
                }
            } catch(e) { alert('Error connecting'); }
            
            btn.textContent = origText;
            btn.disabled = false;
        };

        window.deleteServer = async (id) => {
            if(!confirm('Delete this server config?')) return;
            await api('delete_server', { server_id: id });
            await loadServers();
            if(activeServerId === id) showView('home');
        };

        document.getElementById('saveBtn').onclick = async () => {
            const form = document.getElementById('deployForm');
            const fd = new FormData(form);
            const res = await fetch('?action=save_server', { method: 'POST', body: fd });
            const json = await res.json();
            if(json.status === 'success') {
                // Flash success
                const btn = document.getElementById('saveBtn');
                const originalHTML = btn.innerHTML;
                btn.innerHTML = '<span class="text-emerald-400">Saved!</span>';
                setTimeout(() => btn.innerHTML = originalHTML, 1500);

                await loadServers();
                const id = fd.get('server_id');
                const s = servers.find(x => x.id === id);
                if(s) {
                    // Update UI with latest from server state if needed, but loadServers handles it
                    // Maybe just re-open? No, openDeploy might reset UI state. 
                    // Just updating list in background is enough.
                    renderServerList();
                }
            }
        };

        document.getElementById('adminPanelBtn').onclick = () => {
            const form = document.getElementById('deployForm');
            if (!form) return;
            const fd = new FormData(form);
            let target = (fd.get('main_domain') || fd.get('host') || '').toString().trim();
            if (!target) return;
            target = target.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
            const url = 'http://' + target + '/admin.html';
            window.open(url, '_blank');
        };

        // Terminal & SSE
        const term = document.getElementById('terminal');
        const logTerm = document.getElementById('log-terminal');
        const copyLogsBtn = document.getElementById('copyLogsBtn');
        
        const log = (msg, type='info') => {
            if (!term) return;
            const div = document.createElement('div');
            div.className = type === 'error' ? 'text-red-400 bg-red-900/10 px-2 py-0.5 rounded border-l-2 border-red-500' : (type === 'success' ? 'text-emerald-400' : 'text-slate-300');
            div.innerHTML = `<span class="opacity-50 select-none mr-2">$</span>${msg}`;
            term.appendChild(div);
            // Auto-scroll
            requestAnimationFrame(() => {
                term.scrollTop = term.scrollHeight;
            });
        };

        if (copyLogsBtn && logTerm) {
            copyLogsBtn.addEventListener('click', async () => {
                const text = logTerm.textContent || '';
                if (!text) return;
                try {
                    await navigator.clipboard.writeText(text);
                    const original = copyLogsBtn.textContent;
                    copyLogsBtn.textContent = 'Copied!';
                    setTimeout(() => copyLogsBtn.textContent = original, 1000);
                } catch (e) {}
            });
        }

        const refreshLogs = async () => {
            if (!logTerm) return;
            const form = document.getElementById('deployForm');
            if (!form) return;
            const fd = new FormData(form);
            try {
                const res = await fetch('?action=view_logs', { method: 'POST', body: fd });
                const json = await res.json();
                if (json.logs) {
                    // Check if we are near bottom BEFORE updating
                    const isAtBottom = (logTerm.scrollHeight - logTerm.scrollTop - logTerm.clientHeight) < 100;
                    
                    logTerm.textContent = json.logs;
                    
                    // Auto-scroll if already at bottom or if empty
                    if (isAtBottom || logTerm.textContent.length < 500) {
                        requestAnimationFrame(() => {
                            logTerm.scrollTop = logTerm.scrollHeight;
                        });
                    }
                }
            } catch (e) {}
        };

        const startLogStream = () => {
            if (logStreamTimer) clearInterval(logStreamTimer);
            refreshLogs();
            logStreamTimer = setInterval(refreshLogs, 4000);
        };

        const runSse = async (action, extra={}, clearTerm=true) => {
            const form = document.getElementById('deployForm');
            const fd = new FormData(form);
            for(const k in extra) fd.append(k, extra[k]);
            
            if(clearTerm) term.innerHTML = '';
            log(`Starting ${action}...`);
            document.getElementById('term-status').innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-yellow-400 animate-pulse"></span> Working...';
            
            try {
                const res = await fetch('?action=' + action, { method: 'POST', body: fd });
                const reader = res.body.getReader();
                const decoder = new TextDecoder();
                while(true) {
                    const {done, value} = await reader.read();
                    if(done) break;
                    const chunk = decoder.decode(value);
                    const lines = chunk.split('\n\n');
                    lines.forEach(line => {
                        if(line.startsWith('data: ')) {
                            try {
                                const data = JSON.parse(line.substring(6));
                                log(data.message, data.type);
                            } catch(e) {}
                        }
                    });
                }
                document.getElementById('term-status').innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Done';
                return true;
            } catch(e) {
                 log(e.message, 'error');
                 document.getElementById('term-status').innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-red-500"></span> Error';
                 return false;
            }
        };

        const deployActiveDomains = document.getElementById('deployActiveDomains');

        const renderStatusMessage = (text) => {
            if (!deployActiveDomains) return;
            deployActiveDomains.innerHTML = '';
            const span = document.createElement('span');
            span.className = 'text-[10px] text-slate-500';
            span.textContent = text;
            deployActiveDomains.appendChild(span);
        };

        const renderDomainStatusPill = (status) => {
            if (!deployActiveDomains) return;
            const pill = document.createElement('div');
            const isLive = !!status.live;
            const isLocal = !!status.local_live;
            const matchesHost = !!status.matches_host;

            let colorClass = 'bg-red-900/20 border-red-900/30 text-red-300';
            if (isLive) {
                colorClass = 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300';
            } else if (isLocal) {
                colorClass = 'bg-yellow-500/10 border-yellow-500/30 text-yellow-300';
            }

            pill.className = `px-1.5 py-0.5 border text-[10px] rounded ${colorClass} flex items-center gap-1`;

            const code = status.https_code || status.http_code || status.local_code;
            const ip = status.dns_ip || '';
            let extra = '';
            if (!matchesHost && ip) extra += ' (DNS≠Host)';
            
            pill.textContent = code ? `${status.domain} (${code})${extra}` : `${status.domain}${extra}`;
            deployActiveDomains.appendChild(pill);
        };

        const checkDomainStatusAuto = async () => {
            const form = document.getElementById('deployForm');
            const btn = document.getElementById('checkStatusBtn');
            if (!form || !deployActiveDomains) return;
            if (btn) {
                btn.disabled = true;
                btn.classList.add('opacity-50', 'cursor-not-allowed');
                btn.textContent = 'Checking...';
            }
            renderStatusMessage('Checking...');
            const fd = new FormData(form);
            try {
                const res = await fetch('?action=domain_status', { method: 'POST', body: fd });
                const json = await res.json();
                if (json.status !== 'success') {
                    renderStatusMessage(json.message || 'Failed');
                    return;
                }
                const items = Array.isArray(json.statuses) ? json.statuses : [];
                deployActiveDomains.innerHTML = '';
                if (items.length === 0) {
                    renderStatusMessage('None');
                    return;
                }
                items.forEach(renderDomainStatusPill);
            } catch (e) {
                renderStatusMessage('Request failed');
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.classList.remove('opacity-50', 'cursor-not-allowed');
                    btn.textContent = 'Refresh';
                }
            }
        };

        document.getElementById('checkStatusBtn').onclick = () => { checkDomainStatusAuto(); };
        document.getElementById('deployBtn').onclick = async (e) => { 
            e.preventDefault();
            if(!confirm('This will CLEAN/UNINSTALL the remote server first, then DEPLOY fresh. Continue?')) return;
            
            const btn = document.getElementById('deployBtn');
            const orig = btn.innerHTML;
            btn.disabled = true;
            btn.classList.add('opacity-50', 'cursor-not-allowed');
            btn.innerHTML = '🧹 Uninstalling...';
            
            const uninstallOk = await runSse('delete_uninstall', {}, true);
            
            if (uninstallOk) {
                btn.innerHTML = '🚀 Deploying...';
                log('--- Uninstall Complete. Starting Deployment ---', 'success');
                await new Promise(r => setTimeout(r, 1000));
                await runSse('deploy', {}, false);
            } else {
                log('Uninstall phase failed. Stopping.', 'error');
            }
            
            btn.disabled = false;
            btn.classList.remove('opacity-50', 'cursor-not-allowed');
            btn.innerHTML = orig;
        };
        document.getElementById('updateCodeBtn').onclick = () => runSse('update_code');
        document.getElementById('applyDomainsBtn').onclick = () => runSse('apply_domains');
        document.getElementById('testBtn').onclick = async () => {
             const btn = document.getElementById('testBtn');
             btn.textContent = '...';
             const fd = new FormData(document.getElementById('deployForm'));
             const res = await fetch('?action=test_connection', { method: 'POST', body: fd });
             const json = await res.json();
             log(json.message, json.status);
             btn.textContent = 'Test Ping';
        };
        document.getElementById('toolSslBtn').onclick = () => runSse('ssl');
        document.getElementById('removeDomainsBtn').onclick = () => runSse('remove_domains_only');
        document.getElementById('verifyStructBtn').onclick = () => runSse('verify_structure');
        document.getElementById('viewLogsBtn').onclick = async () => {
             switchTerminalTab('logs');
        };
        
        const installBtn = document.getElementById('installChromeBtn');
        if (installBtn) installBtn.onclick = () => runSse('puppeteer_install');

        loadServers().then(() => showView('home'));
    </script>
</body>
</html>
        <?php
    }
}

if (realpath(__FILE__) === realpath($_SERVER['SCRIPT_FILENAME'])) {
    (new Deployer())->run();
}
