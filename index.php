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
        $jsonActions = ['add_server', 'delete_server', 'save_server', 'test_connection', 'list_domains', 'list_managed_domains', 'domain_status'];
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
                case 'test_connection':
                    $this->connectSsh($host, $port, $user, $password); // Will throw if fails
                    $this->jsonResponse('success', 'Connection successful!');
                    break;
                case 'view_logs':
                    $this->apiViewLogs($host, $port, $user, $password, $path);
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
            $cmd .= " && printf '=== $log ===\\n' && if [ -f $log ]; then tail -n 200 $log; else echo '$log not found'; fi && printf '\\n'";
        }
        $cmd .= " && printf '=== Processes ===\\n' && (ps aux | grep 'php index.php worker' | grep -v grep || echo 'php index.php worker not running') && (ps aux | grep 'node consolidated.js' | grep -v grep || echo 'node consolidated.js not running') && printf '\\n'";
        $cmd .= " && printf '=== Disk Usage (project) ===\\n' && (du -sh . 2>/dev/null || echo 'du not available') && printf '\\n'";
        $output = (string)$ssh->exec($sudo . "sh -lc " . escapeshellarg($cmd));
        $this->jsonResponse('success', '', ['logs' => $output]);
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
        } catch (Exception $e) {}

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
                "touch " . escapeshellarg($path) . "/deploy.log " . escapeshellarg($path) . "/puppeteer.log " . escapeshellarg($path) . "/worker.log " . escapeshellarg($path) . "/project.log",
                "echo \"--- Deploy Start: $(date) ---\" >> " . escapeshellarg($path) . "/deploy.log",
                "echo \"--- Deploy Start: $(date) ---\" >> " . escapeshellarg($path) . "/project.log",
                "echo \"--- Puppeteer Log Init ---\" >> " . escapeshellarg($path) . "/puppeteer.log",
                "echo \"--- Puppeteer Log Init ---\" >> " . escapeshellarg($path) . "/project.log",
                "echo \"--- Worker Log Init ---\" >> " . escapeshellarg($path) . "/worker.log",
                "echo \"--- Worker Log Init ---\" >> " . escapeshellarg($path) . "/project.log",
                "chown -R www-data:www-data " . escapeshellarg($path),
                "chmod -R 755 " . escapeshellarg($path),
                "mkdir -p " . escapeshellarg($path) . "/session_data",
                "chmod -R 777 " . escapeshellarg($path) . "/session_data",
                "touch " . escapeshellarg($path) . "/database.sqlite && chown www-data:www-data " . escapeshellarg($path) . "/database.sqlite && chmod 666 " . escapeshellarg($path) . "/database.sqlite",
                "cd " . escapeshellarg($maPath) . " && if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 && [ -f package.json ]; then HOME=" . escapeshellarg($maPath) . " npm install --production || HOME=" . escapeshellarg($maPath) . " npm install; fi",
                "mkdir -p " . escapeshellarg($maPath . '/.cache/puppeteer') . " && cd " . escapeshellarg($maPath) . " && if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 && [ -f package.json ]; then HOME=" . escapeshellarg($maPath) . " PUPPETEER_CACHE_DIR=" . escapeshellarg($maPath . '/.cache/puppeteer') . " npx puppeteer browsers install chrome || true; fi"
            ];
            $ssh->exec($sudo . implode('; ', $commands));
            if (method_exists($ssh, 'disconnect')) $ssh->disconnect();

            $this->sseMessage("🔄 Restarting worker...");
            [$sshWorker, $sudoWorker] = $this->connectSsh($host, $port, $user, $password);
            $this->restartWorker($sshWorker, $sudoWorker, $path, $user);
            if (method_exists($sshWorker, 'disconnect')) $sshWorker->disconnect();

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
                "cd " . escapeshellarg($path) . " && unzip -o deploy_package.zip && rm deploy_package.zip",
                "cd " . escapeshellarg($path) . " && if [ ! -f config.json.enc ]; then cp config.example.json config.json.enc 2>/dev/null || true; fi",
                "echo " . escapeshellarg(base64_encode(json_encode(['main_domain' => $main_domain, 'rotation_path' => $rotation_path, 'rotation_slugs' => $rotation_slugs]))) . " | base64 -d > " . escapeshellarg($path) . "/deployment.json",
                "chmod 644 " . escapeshellarg($path) . "/deployment.json",
                "touch " . escapeshellarg($path) . "/deploy.log " . escapeshellarg($path) . "/puppeteer.log " . escapeshellarg($path) . "/worker.log " . escapeshellarg($path) . "/project.log",
                "echo \"--- Deploy Start: $(date) ---\" >> " . escapeshellarg($path) . "/deploy.log",
                "echo \"--- Deploy Start: $(date) ---\" >> " . escapeshellarg($path) . "/project.log",
                "echo \"--- Puppeteer Log Init ---\" >> " . escapeshellarg($path) . "/puppeteer.log",
                "echo \"--- Puppeteer Log Init ---\" >> " . escapeshellarg($path) . "/project.log",
                "echo \"--- Worker Log Init ---\" >> " . escapeshellarg($path) . "/worker.log",
                "echo \"--- Worker Log Init ---\" >> " . escapeshellarg($path) . "/project.log",
                "chown -R www-data:www-data " . escapeshellarg($path),
                "chmod -R 755 " . escapeshellarg($path),
                "mkdir -p " . escapeshellarg($path) . "/session_data && chmod -R 777 " . escapeshellarg($path) . "/session_data",
                "touch " . escapeshellarg($path) . "/database.sqlite && chown www-data:www-data " . escapeshellarg($path) . "/database.sqlite && chmod 666 " . escapeshellarg($path) . "/database.sqlite",
                "cd " . escapeshellarg($maPath) . " && if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 && [ -f package.json ]; then npm install --production || npm install; fi",
                "mkdir -p " . escapeshellarg($maPath . '/.cache/puppeteer') . " && cd " . escapeshellarg($maPath) . " && if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 && [ -f package.json ]; then PUPPETEER_CACHE_DIR=" . escapeshellarg($maPath . '/.cache/puppeteer') . " npx puppeteer browsers install chrome || true; fi"
            ];
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

            $this->sseMessage("⚙️ Configuring remote (nginx)...");
            [$sshNginx, $sudoNginx] = $this->connectSsh($host, $port, $user, $password);
            $this->applyNginxConfig($sshNginx, $sudoNginx, $main_domain, $domains, $path, $rotation_enabled, $wildcard_enabled, $rotation_path, $rotation_slugs);
            
            $checkUrl = "http://localhost" . ($rotation_enabled && $rotation_path ? "/$rotation_path/{$rotation_slugs[0]}" : "/");
            $this->sseMessage("⚙️ Configuring remote (health)...");
            [$sshHealth, $sudoHealth] = $this->connectSsh($host, $port, $user, $password);
            $httpCode = trim($sshHealth->exec("curl -s -o /dev/null -w '%{http_code}' " . escapeshellarg($checkUrl)));
            if ($httpCode >= 200 && $httpCode < 400) $this->sseMessage("✅ Health Check Passed ($httpCode)");
            else $this->sseMessage("⚠️ Health Check Warning ($httpCode)", 'warning');

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

    private function connectSsh($host, $port, $user, $password) {
        $ssh = new SSH2($host, $port);
        if (!$ssh->login($user, $password)) throw new Exception("SSH Login failed.");
        return [$ssh, ($user === 'root' ? '' : 'sudo ')];
    }

    private function restartWorker($ssh, $sudo, $path, $user) {
        $maPath = rtrim($path, '/');
        $base = "cd " . escapeshellarg($maPath) . " && $sudo pkill -f 'php index.php worker' || true;";
        $run = "cd " . escapeshellarg($maPath) . " && " . ($user === 'root' ? "" : "sudo -u www-data ") . "nohup php index.php worker > project.log 2>&1 < /dev/null & echo 'STARTED'";
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

    private function remoteLog($ssh, $sudo, $path, $msg) {
        $cmd = $sudo . "sh -lc " . escapeshellarg("cd " . $path . " && printf '[%s] %s\\n' " . date('c') . " " . escapeshellarg(substr($msg, 0, 1000)) . " | tee -a deploy.log project.log >/dev/null");
        try { $ssh->exec($cmd); } catch (Exception $e) {}
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
            } catch (Exception $e) {}
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
        $srvs = $this->serverConfig;
        if ($this->currentLicense && !$this->isMaster) {
            $srvs = array_values(array_filter($srvs, fn($s) => ($s['license_key'] ?? '') === $this->currentLicense));
        }
        $jsonSrvs = json_encode($srvs);
        $lic = htmlspecialchars($this->currentLicense);
        
        // Minified-ish HTML structure to save space but keep logic
        require __DIR__ . '/vendor/autoload.php'; // Ensure assets if any? No, we use CDN mostly.
        ?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>closedpages deployer</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <script>tailwind.config={darkMode:'class',theme:{extend:{fontFamily:{mono:['"JetBrains Mono"','monospace'],sans:['Inter','sans-serif']},colors:{brand:{500:'#0ea5e9',600:'#0284c7'}}}}}</script>
    <style>.custom-scrollbar::-webkit-scrollbar{width:6px;height:6px}.custom-scrollbar::-webkit-scrollbar-track{background:#0000}.custom-scrollbar::-webkit-scrollbar-thumb{background:#334155;border-radius:3px}</style>
</head>
<body class="min-h-screen flex flex-col bg-slate-950 text-slate-200 font-sans selection:bg-brand-500/30">
    <header class="border-b border-white/5 bg-black/20 backdrop-blur sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 h-14 flex items-center justify-between">
            <div class="flex items-center gap-3 cursor-pointer" onclick="showView('home')">
                <div class="w-8 h-8 rounded bg-brand-600 flex items-center justify-center font-bold text-white">L</div>
                <h1 class="font-bold">ClosedPages <span class="text-brand-500 font-mono">Deployer</span></h1>
            </div>
            <div class="text-xs font-mono text-slate-500">
                <?php echo $lic; ?>
                <?php if ($lic): ?>
                    <a href="?action=logout" class="ml-2 text-red-500 hover:underline">Logout</a>
                <?php endif; ?>
            </div>
        </div>
    </header>
    <main class="flex-1 max-w-7xl mx-auto w-full p-4">
        <div id="view-home" class="space-y-6">
            <div class="flex justify-between items-center">
                <h2 class="text-xl font-bold">Servers</h2>
                <button onclick="showView('add-server')" class="px-4 py-2 bg-brand-600 hover:bg-brand-500 text-white rounded-lg font-medium text-sm transition">Add VPS</button>
            </div>
            <div id="server-list" class="grid grid-cols-1 md:grid-cols-3 gap-4"></div>
        </div>

        <div id="view-add-server" class="hidden max-w-xl mx-auto">
            <h2 class="text-xl font-bold mb-6">Add New VPS</h2>
            <form id="addServerForm" class="space-y-4 bg-slate-900/50 p-6 rounded-xl border border-white/5">
                <input type="text" name="host" required class="w-full bg-black/20 border border-slate-700 rounded-lg px-4 py-2 text-sm focus:border-brand-500 outline-none" placeholder="IP Address">
                <div class="grid grid-cols-2 gap-4">
                    <input type="text" name="user" value="root" required class="w-full bg-black/20 border border-slate-700 rounded-lg px-4 py-2 text-sm outline-none" placeholder="User">
                    <input type="number" name="port" value="22" class="w-full bg-black/20 border border-slate-700 rounded-lg px-4 py-2 text-sm outline-none" placeholder="Port">
                </div>
                <input type="password" name="password" required class="w-full bg-black/20 border border-slate-700 rounded-lg px-4 py-2 text-sm outline-none" placeholder="SSH Password">
                <input type="text" name="main_domain" class="w-full bg-black/20 border border-slate-700 rounded-lg px-4 py-2 text-sm outline-none" placeholder="Main Domain">
                <textarea name="domains" rows="3" class="w-full bg-black/20 border border-slate-700 rounded-lg px-4 py-2 text-sm outline-none" placeholder="Additional Domains (one per line)"></textarea>
                
                <div class="flex items-center gap-2 text-sm text-slate-400">
                    <input type="checkbox" name="wildcard_enabled" value="1" class="rounded bg-black/20 border-slate-700 text-brand-500">
                    <label>Enable Wildcard (*.domain.com)</label>
                </div>
                <input type="hidden" name="rotation_enabled" value="1">
                <input type="hidden" name="local_path" value="<?php echo htmlspecialchars(__DIR__); ?>">
                <input type="hidden" name="path" value="/var/www/html">
                <?php if ($lic): ?><input type="hidden" name="license_key" value="<?php echo $lic; ?>"><?php endif; ?>
                
                <button type="submit" class="w-full py-2.5 bg-brand-600 hover:bg-brand-500 text-white rounded-lg font-bold text-sm">Connect & Add</button>
            </form>
            <button onclick="showView('home')" class="mt-4 text-sm text-slate-500 hover:text-white">Cancel</button>
        </div>

        <div id="view-deploy" class="hidden h-[calc(100vh-8rem)] flex flex-col lg:flex-row gap-4">
            <div class="w-full lg:w-1/3 flex flex-col gap-4">
                <button onclick="showView('home')" class="text-xs text-slate-500 hover:text-white self-start">← Back</button>
                <form id="deployForm" class="flex-1 flex flex-col bg-slate-900/50 border border-white/5 rounded-xl overflow-hidden">
                    <input type="hidden" name="server_id" id="deploy_server_id">
                    <?php if ($lic): ?><input type="hidden" name="license_key" value="<?php echo $lic; ?>"><?php endif; ?>
                    <div class="p-4 overflow-y-auto custom-scrollbar space-y-4 flex-1">
                        <div class="space-y-2">
                            <label class="text-xs font-bold text-slate-500 uppercase">Target</label>
                            <input type="text" name="host" id="deploy_host" class="w-full bg-black/20 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-300">
                            <div class="flex gap-2">
                                <input type="text" name="user" id="deploy_user" class="w-1/2 bg-black/20 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-300">
                                <input type="password" name="password" id="deploy_password" class="w-1/2 bg-black/20 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-300">
                            </div>
                            <input type="hidden" name="port" id="deploy_port" value="22">
                        </div>
                        <div class="space-y-2">
                            <label class="text-xs font-bold text-slate-500 uppercase">Domains</label>
                            <input type="text" name="main_domain" id="deploy_main_domain" class="w-full bg-black/20 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-300" placeholder="Main Domain">
                            <textarea name="domains" id="deploy_domains" class="hidden"></textarea>
                            <div class="flex gap-2">
                                <input id="new_domain_input" class="flex-1 bg-black/20 border border-slate-700 rounded px-2 py-1 text-xs" placeholder="Add domain...">
                                <button type="button" onclick="addDomainPill()" class="px-3 bg-slate-800 rounded border border-slate-700 text-xs">+</button>
                            </div>
                            <div id="domain_pills" class="flex flex-wrap gap-1"></div>
                            <label class="flex items-center gap-2 text-xs text-slate-400">
                                <input type="checkbox" name="wildcard_enabled" id="deploy_wildcard_enabled" value="1"> Wildcard
                            </label>
                            <div class="mt-3 space-y-1">
                                <div class="flex items-center justify-between">
                                    <span class="text-xs font-bold text-slate-500 uppercase">Domain Status</span>
                                    <button type="button" id="checkStatusBtn" class="px-2 py-0.5 border border-slate-700 rounded text-[10px] text-slate-400 hover:text-slate-100 hover:bg-slate-800">
                                        Refresh
                                    </button>
                                </div>
                                <div id="deployActiveDomains" class="flex flex-wrap gap-1 text-xs text-slate-400">
                                    <span class="text-slate-500">Not checked</span>
                                </div>
                            </div>
                        </div>
                        <input type="hidden" name="local_path" id="deploy_local_path" value="<?php echo htmlspecialchars(__DIR__); ?>">
                        <input type="hidden" name="path" value="/var/www/html">
                        
                        <div class="grid grid-cols-2 gap-2 pt-2">
                            <button type="button" id="testBtn" class="py-1 bg-slate-800 text-xs rounded border border-slate-700 text-slate-300">Test Conn</button>
                            <button type="button" id="toolSslBtn" class="py-1 bg-purple-900/20 text-xs rounded border border-purple-500/30 text-purple-300">SSL (Certbot)</button>
                            <button type="button" id="removeDomainsBtn" class="py-1 bg-orange-900/20 text-xs rounded border border-orange-500/30 text-orange-300">Clean Nginx</button>
                            <button type="button" id="deleteBtn" class="py-1 bg-red-900/20 text-xs rounded border border-red-500/30 text-red-300">Uninstall</button>
                        </div>
                        <button type="button" id="viewLogsBtn" class="w-full py-1 bg-slate-800 text-xs rounded border border-slate-700 text-slate-300">View Logs</button>
                  
                    <div class="p-1 border-t border-white/5 bg-black/20 space-y-2">
                        <button type="submit" id="deployBtn" class="w-full py-2 bg-brand-600 hover:bg-brand-500 text-white rounded font-bold text-sm">Full Deploy</button>
                        <div class="grid grid-cols-2 gap-2">
                            <button type="button" id="updateCodeBtn" class="py-1.5 bg-blue-600/80 hover:bg-blue-600 text-white rounded text-xs font-medium">Update Code</button>
                            <button type="button" id="applyDomainsBtn" class="py-1.5 bg-emerald-600/80 hover:bg-emerald-600 text-white rounded text-xs font-medium">Update Domains</button>
                        </div>
                        <div class="grid grid-cols-2 gap-2">
                            <button type="button" id="saveBtn" class="py-1.5 bg-slate-800 text-slate-300 rounded text-xs border border-slate-700">Save Config</button>
                            <button type="button" id="adminPanelBtn" class="py-1.5 bg-slate-900 text-slate-200 rounded text-xs border border-slate-600">Admin Panel</button>
                        </div>
                    </div>
                      </div>
                </form>
            </div>
            <div class="flex-1 flex flex-col gap-3">
                <div class="flex-1 flex flex-col bg-black rounded-xl border border-white/10 overflow-hidden font-mono text-xs">
                    <div class="px-3 py-2 bg-white/5 border-b border-white/5 text-slate-500 flex justify-between">
                        <span>Deploy Output</span>
                        <span id="term-status" class="text-emerald-500">Ready</span>
                    </div>
                    <div id="terminal" class="flex-1 p-4 overflow-y-auto text-slate-300 space-y-1"></div>
                </div>
                <div class="flex-1 flex flex-col bg-black rounded-xl border border-white/10 overflow-hidden font-mono text-xs">
                    <div class="px-3 py-2 bg-white/5 border-b border-white/5 text-slate-500 flex justify-between">
                        <span>Project Logs (View Only)</span>
                    </div>
                    <div id="log-terminal" class="flex-1 p-4 overflow-y-auto text-slate-300 whitespace-pre-wrap"></div>
                </div>
            </div>
        </div>
    </main>

    <script>
        const servers = <?php echo $jsonSrvs; ?>;
        let logStreamTimer = null;

        function showView(id) {
            document.querySelectorAll('[id^="view-"]').forEach(el => el.classList.add('hidden'));
            document.getElementById('view-' + id).classList.remove('hidden');
            if(id === 'home') renderServerList();
        }

        function renderServerList() {
            const list = document.getElementById('server-list');
            list.innerHTML = '';
            servers.forEach((s) => {
                const el = document.createElement('div');
                el.className = 'bg-slate-900/50 border border-white/10 p-4 rounded-xl hover:border-brand-500/50 cursor-pointer transition relative group';
                // Use setAttribute to ensure the click handler is explicitly attached and visible
                el.setAttribute('onclick', `openDeploy('${s.id}')`);
                el.innerHTML = `
                    <div class="flex justify-between mb-2">
                        <span class="font-bold text-white">${s.host}</span>
                        <button onclick="event.stopPropagation(); deleteServer('${s.id}')" class="text-slate-600 hover:text-red-500 z-10 relative">✕</button>
                    </div>
                    <div class="text-xs text-slate-500 mb-3">${s.user} @ :${s.port}</div>
                    <div class="flex flex-wrap gap-1">
                        ${s.main_domain ? `<span class="px-1.5 py-0.5 bg-blue-500/10 text-blue-400 text-[10px] rounded border border-blue-500/20">${s.main_domain}</span>` : ''}
                        ${(s.domains||[]).length > 0 ? `<span class="px-1.5 py-0.5 bg-slate-800 text-slate-400 text-[10px] rounded border border-slate-700">+${s.domains.length}</span>` : ''}
                    </div>
                `;
                list.appendChild(el);
            });
            if(servers.length === 0) list.innerHTML = '<div class="col-span-full text-center py-10 text-slate-500">No servers found.</div>';
        }

        function openDeploy(id) {
            const s = servers.find(x => x.id === id);
            if (!s) return;
            
            // Populate basic fields
            document.getElementById('deploy_server_id').value = s.id || '';
            document.getElementById('deploy_host').value = s.host || '';
            document.getElementById('deploy_user').value = s.user || root;
            document.getElementById('deploy_port').value = s.port || 22;
            document.getElementById('deploy_password').value = s.password || '';
            document.getElementById('deploy_main_domain').value = s.main_domain || '';
            document.getElementById('deploy_wildcard_enabled').checked = !!s.wildcard_enabled;
            
            // Populate domains
            const dArea = document.getElementById('deploy_domains');
            if (dArea) dArea.value = (s.domains || []).join('\n');
            renderPills();
            
            showView('deploy');
            startLogStream();
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
                p.className = 'px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-[10px] flex items-center gap-1';
                p.innerHTML = `${d} <button type="button" onclick="removeDomain('${d}')" class="hover:text-red-400">×</button>`;
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
            const res = await fetch('?action=add_server', { method: 'POST', body: fd });
            const json = await res.json();
            if(json.status === 'success') {
                servers.push(json.server);
                showView('home');
                e.target.reset();
            } else {
                alert(json.message);
            }
        };

        window.deleteServer = async (id) => {
            if(!confirm('Delete this server config?')) return;
            await api('delete_server', { server_id: id });
            const idx = servers.findIndex(s => s.id === id);
            if(idx > -1) servers.splice(idx, 1);
            renderServerList();
        };

        document.getElementById('saveBtn').onclick = async () => {
            const form = document.getElementById('deployForm');
            const fd = new FormData(form);
            const res = await fetch('?action=save_server', { method: 'POST', body: fd });
            const json = await res.json();
            if(json.status === 'success') {
                alert('Saved');
                const id = fd.get('server_id');
                const s = servers.find(x => x.id === id);
                if(s) {
                    s.host = fd.get('host'); s.user = fd.get('user'); s.password = fd.get('password');
                    s.main_domain = fd.get('main_domain');
                    s.domains = fd.get('domains').split('\n').filter(x=>x);
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
        const log = (msg, type='info') => {
            if (!term) return;
            const div = document.createElement('div');
            div.className = type === 'error' ? 'text-red-400' : (type === 'success' ? 'text-emerald-400' : 'text-slate-300');
            div.innerText = `> ${msg}`;
            term.appendChild(div);
            term.scrollTop = term.scrollHeight;
        };

        const refreshLogs = async () => {
            if (!logTerm) return;
            const form = document.getElementById('deployForm');
            if (!form) return;
            const fd = new FormData(form);
            try {
                const res = await fetch('?action=view_logs', { method: 'POST', body: fd });
                const json = await res.json();
                if (json.logs) {
                    logTerm.textContent = json.logs;
                    logTerm.scrollTop = logTerm.scrollHeight;
                }
            } catch (e) {
            }
        };

        const startLogStream = () => {
            if (logStreamTimer) clearInterval(logStreamTimer);
            refreshLogs();
            logStreamTimer = setInterval(refreshLogs, 4000);
        };

        const runSse = (action, extra={}) => {
            const form = document.getElementById('deployForm');
            const fd = new FormData(form);
            for(const k in extra) fd.append(k, extra[k]);
            
            // Convert FormData to query string for SSE url? No, usually SSE is GET. 
            // But we have logic in handleApi that checks POST. 
            // We need to use fetch/XHR for POST and read stream manually, or EventSource with GET parameters.
            // Our PHP expects POST for these actions. 
            
            term.innerHTML = '';
            log(`Starting ${action}...`);
            
            fetch('?action=' + action, { method: 'POST', body: fd }).then(async res => {
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
            });
        };

        const deployActiveDomains = document.getElementById('deployActiveDomains');

        const renderStatusMessage = (text) => {
            if (!deployActiveDomains) return;
            deployActiveDomains.innerHTML = '';
            const span = document.createElement('span');
            span.className = 'text-xs text-slate-500';
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

            pill.className = `px-2 py-1 border text-xs rounded ${colorClass}`;

            const code = status.https_code || status.http_code || status.local_code;
            const ip = status.dns_ip || '';
            let extra = '';
            if (!matchesHost && ip) extra += ' (DNS ≠ Host)';
            else if (ip) extra += ' (' + ip + ')';

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
                }
            }
        };

        document.getElementById('deployBtn').onclick = (e) => { e.preventDefault(); runSse('deploy'); };
        document.getElementById('updateCodeBtn').onclick = () => runSse('update_code');
        document.getElementById('applyDomainsBtn').onclick = () => runSse('apply_domains');
        document.getElementById('testBtn').onclick = async () => {
             const fd = new FormData(document.getElementById('deployForm'));
             const res = await fetch('?action=test_connection', { method: 'POST', body: fd });
             const json = await res.json();
             log(json.message, json.status);
        };
        document.getElementById('toolSslBtn').onclick = () => runSse('ssl');
        document.getElementById('removeDomainsBtn').onclick = () => runSse('remove_domains_only');
        document.getElementById('deleteBtn').onclick = () => { if(confirm('Uninstall everything from VPS?')) runSse('delete_uninstall'); };
        document.getElementById('viewLogsBtn').onclick = async () => {
             await refreshLogs();
             startLogStream();
        };

        renderServerList();
    </script>
</body>
</html>
        <?php
    }
}

if (realpath(__FILE__) === realpath($_SERVER['SCRIPT_FILENAME'])) {
    (new Deployer())->run();
}
