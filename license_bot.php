<?php

require_once __DIR__ . '/vendor/autoload.php';

use App\Crypto;

$config = [];
$configPath = __DIR__ . '/license_config.json.enc';
if (file_exists($configPath)) {
    $json = Crypto::loadEncrypted($configPath);
    if ($json) {
        $decoded = json_decode($json, true);
        if (is_array($decoded)) {
            $config = $decoded;
        }
    }
}

$botToken = $config['botToken'] ?? getenv('LICENSE_BOT_TOKEN') ?: '';
$adminChatId = (int)($config['adminChatId'] ?? getenv('LICENSE_ADMIN_CHAT_ID') ?: 0);
$btcAddress = $config['btcAddress'] ?? getenv('LICENSE_BTC_ADDRESS') ?: '';
$usdtAddress = $config['usdtAddress'] ?? getenv('LICENSE_USDT_ADDRESS') ?: '';
$dbFile = __DIR__ . '/license_bot.db';

if (!$botToken) {
    http_response_code(500);
    exit;
}

try {
    $pdo = new PDO('sqlite:' . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Throwable $e) {
    http_response_code(500);
    exit;
}

$pdo->exec("CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_chat_id INTEGER NOT NULL,
    username TEXT,
    plan_days INTEGER NOT NULL,
    price_usd INTEGER NOT NULL,
    payment_method TEXT NOT NULL,
    status TEXT NOT NULL,
    tx_proof TEXT,
    created_at TEXT NOT NULL,
    approved_at TEXT
)");

$pdo->exec("CREATE INDEX IF NOT EXISTS idx_invoices_user_status ON invoices(user_chat_id, status)");

$pdo->exec("CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT NOT NULL UNIQUE,
    user_chat_id INTEGER NOT NULL,
    username TEXT,
    plan_days INTEGER NOT NULL,
    price_usd INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    invoice_id INTEGER
)");

function tg_request($method, $params)
{
    global $botToken;
    $ch = curl_init('https://api.telegram.org/bot' . $botToken . '/' . $method);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    $res = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    $log = [
        'method' => $method,
        'params' => $params,
        'http_code' => $code,
        'error' => $err ?: null,
        'response' => $res ?: null,
        'time' => gmdate('c')
    ];
    @file_put_contents(__DIR__ . '/license_bot.log', json_encode($log, JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND);
    return $res;
}

function send_menu($chatId)
{
    $text = "Select license duration:\n\n10 days – \$130\n20 days – \$210\n30 days – \$300";
    $keyboard = [
        'inline_keyboard' => [
            [
                ['text' => '10 days ($130)', 'callback_data' => 'plan:10'],
            ],
            [
                ['text' => '20 days ($210)', 'callback_data' => 'plan:20'],
            ],
            [
                ['text' => '30 days ($300)', 'callback_data' => 'plan:30'],
            ],
        ],
    ];
    tg_request('sendMessage', [
        'chat_id' => $chatId,
        'text' => $text,
        'reply_markup' => json_encode($keyboard),
    ]);
}

function prices()
{
    return [
        10 => 130,
        20 => 210,
        30 => 300,
    ];
}

function handle_plan_selection($chatId, $days)
{
    $prices = prices();
    if (!isset($prices[$days])) {
        tg_request('sendMessage', [
            'chat_id' => $chatId,
            'text' => 'Invalid plan.',
        ]);
        return;
    }
    $price = $prices[$days];
    $text = "You selected a {$days}-day license for \${$price}.\n\nChoose payment method:";
    $keyboard = [
        'inline_keyboard' => [
            [
                ['text' => 'BTC', 'callback_data' => 'pay:' . $days . ':BTC'],
                ['text' => 'USDT', 'callback_data' => 'pay:' . $days . ':USDT'],
            ],
        ],
    ];
    tg_request('sendMessage', [
        'chat_id' => $chatId,
        'text' => $text,
        'reply_markup' => json_encode($keyboard),
    ]);
}

function create_invoice($chatId, $username, $days, $method)
{
    global $pdo, $btcAddress, $usdtAddress;
    $prices = prices();
    if (!isset($prices[$days])) {
        return null;
    }
    $price = $prices[$days];
    $createdAt = gmdate('c');
    $status = 'awaiting_proof';
    $stmt = $pdo->prepare('INSERT INTO invoices (user_chat_id, username, plan_days, price_usd, payment_method, status, created_at) VALUES (:user_chat_id, :username, :plan_days, :price_usd, :payment_method, :status, :created_at)');
    $stmt->execute([
        ':user_chat_id' => $chatId,
        ':username' => $username,
        ':plan_days' => $days,
        ':price_usd' => $price,
        ':payment_method' => $method,
        ':status' => $status,
        ':created_at' => $createdAt,
    ]);
    $invoiceId = (int)$pdo->lastInsertId();
    if ($method === 'BTC') {
        $payTo = $btcAddress;
    } else {
        $payTo = $usdtAddress;
    }
    $text = "Invoice #{$invoiceId}\n\nPlan: {$days} days\nPrice: \${$price}\nPayment Method: {$method}\n\nPay to this address:\n{$payTo}\n\nAfter payment, send the transaction hash or a screenshot here.";
    tg_request('sendMessage', [
        'chat_id' => $chatId,
        'text' => $text,
    ]);
    return $invoiceId;
}

function handle_payment_method($chatId, $from, $days, $method)
{
    $username = '';
    if (isset($from['username'])) {
        $username = $from['username'];
    } elseif (isset($from['first_name']) || isset($from['last_name'])) {
        $username = trim(($from['first_name'] ?? '') . ' ' . ($from['last_name'] ?? ''));
    }
    $method = strtoupper($method);
    if (!in_array($method, ['BTC', 'USDT'], true)) {
        tg_request('sendMessage', [
            'chat_id' => $chatId,
            'text' => 'Invalid payment method.',
        ]);
        return;
    }
    $invoiceId = create_invoice($chatId, $username, $days, $method);
    if ($invoiceId === null) {
        tg_request('sendMessage', [
            'chat_id' => $chatId,
            'text' => 'Could not create invoice.',
        ]);
    }
}

function get_pending_invoice_for_user($chatId)
{
    global $pdo;
    $stmt = $pdo->prepare('SELECT * FROM invoices WHERE user_chat_id = :user_chat_id AND status = :status ORDER BY id DESC LIMIT 1');
    $stmt->execute([
        ':user_chat_id' => $chatId,
        ':status' => 'awaiting_proof',
    ]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

function update_invoice_with_proof($invoiceId, $proof)
{
    global $pdo;
    $stmt = $pdo->prepare('UPDATE invoices SET tx_proof = :tx_proof, status = :status WHERE id = :id');
    $stmt->execute([
        ':tx_proof' => $proof,
        ':status' => 'pending_admin',
        ':id' => $invoiceId,
    ]);
}

function generate_license_key()
{
    $raw = strtoupper(bin2hex(random_bytes(16)));
    $parts = str_split($raw, 4);
    $parts = array_slice($parts, 0, 4);
    return implode('-', $parts);
}

function create_license_for_invoice($invoice)
{
    global $pdo;
    $userChatId = (int)$invoice['user_chat_id'];
    $username = $invoice['username'];
    $planDays = (int)$invoice['plan_days'];
    $priceUsd = (int)$invoice['price_usd'];
    $createdAt = gmdate('c');
    $expiresAt = gmdate('c', time() + $planDays * 86400);
    $status = 'active';
    do {
        $licenseKey = generate_license_key();
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM licenses WHERE license_key = :key');
        $stmt->execute([':key' => $licenseKey]);
        $exists = (int)$stmt->fetchColumn() > 0;
    } while ($exists);
    $stmt = $pdo->prepare('INSERT INTO licenses (license_key, user_chat_id, username, plan_days, price_usd, status, created_at, expires_at, invoice_id) VALUES (:license_key, :user_chat_id, :username, :plan_days, :price_usd, :status, :created_at, :expires_at, :invoice_id)');
    $stmt->execute([
        ':license_key' => $licenseKey,
        ':user_chat_id' => $userChatId,
        ':username' => $username,
        ':plan_days' => $planDays,
        ':price_usd' => $priceUsd,
        ':status' => $status,
        ':created_at' => $createdAt,
        ':expires_at' => $expiresAt,
        ':invoice_id' => $invoice['id'],
    ]);
    return $licenseKey;
}

function mark_invoice_status($invoiceId, $status)
{
    global $pdo;
    if ($status === 'approved') {
        $stmt = $pdo->prepare('UPDATE invoices SET status = :status, approved_at = :approved_at WHERE id = :id');
        $stmt->execute([
            ':status' => $status,
            ':approved_at' => gmdate('c'),
            ':id' => $invoiceId,
        ]);
    } else {
        $stmt = $pdo->prepare('UPDATE invoices SET status = :status WHERE id = :id');
        $stmt->execute([
            ':status' => $status,
            ':id' => $invoiceId,
        ]);
    }
}

function get_invoice_by_id($id)
{
    global $pdo;
    $stmt = $pdo->prepare('SELECT * FROM invoices WHERE id = :id');
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

function handle_user_payment_proof($message)
{
    global $adminChatId;
    $chatId = $message['chat']['id'];
    if ($chatId === $adminChatId) {
        return;
    }
    $invoice = get_pending_invoice_for_user($chatId);
    if (!$invoice) {
        tg_request('sendMessage', [
            'chat_id' => $chatId,
            'text' => 'No pending invoice found. Use /start to create one.',
        ]);
        return;
    }
    $proof = '';
    if (!empty($message['photo']) && is_array($message['photo'])) {
        $photos = $message['photo'];
        $last = end($photos);
        if (isset($last['file_id'])) {
            $proof = 'photo:' . $last['file_id'];
        }
    } elseif (!empty($message['text'])) {
        $text = trim($message['text']);
        if ($text !== '' && $text !== '/start') {
            $proof = $text;
        }
    }
    if ($proof === '') {
        tg_request('sendMessage', [
            'chat_id' => $chatId,
            'text' => 'Send the transaction hash or a screenshot as proof of payment.',
        ]);
        return;
    }
    update_invoice_with_proof($invoice['id'], $proof);
    tg_request('sendMessage', [
        'chat_id' => $chatId,
        'text' => 'Payment proof received. Waiting for admin approval.',
    ]);
    notify_admin_new_proof($invoice['id']);
}

function notify_admin_new_proof($invoiceId)
{
    global $adminChatId;
    $invoice = get_invoice_by_id($invoiceId);
    if (!$invoice) {
        return;
    }
    $caption = "New payment proof\n\nInvoice #" . $invoice['id'] .
        "\nUser: " . $invoice['user_chat_id'] .
        "\nPlan: " . $invoice['plan_days'] . " days" .
        "\nPrice: $" . $invoice['price_usd'] .
        "\nMethod: " . $invoice['payment_method'];
    $proof = $invoice['tx_proof'] ?? '';
    $keyboard = [
        'inline_keyboard' => [
            [
                ['text' => 'Approve', 'callback_data' => 'approve:' . $invoice['id']],
                ['text' => 'Reject', 'callback_data' => 'reject:' . $invoice['id']],
            ],
        ],
    ];
    if ($proof && str_starts_with($proof, 'photo:')) {
        $fileId = substr($proof, strlen('photo:'));
        tg_request('sendPhoto', [
            'chat_id' => $adminChatId,
            'photo' => $fileId,
            'caption' => $caption,
            'reply_markup' => json_encode($keyboard),
        ]);
    } else {
        if ($proof) {
            $caption .= "\n\nText proof:\n" . $proof;
        }
        tg_request('sendMessage', [
            'chat_id' => $adminChatId,
            'text' => $caption,
            'reply_markup' => json_encode($keyboard),
        ]);
    }
}

function handle_admin_decision($fromId, $data)
{
    global $adminChatId;
    if ($fromId !== $adminChatId) {
        return;
    }
    if (str_starts_with($data, 'approve:')) {
        $invoiceId = (int)substr($data, strlen('approve:'));
        $invoice = get_invoice_by_id($invoiceId);
        if (!$invoice || $invoice['status'] !== 'pending_admin') {
            tg_request('sendMessage', [
                'chat_id' => $adminChatId,
                'text' => 'Invoice not found or already processed.',
            ]);
            return;
        }
        $licenseKey = create_license_for_invoice($invoice);
        mark_invoice_status($invoiceId, 'approved');
        $expiresAt = $pdo = null;
        $expiresAt = $invoice['plan_days'] ? gmdate('c', time() + (int)$invoice['plan_days'] * 86400) : '';
        tg_request('sendMessage', [
            'chat_id' => $invoice['user_chat_id'],
            'text' => "Your license is approved.\n\nLicense: {$licenseKey}\nPlan: {$invoice['plan_days']} days\nPrice: \${$invoice['price_usd']}\nKeep this license safe. You will use it to access the admin panel.",
        ]);
        tg_request('sendMessage', [
            'chat_id' => $adminChatId,
            'text' => "Invoice #{$invoiceId} approved.\nLicense: {$licenseKey}\nUser: {$invoice['user_chat_id']}",
        ]);
    } elseif (str_starts_with($data, 'reject:')) {
        $invoiceId = (int)substr($data, strlen('reject:'));
        $invoice = get_invoice_by_id($invoiceId);
        if (!$invoice || $invoice['status'] !== 'pending_admin') {
            tg_request('sendMessage', [
                'chat_id' => $adminChatId,
                'text' => 'Invoice not found or already processed.',
            ]);
            return;
        }
        mark_invoice_status($invoiceId, 'rejected');
        tg_request('sendMessage', [
            'chat_id' => $invoice['user_chat_id'],
            'text' => 'Your payment was rejected by admin. Contact support if needed.',
        ]);
        tg_request('sendMessage', [
            'chat_id' => $adminChatId,
            'text' => "Invoice #{$invoiceId} rejected.",
        ]);
    }
}

$body = file_get_contents('php://input');
if (!$body) {
    exit;
}

$update = json_decode($body, true);
if (!is_array($update)) {
    exit;
}

if (isset($update['callback_query'])) {
    $callback = $update['callback_query'];
    $data = $callback['data'] ?? '';
    $from = $callback['from'] ?? [];
    $fromId = $from['id'] ?? 0;
    $message = $callback['message'] ?? null;
    if (strpos($data, 'plan:') === 0 && $message) {
        $parts = explode(':', $data);
        $days = (int)($parts[1] ?? 0);
        $chatId = $message['chat']['id'];
        handle_plan_selection($chatId, $days);
    } elseif (strpos($data, 'pay:') === 0 && $message) {
        $parts = explode(':', $data);
        $days = (int)($parts[1] ?? 0);
        $method = $parts[2] ?? '';
        $chatId = $message['chat']['id'];
        handle_payment_method($chatId, $from, $days, $method);
    } elseif (strpos($data, 'approve:') === 0 || strpos($data, 'reject:') === 0) {
        handle_admin_decision($fromId, $data);
    }
    if (isset($callback['id'])) {
        tg_request('answerCallbackQuery', [
            'callback_query_id' => $callback['id'],
        ]);
    }
    exit;
}

if (isset($update['message'])) {
    $message = $update['message'];
    $chatId = $message['chat']['id'];
    $text = isset($message['text']) ? trim($message['text']) : '';
    if ($text === '/start') {
        $welcome = "Welcome.\n\nThis bot generates time-limited licenses for the deployer admin panel.\n\nUse the menu to choose your license duration.";
        tg_request('sendMessage', [
            'chat_id' => $chatId,
            'text' => $welcome,
        ]);
        send_menu($chatId);
        exit;
    }
    handle_user_payment_proof($message);
}
