<?php

$botToken = getenv('LICENSE_BOT_TOKEN') ?: '';
$adminChatId = getenv('LICENSE_ADMIN_CHAT_ID') ?: '';
$btcAddress = getenv('LICENSE_BTC_ADDRESS') ?: '';
$usdtAddress = getenv('LICENSE_USDT_ADDRESS') ?: '';

if ($botToken === '' || $adminChatId === '') {
    fwrite(STDERR, "Missing LICENSE_BOT_TOKEN or LICENSE_ADMIN_CHAT_ID env\n");
    exit(1);
}

$apiBase = "https://api.telegram.org/bot{$botToken}/";

$dbPath = dirname(__DIR__) . '/license_bot.db';
$db = new PDO('sqlite:' . $dbPath);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$db->exec("CREATE TABLE IF NOT EXISTS licenses (
    license_key TEXT PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    duration_days INTEGER,
    status TEXT,
    expires_at TEXT,
    payment_method TEXT,
    created_at TEXT
)");

$db->exec("CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    duration_days INTEGER,
    price_usd INTEGER,
    payment_method TEXT,
    status TEXT,
    proof TEXT,
    created_at TEXT
)");

$db->exec("CREATE TABLE IF NOT EXISTS user_state (
    user_id INTEGER PRIMARY KEY,
    state TEXT,
    request_id INTEGER
)");

function tgRequest($method, $params = [])
{
    global $apiBase;
    $ch = curl_init($apiBase . $method);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
    $resp = curl_exec($ch);
    curl_close($ch);
    return $resp ? json_decode($resp, true) : null;
}

function generateLicenseKey()
{
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $out = '';
    for ($i = 0; $i < 24; $i++) {
        $out .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $out;
}

function setUserState($userId, $state, $requestId = null)
{
    global $db;
    $stmt = $db->prepare("INSERT INTO user_state (user_id, state, request_id) VALUES (:u, :s, :r)
        ON CONFLICT(user_id) DO UPDATE SET state = excluded.state, request_id = excluded.request_id");
    $stmt->execute([':u' => $userId, ':s' => $state, ':r' => $requestId]);
}

function getUserState($userId)
{
    global $db;
    $stmt = $db->prepare("SELECT state, request_id FROM user_state WHERE user_id = :u");
    $stmt->execute([':u' => $userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) return [null, null];
    return [$row['state'], $row['request_id']];
}

function clearUserState($userId)
{
    global $db;
    $stmt = $db->prepare("DELETE FROM user_state WHERE user_id = :u");
    $stmt->execute([':u' => $userId]);
}

function sendMainMenu($chatId)
{
    $keyboard = [
        'inline_keyboard' => [
            [
                ['text' => '10 days – $130', 'callback_data' => 'buy|10|130'],
            ],
            [
                ['text' => '20 days – $210', 'callback_data' => 'buy|20|210'],
            ],
            [
                ['text' => '30 days – $300', 'callback_data' => 'buy|30|300'],
            ],
        ]
    ];
    $text = "Select license duration:";
    tgRequest('sendMessage', [
        'chat_id' => $chatId,
        'text' => $text,
        'reply_markup' => json_encode($keyboard)
    ]);
}

function handleUserMessage($update)
{
    global $db, $btcAddress, $usdtAddress, $adminChatId;
    if (empty($update['message'])) return;
    $msg = $update['message'];
    $chatId = $msg['chat']['id'] ?? null;
    $userId = $msg['from']['id'] ?? null;
    $username = $msg['from']['username'] ?? '';
    if (!$chatId || !$userId) return;

    $text = trim($msg['text'] ?? '');

    if ($text === '/start') {
        clearUserState($userId);
        tgRequest('sendMessage', [
            'chat_id' => $chatId,
            'text' => "Welcome. Use the buttons below to purchase a license."
        ]);
        sendMainMenu($chatId);
        return;
    }

    [$state, $requestId] = getUserState($userId);
    if ($state === 'awaiting_proof' && $requestId) {
        $proof = $text !== '' ? $text : 'Attachment';
        $stmt = $db->prepare("UPDATE requests SET proof = :p WHERE id = :id");
        $stmt->execute([':p' => $proof, ':id' => $requestId]);
        tgRequest('sendMessage', [
            'chat_id' => $chatId,
            'text' => "Thank you. Your payment proof has been recorded and is pending review."
        ]);

        $stmt = $db->prepare("SELECT * FROM requests WHERE id = :id");
        $stmt->execute([':id' => $requestId]);
        $req = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($req) {
            $info = "New payment proof\nUser ID: {$req['user_id']}\nUsername: @" . ($req['username'] ?: 'n/a') . "\nDuration: {$req['duration_days']} days\nPrice: \${$req['price_usd']}\nMethod: {$req['payment_method']}\nProof: {$proof}\nRequest ID: {$req['id']}";
            tgRequest('sendMessage', [
                'chat_id' => $adminChatId,
                'text' => $info
            ]);
        }
        clearUserState($userId);
        return;
    }

    sendMainMenu($chatId);
}

function handleCallbackQuery($update)
{
    global $db, $btcAddress, $usdtAddress, $adminChatId;
    if (empty($update['callback_query'])) return;
    $cb = $update['callback_query'];
    $data = $cb['data'] ?? '';
    $fromId = $cb['from']['id'] ?? null;
    $chatId = $cb['message']['chat']['id'] ?? null;
    $messageId = $cb['message']['message_id'] ?? null;
    if (!$fromId || !$chatId) return;

    $parts = explode('|', $data);
    if ($parts[0] === 'buy' && count($parts) === 3) {
        $duration = (int)$parts[1];
        $price = (int)$parts[2];

        $keyboard = [
            'inline_keyboard' => [
                [
                    ['text' => 'Pay with USDT', 'callback_data' => "pay|USDT|{$duration}|{$price}"],
                ],
                [
                    ['text' => 'Pay with BTC', 'callback_data' => "pay|BTC|{$duration}|{$price}"],
                ],
            ]
        ];
        tgRequest('editMessageText', [
            'chat_id' => $chatId,
            'message_id' => $messageId,
            'text' => "Choose payment method for {$duration} days (\${$price}):",
            'reply_markup' => json_encode($keyboard)
        ]);
        return;
    }

    if ($parts[0] === 'pay' && count($parts) === 4) {
        $method = $parts[1];
        $duration = (int)$parts[2];
        $price = (int)$parts[3];
        $address = $method === 'BTC' ? $btcAddress : $usdtAddress;

        $username = $cb['from']['username'] ?? '';

        $stmt = $db->prepare("INSERT INTO requests (user_id, username, duration_days, price_usd, payment_method, status, proof, created_at) VALUES (:u, :n, :d, :p, :m, 'pending', '', :c)");
        $stmt->execute([
            ':u' => $fromId,
            ':n' => $username,
            ':d' => $duration,
            ':p' => $price,
            ':m' => $method,
            ':c' => gmdate('c')
        ]);
        $requestId = (int)$db->lastInsertId();

        $invoice = "Invoice ID: {$requestId}\nDuration: {$duration} days\nPrice: \${$price}\nPayment method: {$method}\n\nSend exactly \${$price} equivalent to:\n{$address}\n\nAfter sending, reply here with your transaction hash or screenshot.";

        tgRequest('sendMessage', [
            'chat_id' => $chatId,
            'text' => $invoice
        ]);

        $adminText = "New license request\nRequest ID: {$requestId}\nUser ID: {$fromId}\nUsername: @" . ($username ?: 'n/a') . "\nDuration: {$duration} days\nPrice: \${$price}\nMethod: {$method}\nStatus: pending";
        $adminKeyboard = [
            'inline_keyboard' => [
                [
                    ['text' => 'Approve', 'callback_data' => "approve|{$requestId}"],
                    ['text' => 'Decline', 'callback_data' => "decline|{$requestId}"],
                ]
            ]
        ];
        tgRequest('sendMessage', [
            'chat_id' => $adminChatId,
            'text' => $adminText,
            'reply_markup' => json_encode($adminKeyboard)
        ]);

        setUserState($fromId, 'awaiting_proof', $requestId);

        tgRequest('answerCallbackQuery', [
            'callback_query_id' => $cb['id'],
            'text' => 'Invoice created. Please send your payment proof.'
        ]);
        return;
    }

    if (($parts[0] === 'approve' || $parts[0] === 'decline') && count($parts) === 2) {
        $requestId = (int)$parts[1];
        if ((string)$fromId !== (string)$adminChatId) {
            tgRequest('answerCallbackQuery', [
                'callback_query_id' => $cb['id'],
                'text' => 'Not authorized',
                'show_alert' => true
            ]);
            return;
        }

        $stmt = $db->prepare("SELECT * FROM requests WHERE id = :id");
        $stmt->execute([':id' => $requestId]);
        $req = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$req) {
            tgRequest('answerCallbackQuery', [
                'callback_query_id' => $cb['id'],
                'text' => 'Request not found',
                'show_alert' => true
            ]);
            return;
        }

        if ($parts[0] === 'decline') {
            $db->prepare("UPDATE requests SET status = 'declined' WHERE id = :id")->execute([':id' => $requestId]);
            tgRequest('answerCallbackQuery', [
                'callback_query_id' => $cb['id'],
                'text' => 'Request declined'
            ]);
            tgRequest('sendMessage', [
                'chat_id' => $req['user_id'],
                'text' => "Your license request (ID {$requestId}) has been declined."
            ]);
            return;
        }

        $duration = (int)$req['duration_days'];
        $licenseKey = generateLicenseKey();
        $expiresAt = gmdate('c', time() + $duration * 86400);

        $stmt = $db->prepare("INSERT OR REPLACE INTO licenses (license_key, user_id, username, duration_days, status, expires_at, payment_method, created_at) VALUES (:k, :u, :n, :d, 'active', :e, :m, :c)");
        $stmt->execute([
            ':k' => $licenseKey,
            ':u' => $req['user_id'],
            ':n' => $req['username'],
            ':d' => $duration,
            ':e' => $expiresAt,
            ':m' => $req['payment_method'],
            ':c' => gmdate('c')
        ]);

        $db->prepare("UPDATE requests SET status = 'approved' WHERE id = :id")->execute([':id' => $requestId]);

        tgRequest('answerCallbackQuery', [
            'callback_query_id' => $cb['id'],
            'text' => 'License approved and generated'
        ]);

        $msgToUser = "Your license has been approved.\nLicense key: {$licenseKey}\nDuration: {$duration} days\nExpires at (UTC): {$expiresAt}\n\nUse this key in the deployer login.";
        tgRequest('sendMessage', [
            'chat_id' => $req['user_id'],
            'text' => $msgToUser
        ]);
        return;
    }
}

$offset = 0;
while (true) {
    $resp = tgRequest('getUpdates', ['timeout' => 30, 'offset' => $offset]);
    if (!is_array($resp) || empty($resp['ok']) || empty($resp['result'])) {
        continue;
    }
    foreach ($resp['result'] as $update) {
        $offset = $update['update_id'] + 1;
        if (isset($update['message'])) {
            handleUserMessage($update);
        } elseif (isset($update['callback_query'])) {
            handleCallbackQuery($update);
        }
    }
}

