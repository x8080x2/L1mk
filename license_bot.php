<?php

class LicenseBot
{
    private $botToken;
    private $adminChatId;
    private $btcAddress;
    private $usdtAddress;
    private $apiBase;
    private $db;
    private $mockTgHandler = null;

    public function __construct($config = [])
    {
        $this->loadEnv();
        
        $this->botToken = $config['bot_token'] ?? getenv('LICENSE_BOT_TOKEN') ?: '';
        $this->adminChatId = $config['admin_chat_id'] ?? getenv('LICENSE_ADMIN_CHAT_ID') ?: '';
        $this->btcAddress = $config['btc_address'] ?? getenv('LICENSE_BTC_ADDRESS') ?: '';
        $this->usdtAddress = $config['usdt_address'] ?? getenv('LICENSE_USDT_ADDRESS') ?: '';
        $this->mockTgHandler = $config['mock_tg_handler'] ?? null;

        if (!$this->botToken || !$this->adminChatId) {
            // Only exit if not in test mode (mock handler)
            if (!$this->mockTgHandler) {
                fwrite(STDERR, "Missing LICENSE_BOT_TOKEN or LICENSE_ADMIN_CHAT_ID env\n");
                exit(1);
            }
        }

        $this->apiBase = "https://api.telegram.org/bot{$this->botToken}/";

        $dbPath = $config['db_path'] ?? (dirname(__DIR__) . '/license_bot.db');
        $this->db = new PDO('sqlite:' . $dbPath);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->initDb();
    }

    private function loadEnv()
    {
        $envPath = __DIR__ . '/.env';
        if (file_exists($envPath)) {
            $env = parse_ini_file($envPath);
            foreach ($env as $k => $v) {
                if (!getenv($k)) putenv("$k=$v");
            }
        }
    }

    private function initDb()
    {
        $this->db->exec("CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            user_id INTEGER,
            username TEXT,
            duration_days INTEGER,
            status TEXT,
            expires_at TEXT,
            payment_method TEXT,
            created_at TEXT
        )");

        $this->db->exec("CREATE TABLE IF NOT EXISTS requests (
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

        $this->db->exec("CREATE TABLE IF NOT EXISTS user_state (
            user_id INTEGER PRIMARY KEY,
            state TEXT,
            request_id INTEGER
        )");
    }

    public function getDb() {
        return $this->db;
    }

    protected function tgRequest($method, $params = [])
    {
        $ch = curl_init($this->apiBase . $method);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
        $resp = curl_exec($ch);
        unset($ch);
        return $resp ? json_decode($resp, true) : null;
    }

    private function generateLicenseKey()
    {
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $out = '';
        for ($i = 0; $i < 24; $i++) {
            $out .= $chars[random_int(0, strlen($chars) - 1)];
        }
        return $out;
    }

    private function setUserState($userId, $state, $requestId = null)
    {
        $stmt = $this->db->prepare("INSERT INTO user_state (user_id, state, request_id) VALUES (:u, :s, :r)
            ON CONFLICT(user_id) DO UPDATE SET state = excluded.state, request_id = excluded.request_id");
        $stmt->execute([':u' => $userId, ':s' => $state, ':r' => $requestId]);
    }

    private function getUserState($userId)
    {
        $stmt = $this->db->prepare("SELECT state, request_id FROM user_state WHERE user_id = :u");
        $stmt->execute([':u' => $userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) return [null, null];
        return [$row['state'], $row['request_id']];
    }

    private function clearUserState($userId)
    {
        $stmt = $this->db->prepare("DELETE FROM user_state WHERE user_id = :u");
        $stmt->execute([':u' => $userId]);
    }

    private function sendMainMenu($chatId)
    {
        $keyboard = [
            'inline_keyboard' => [
                [['text' => '💎 Standard Access (10 Days) - $130', 'callback_data' => 'buy|10|130']],
                [['text' => '🚀 Weekly Access (20 Days) - $210', 'callback_data' => 'buy|20|210']],
                [['text' => '👑 Monthly  Access (30 Days) - $300', 'callback_data' => 'buy|30|300']],
            ]
        ];
        
        $msg = "🔐 *Welcome to @ClosedPages *\n\n" .
               "We provide secure, premium access to the ClosedLink.\n" .
               "Select a subscription plan.\n\n" .
               "All licenses grant full access to; Advanced Deployment Tools Real-time Analytics 24/7 System Availability";

        $this->tgRequest('sendMessage', [
            'chat_id' => $chatId,
            'text' => $msg,
            'parse_mode' => 'Markdown',
            'reply_markup' => json_encode($keyboard)
        ]);
    }

    public function handleUpdate($update)
    {
        if (isset($update['message'])) {
            $this->handleUserMessage($update);
        } elseif (isset($update['callback_query'])) {
            $this->handleCallbackQuery($update);
        }
    }

    private function handleUserMessage($update)
    {
        if (empty($update['message'])) return;
        $msg = $update['message'];
        $chatId = $msg['chat']['id'] ?? null;
        $userId = $msg['from']['id'] ?? null;
        $username = $msg['from']['username'] ?? '';
        if (!$chatId || !$userId) return;

        $text = trim($msg['text'] ?? '');

        if ($text === '/start') {
            $this->clearUserState($userId);
            // $this->tgRequest('sendMessage', [
            //     'chat_id' => $chatId,
            //     'text' => "Welcome. Use the buttons below to purchase a license."
            // ]);
            $this->sendMainMenu($chatId);
            return;
        }

        [$state, $requestId] = $this->getUserState($userId);
        if ($state === 'awaiting_proof' && $requestId) {
            $proof = $text !== '' ? $text : 'Attachment';
            $stmt = $this->db->prepare("UPDATE requests SET proof = :p WHERE id = :id");
            $stmt->execute([':p' => $proof, ':id' => $requestId]);
            $this->tgRequest('sendMessage', [
                'chat_id' => $chatId,
                'text' => "Thank you. Your payment proof has been recorded and is pending review."
            ]);

            $stmt = $this->db->prepare("SELECT * FROM requests WHERE id = :id");
            $stmt->execute([':id' => $requestId]);
            $req = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($req) {
                $info = "New payment proof\nUser ID: {$req['user_id']}\nUsername: @" . ($req['username'] ?: 'n/a') . "\nDuration: {$req['duration_days']} days\nPrice: \${$req['price_usd']}\nMethod: {$req['payment_method']}\nProof: {$proof}\nRequest ID: {$req['id']}";
                $this->tgRequest('sendMessage', [
                    'chat_id' => $this->adminChatId,
                    'text' => $info
                ]);
            }
            $this->clearUserState($userId);
            return;
        }

        $this->sendMainMenu($chatId);
    }

    private function handleCallbackQuery($update)
    {
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
                    [['text' => 'Pay with USDT', 'callback_data' => "pay|USDT|{$duration}|{$price}"]],
                    [['text' => 'Pay with BTC', 'callback_data' => "pay|BTC|{$duration}|{$price}"]],
                ]
            ];
            $this->tgRequest('editMessageText', [
                'chat_id' => $chatId,
                'message_id' => $messageId,
                'text' => "💳 *Payment Method Selection*\n\n" .
                          "You have selected: *{$duration} Days Access* (\${$price})\n\n" .
                          "Please choose your preferred secure payment method below:",
                'parse_mode' => 'Markdown',
                'reply_markup' => json_encode($keyboard)
            ]);
            return;
        }

        if ($parts[0] === 'pay' && count($parts) === 4) {
            $method = $parts[1];
            $duration = (int)$parts[2];
            $price = (int)$parts[3];
            $address = $method === 'BTC' ? $this->btcAddress : $this->usdtAddress;

            $username = $cb['from']['username'] ?? '';

            $stmt = $this->db->prepare("INSERT INTO requests (user_id, username, duration_days, price_usd, payment_method, status, proof, created_at) VALUES (:u, :n, :d, :p, :m, 'pending', '', :c)");
            $stmt->execute([
                ':u' => $fromId,
                ':n' => $username,
                ':d' => $duration,
                ':p' => $price,
                ':m' => $method,
                ':c' => gmdate('c')
            ]);
            $requestId = (int)$this->db->lastInsertId();

            $invoice = "🧾 *INVOICE #{$requestId}*\n\n" .
                       "📦 *Plan:* {$duration} Days Premium Access\n" .
                       "💰 *Amount:* \${$price} USD\n" .
                       "💠 *Method:* {$method}\n\n" .
                       "⚠️ *PAYMENT INSTRUCTIONS:*\n" .
                       "Send EXACTLY \${$price} worth of {$method} to the address below:\n\n" .
                       "`{$address}`\n\n" .
                       "(Tap address to copy)\n\n" .
                       "⏳ *After payment:* Reply to this message with your Transaction Hash (TXID) or a screenshot of the confirmation.";

            $this->tgRequest('sendMessage', [
                'chat_id' => $chatId,
                'text' => $invoice,
                'parse_mode' => 'Markdown'
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
            $this->tgRequest('sendMessage', [
                'chat_id' => $this->adminChatId,
                'text' => $adminText,
                'reply_markup' => json_encode($adminKeyboard)
            ]);

            $this->setUserState($fromId, 'awaiting_proof', $requestId);

            $this->tgRequest('answerCallbackQuery', [
                'callback_query_id' => $cb['id'],
                'text' => 'Invoice created. Please send your payment proof.'
            ]);
            return;
        }

        if (($parts[0] === 'approve' || $parts[0] === 'decline') && count($parts) === 2) {
            $requestId = (int)$parts[1];
            if ((string)$fromId !== (string)$this->adminChatId) {
                $this->tgRequest('answerCallbackQuery', [
                    'callback_query_id' => $cb['id'],
                    'text' => 'Not authorized',
                    'show_alert' => true
                ]);
                return;
            }

            $stmt = $this->db->prepare("SELECT * FROM requests WHERE id = :id");
            $stmt->execute([':id' => $requestId]);
            $req = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$req) {
                $this->tgRequest('answerCallbackQuery', [
                    'callback_query_id' => $cb['id'],
                    'text' => 'Request not found',
                    'show_alert' => true
                ]);
                return;
            }

            if ($parts[0] === 'decline') {
                $this->db->prepare("UPDATE requests SET status = 'declined' WHERE id = :id")->execute([':id' => $requestId]);
                $this->tgRequest('answerCallbackQuery', [
                    'callback_query_id' => $cb['id'],
                    'text' => 'Request declined'
                ]);
                $this->tgRequest('sendMessage', [
                    'chat_id' => $req['user_id'],
                    'text' => "Your license request (ID {$requestId}) has been declined."
                ]);
                return;
            }

            $duration = (int)$req['duration_days'];
            $licenseKey = $this->generateLicenseKey();
            $expiresAt = gmdate('c', time() + $duration * 86400);

            $stmt = $this->db->prepare("INSERT OR REPLACE INTO licenses (license_key, user_id, username, duration_days, status, expires_at, payment_method, created_at) VALUES (:k, :u, :n, :d, 'active', :e, :m, :c)");
            $stmt->execute([
                ':k' => $licenseKey,
                ':u' => $req['user_id'],
                ':n' => $req['username'],
                ':d' => $duration,
                ':e' => $expiresAt,
                ':m' => $req['payment_method'],
                ':c' => gmdate('c')
            ]);

            $this->db->prepare("UPDATE requests SET status = 'approved' WHERE id = :id")->execute([':id' => $requestId]);

            $this->tgRequest('answerCallbackQuery', [
                'callback_query_id' => $cb['id'],
                'text' => 'License approved and generated'
            ]);

            $msgToUser = "✅ *LICENSE APPROVED*\n\n" .
                         "Thank you for your purchase. Your access has been granted.\n\n" .
                         "🔑 *License Key:*\n`{$licenseKey}`\n\n" .
                         "📅 *Duration:* {$duration} days\n" .
                         "⏰ *Expires:* {$expiresAt}\n\n" .
                         "👇 *How to use:*\n" .
                         "1. Copy the license key above.\n" .
                         "2. Go to your deployer login page.\n" .
                         "3. Paste the key to unlock the panel.";

            $this->tgRequest('sendMessage', [
                'chat_id' => $req['user_id'],
                'text' => $msgToUser,
                'parse_mode' => 'Markdown'
            ]);
            return;
        }
    }

    public function run()
    {
        // Ensure webhook is deleted for getUpdates to work
        $this->tgRequest('deleteWebhook');
        
        $offset = 0;
        echo "License Bot Started...\n";
        while (true) {
            $resp = $this->tgRequest('getUpdates', ['timeout' => 30, 'offset' => $offset]);
            if (!is_array($resp) || empty($resp['ok']) || empty($resp['result'])) {
                if (!empty($resp) && empty($resp['ok'])) {
                    echo "Error in getUpdates: " . json_encode($resp) . "\n";
                }
                sleep(2); // Prevent tight loop on error
                continue;
            }
            foreach ($resp['result'] as $update) {
                echo "Received update: " . json_encode($update) . "\n";
                $offset = $update['update_id'] + 1;
                $this->handleUpdate($update);
            }
        }
    }
}

// Check if running directly
if (php_sapi_name() === 'cli' && isset($argv[0]) && basename($argv[0]) === basename(__FILE__)) {
    $bot = new LicenseBot();
    $bot->run();
}

