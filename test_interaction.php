<?php
// Simulate the environment for testing
if (!function_exists('curl_init')) {
    function curl_init() { return true; }
    function curl_setopt() {}
    function curl_exec() { return '{}'; }
    function curl_close() {}
    function curl_getinfo() { return 200; }
}

require_once 'license_bot.php';

echo "--- Starting Bot Interaction Simulation ---\n";

// Mock Handler to capture bot responses
$mockHandler = function($method, $params) {
    echo "\n[BOT ACTION] Method: $method\n";
    if ($method === 'sendMessage') {
        echo "   -> To: {$params['chat_id']}\n";
        echo "   -> Text: {$params['text']}\n";
        if (isset($params['reply_markup'])) {
            echo "   -> Markup: Yes\n";
        }
    } elseif ($method === 'editMessageText') {
        echo "   -> Text: {$params['text']}\n";
    }
    return ['ok' => true, 'result' => []];
};

// Initialize Bot with Mock Handler
$bot = new LicenseBot([
    'bot_token' => 'TEST_TOKEN',
    'admin_chat_id' => '123456',
    'mock_tg_handler' => $mockHandler,
    'db_path' => ':memory:' // Use in-memory DB for testing
]);

// 1. Simulate User sending /start
echo "\n--- Simulation 1: User sends /start ---\n";
$updateStart = [
    'message' => [
        'message_id' => 1,
        'from' => ['id' => 999, 'username' => 'testuser'],
        'chat' => ['id' => 999],
        'text' => '/start'
    ]
];
$bot->handleUpdate($updateStart);

// 2. Simulate User clicking "10 days" button
echo "\n--- Simulation 2: User clicks '10 days' button ---\n";
$updateClick = [
    'callback_query' => [
        'id' => 'cb1',
        'from' => ['id' => 999, 'username' => 'testuser'],
        'message' => ['chat' => ['id' => 999], 'message_id' => 2],
        'data' => 'buy|10|130'
    ]
];
$bot->handleUpdate($updateClick);

echo "\n--- Simulation Complete ---\n";
