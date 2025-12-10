<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Get Airtable config
$airtableApiKey = $_GET['apiKey'] ?? '';
$airtableBaseId = $_GET['baseId'] ?? '';

if (!$airtableApiKey || !$airtableBaseId) {
    echo json_encode(['error' => 'Missing Airtable credentials']);
    exit;
}

// Fetch SystemConfig to get bot token
$ch = curl_init("https://api.airtable.com/v0/{$airtableBaseId}/SystemConfig");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Authorization: Bearer {$airtableApiKey}",
    "Content-Type: application/json"
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode !== 200) {
    echo json_encode(['error' => 'Failed to fetch SystemConfig']);
    exit;
}

$data = json_decode($response, true);
$botToken = null;

// Find telegram_bot_token in SystemConfig
foreach ($data['records'] as $record) {
    if (isset($record['fields']['telegram_bot_token'])) {
        $botToken = $record['fields']['telegram_bot_token'];
        break;
    }
}

if (!$botToken) {
    echo json_encode(['error' => 'Telegram bot token not found in SystemConfig']);
    exit;
}

// Get recent updates from Telegram
$telegramUrl = "https://api.telegram.org/bot{$botToken}/getUpdates?limit=20";
$ch = curl_init($telegramUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode !== 200) {
    echo json_encode(['error' => 'Failed to connect to Telegram API']);
    exit;
}

$telegramData = json_decode($response, true);

if (!$telegramData['ok'] || empty($telegramData['result'])) {
    echo json_encode(['error' => 'No recent messages found. Please send a message to the bot first.']);
    exit;
}

// Extract unique chat IDs with user info
$chatIds = [];
foreach ($telegramData['result'] as $update) {
    if (isset($update['message']['chat'])) {
        $chat = $update['message']['chat'];
        $chatId = $chat['id'];

        // Build display name
        $name = '';
        if (isset($chat['first_name'])) $name .= $chat['first_name'];
        if (isset($chat['last_name'])) $name .= ' ' . $chat['last_name'];
        if (isset($chat['username'])) $name .= ' (@' . $chat['username'] . ')';

        if (!isset($chatIds[$chatId])) {
            $chatIds[$chatId] = [
                'chatId' => $chatId,
                'name' => trim($name) ?: 'Unknown User',
                'type' => $chat['type'] ?? 'private',
                'lastMessage' => $update['message']['text'] ?? '[No text]',
                'date' => $update['message']['date'] ?? 0
            ];
        }
    }
}

// Sort by most recent
usort($chatIds, function($a, $b) {
    return $b['date'] - $a['date'];
});

echo json_encode([
    'success' => true,
    'chatIds' => array_values($chatIds)
]);
?>
