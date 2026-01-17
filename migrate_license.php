<?php
// migrate_license.php
// Run this script ONCE on your Render environment (via SSH or as a deploy command)
// to verify or insert your specific license key into the persistent database.

echo "--- License Migration Tool ---\n";

// 1. Determine Database Path (Same logic as Deployer/Bot)
$dbPath = (is_dir('/data') && is_writable('/data')) ? '/data/license_bot.db' : (dirname(__DIR__) . '/license_bot.db');
echo "Target Database: $dbPath\n";

if (!is_dir(dirname($dbPath))) {
    echo "❌ Error: Directory " . dirname($dbPath) . " does not exist.\n";
    exit(1);
}

// 2. Connect to Database
try {
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "✅ Connected to SQLite database.\n";
} catch (Exception $e) {
    echo "❌ Error connecting to database: " . $e->getMessage() . "\n";
    // Attempt to create it if it's a new file? 
    // The connection attempt above would have created the file if the directory exists.
    exit(1);
}

// 3. Ensure Table Exists
$pdo->exec("CREATE TABLE IF NOT EXISTS licenses (
    license_key TEXT PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    duration_days INTEGER,
    status TEXT,
    expires_at TEXT,
    payment_method TEXT,
    created_at TEXT,
    vps_json TEXT
)");

$cols = $pdo->query("PRAGMA table_info(licenses)")->fetchAll(PDO::FETCH_ASSOC);
$hasVps = false;
foreach ($cols as $col) {
    if (($col['name'] ?? '') === 'vps_json') {
        $hasVps = true;
        break;
    }
}
if (!$hasVps) {
    $pdo->exec("ALTER TABLE licenses ADD COLUMN vps_json TEXT");
}

// 4. Check/Insert the License
$licenseKey = 'WCXM26KYPSYAKGY8XK4D2R2R';
$userId = 0; // Unknown/System
$username = 'system_import';
$duration = 365; // Give it 1 year validity
$status = 'active';
$expiresAt = gmdate('c', time() + ($duration * 86400));
$method = 'manual_migration';
$createdAt = gmdate('c');

$stmt = $pdo->prepare("SELECT * FROM licenses WHERE license_key = ?");
$stmt->execute([$licenseKey]);
$exists = $stmt->fetch();

if ($exists) {
    echo "ℹ️ License $licenseKey already exists.\n";
    echo "   Status: " . $exists['status'] . "\n";
    echo "   Expires: " . $exists['expires_at'] . "\n";
} else {
    echo "➕ Inserting license $licenseKey...\n";
    $stmt = $pdo->prepare("INSERT INTO licenses (license_key, user_id, username, duration_days, status, expires_at, payment_method, created_at, vps_json) 
                           VALUES (:k, :u, :n, :d, :s, :e, :m, :c, :v)");
    $stmt->execute([
        ':k' => $licenseKey,
        ':u' => $userId,
        ':n' => $username,
        ':d' => $duration,
        ':s' => $status,
        ':e' => $expiresAt,
        ':m' => $method,
        ':c' => $createdAt,
        ':v' => json_encode([])
    ]);
    echo "✅ License inserted successfully.\n";
}

echo "--- Migration Complete ---\n";
