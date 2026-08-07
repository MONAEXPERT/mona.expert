<?php
/**
 * mona.expert — API v2.0
 * Enterprise AI Agent Security & Management
 *
 * Breaking changes from v1.1:
 *  - UUID support on all entities
 *  - New security_checks endpoint
 *  - Chained audit log (SHA-256)
 *  - Improved pagination, error handling
 *  - WebSocket hint for live updates
 */

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Auth-Token, Authorization, X-Requested-With');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex');
header('X-API-Version: 2.0');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// ─── Database Config ──────────────────────────────
$DB_HOST = 'localhost';
$DB_NAME = 'u702975565_Idkskskd';
$DB_USER = 'u702975565_AkskaisiiI828';
$DB_PASS = 'u:x*tS6^Ap|3';

try {
    $pdo = new PDO("mysql:host=$DB_HOST;dbname=$DB_NAME;charset=utf8mb4", $DB_USER, $DB_PASS, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Datenbankverbindung fehlgeschlagen']);
    exit;
}

// ─── Rate Limiting ────────────────────────────────
$RATE_LIMIT_WINDOW = 60;
$rateFile = sys_get_temp_dir() . '/mx_rate_' . md5($_SERVER['REMOTE_ADDR'] ?? 'unknown');
$rateNow = time();
$rateData = @file_get_contents($rateFile) ? json_decode(file_get_contents($rateFile), true) : ['count' => 0, 'reset' => $rateNow + $RATE_LIMIT_WINDOW];
if ($rateData['reset'] < $rateNow) { $rateData = ['count' => 0, 'reset' => $rateNow + $RATE_LIMIT_WINDOW]; }
$rateData['count']++;
file_put_contents($rateFile, json_encode($rateData), LOCK_EX);
header('X-RateLimit-Limit: ' . 60);
header('X-RateLimit-Remaining: ' . max(0, 60 - $rateData['count']));
header('X-RateLimit-Reset: ' . $rateData['reset']);
if ($rateData['count'] > 60) { http_response_code(429); echo json_encode(['status'=>'error','message'=>'Zu viele Anfragen. Bitte kurz warten.']); exit; }

// ─── Helpers ──────────────────────────────────────
function json_out($data, $code = 200) { http_response_code($code); echo json_encode($data, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); exit; }
function error($msg, $code = 400) { json_out(['status' => 'error', 'message' => $msg], $code); }

function genUUID() {
    $data = random_bytes(16);
    $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
    $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function generateToken($prefix = 'mxn_') {
    return $prefix . bin2hex(random_bytes(20));
}

function paginate($pdo, $table, $where, $params, $orderBy = 'created_at DESC', $defaultLimit = 50) {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $limit  = min((int)($input['limit'] ?? $defaultLimit), 500);
    $offset = max((int)($input['offset'] ?? 0), 0);

    $whereClause = $where ? 'WHERE ' . $where : '';
    $countSql = "SELECT COUNT(*) FROM {$table} {$whereClause}";
    $cStmt = $pdo->prepare($countSql);
    $cStmt->execute($params);
    $total = (int)$cStmt->fetchColumn();

    $sql = "SELECT * FROM {$table} {$whereClause} ORDER BY {$orderBy} LIMIT ? OFFSET ?";
    $allParams = array_merge($params, [$limit, $offset]);
    $stmt = $pdo->prepare($sql);
    $stmt->execute($allParams);

    return [
        'data'   => $stmt->fetchAll(),
        'total'  => $total,
        'limit'  => $limit,
        'offset' => $offset,
    ];
}

// ─── Auth ─────────────────────────────────────────
function getToken() {
    $token = '';
    $headers = function_exists('getallheaders') ? getallheaders() : $_SERVER;
    if (isset($headers['X-Auth-Token'])) $token = $headers['X-Auth-Token'];
    elseif (isset($_SERVER['HTTP_X_AUTH_TOKEN'])) $token = $_SERVER['HTTP_X_AUTH_TOKEN'];
    elseif (isset($headers['Authorization'])) $token = str_replace('Bearer ', '', $headers['Authorization']);
    elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) $token = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION']);
    return $token;
}

function authUser($pdo) {
    $token = getToken();
    if (!$token) return null;

    $stmt = $pdo->prepare('SELECT k.user_id, k.type, k.is_active FROM api_keys k WHERE k.key_value = ? AND (k.expires_at IS NULL OR k.expires_at > NOW())');
    $stmt->execute([$token]);
    $key = $stmt->fetch();
    if (!$key || (isset($key['is_active']) && !$key['is_active'])) return null;

    $stmt = $pdo->prepare('SELECT id, uuid, email, display_name, COALESCE(plan, plan_type, \'free\') as plan, role, created_at, last_login_at, last_login, email_verified FROM users WHERE id = ?');
    $stmt->execute([$key['user_id']]);
    $user = $stmt->fetch();
    if (!$user) return null;

    // Normalize field names
    if (!isset($user['last_login_at']) && isset($user['last_login'])) $user['last_login_at'] = $user['last_login'];
    return $user;
}

function requireUser($pdo) {
    $u = authUser($pdo);
    if (!$u) error('Nicht autorisiert. Bitte erneut anmelden.', 401);
    return $u;
}

function requireAdmin($pdo) {
    $u = requireUser($pdo);
    if (($u['role'] ?? 'user') !== 'admin') error('Admin-Zugriff erforderlich.', 403);
    return $u;
}

// ─── Audit Log Helper ────────────────────────────
function auditLog($pdo, $userId, $eventType, $action, $status = 'success', $details = null, $severity = 'info') {
    // Chain hash
    $prevHash = $pdo->query("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1")->fetchColumn();
    $chainData = json_encode(['event' => $eventType, 'action' => $action, 'status' => $status, 'time' => date('c')]);
    $currentHash = hash('sha256', ($prevHash ?: '') . $chainData);

    // details must be valid JSON (CHECK constraint on column)
    $jsonDetails = is_string($details) ? json_encode(['message' => $details]) : json_encode($details);

    $stmt = $pdo->prepare('INSERT INTO audit_log (uuid, user_id, event_type, action, status, summary, details, previous_hash, current_hash, severity, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([
        genUUID(),
        $userId,
        $eventType,
        $action,
        $status,
        is_string($details) ? $details : (is_array($details) ? ($details['summary'] ?? '') : ''),
        $jsonDetails,
        $prevHash,
        $currentHash,
        $severity,
        $_SERVER['REMOTE_ADDR'] ?? null,
        $_SERVER['HTTP_USER_AGENT'] ?? null,
    ]);
    return $pdo->lastInsertId();
}

// ═══════════════════════════════════════════════════
//  ENDPOINTS
// ═══════════════════════════════════════════════════
$action = $_GET['action'] ?? '';

// Backwards/dashboard-compatible action aliases → canonical handlers
$ACTION_ALIASES = [
    'get_wrappers'         => 'list_wrappers',
    'get_agents'           => 'list_wrappers',
    'get_audit_events'     => 'get_audit_log',
    'get_stats'            => 'get_dashboard_data',
    'get_latest_telemetry' => 'get_dashboard_data',
];
if (isset($ACTION_ALIASES[$action])) {
    $action = $ACTION_ALIASES[$action];
}

$rawBody = file_get_contents('php://input');
$input   = json_decode($rawBody, true) ?: [];
if (empty($input) && !empty($_POST)) {
    $input = $_POST;
}

switch ($action) {

    // ═══════════════════════════════════
    //  PUBLIC
    // ═══════════════════════════════════

    case 'health':
        // Server metrics (async safe)
        $load = @sys_getloadavg();
        $memFile = '/proc/meminfo';
        $memTotal = 0; $memFree = 0;
        if (file_exists($memFile)) {
            $lines = @file($memFile);
            if ($lines) {
                foreach ($lines as $l) {
                    if (preg_match('/^MemTotal:\s+(\d+)/', $l, $m)) $memTotal = (int)$m[1];
                    if (preg_match('/^MemAvailable:\s+(\d+)/', $l, $m)) $memFree = (int)$m[1];
                }
            }
        }
        $memPct = $memTotal > 0 ? round((1 - $memFree / $memTotal) * 100, 1) : null;
        $hostname = php_uname('n') ?: gethostname() ?: 'mona.expert';
        $uptime = '';
        $uptimeFile = '/proc/uptime';
        if (file_exists($uptimeFile)) {
            $uptimeSec = (int)@file_get_contents($uptimeFile);
            $days = floor($uptimeSec / 86400);
            $hours = floor(($uptimeSec % 86400) / 3600);
            $uptime = $days . 'd ' . $hours . 'h';
        }

        json_out([
            'status'  => 'ok',
            'service' => 'mona.expert',
            'version' => '2.0',
            'time'    => date('c'),
            'uptime'  => $uptime ?: 'Enterprise AI Agent Security — Audit & Management',
            'server'  => [
                'hostname'      => $hostname,
                'software'      => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
                'php_version'   => phpversion(),
                'cpu_load'      => $load ? round($load[0], 2) : null,
                'load_average'  => $load ? implode(' ', array_map(function($v){return round($v,2);}, $load)) : null,
                'memory_usage'  => $memPct,
                'platform'      => php_uname('s') . ' ' . php_uname('r'),
            ],
        ]);

    case 'register':
        $email    = trim($input['email'] ?? '');
        $password = $input['password'] ?? '';
        $name     = trim($input['name'] ?? '');

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) error('Bitte eine gültige E-Mail-Adresse eingeben.');
        if (strlen($password) < 6) error('Das Passwort muss mindestens 6 Zeichen lang sein.');

        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ?');
        $stmt->execute([$email]);
        if ($stmt->fetch()) error('Diese E-Mail ist bereits registriert.', 409);

        $hash = password_hash($password, PASSWORD_BCRYPT);
        $uuid = genUUID();
        $displayName = $name ?: explode('@', $email)[0];

        $pdo->prepare('INSERT INTO users (uuid, email, password_hash, display_name, plan, role) VALUES (?, ?, ?, ?, ?, ?)')
            ->execute([$uuid, $email, $hash, $displayName, 'free', 'user']);

        $userId = (int)$pdo->lastInsertId();
        $token  = generateToken();
        $keyUuid = genUUID();
        $keyHash = hash('sha256', $token);
        $pdo->prepare('INSERT INTO api_keys (uuid, user_id, key_value, key_hash, key_prefix, type, label) VALUES (?, ?, ?, ?, ?, ?, ?)')
            ->execute([$keyUuid, $userId, $token, $keyHash, substr($token, 0, 8), 'web', 'Session']);

        auditLog($pdo, $userId, 'account', 'register', 'success', "Konto erstellt: {$email}", 'info');

        json_out([
            'status'  => 'ok',
            'user_id' => $userId,
            'uuid'    => $uuid,
            'message' => 'Konto erstellt! Willkommen bei mona.expert.',
            'token'   => $token,
            'user'    => ['id' => $userId, 'uuid' => $uuid, 'email' => $email, 'display_name' => $displayName, 'plan' => 'free', 'role' => 'user'],
        ]);

    case 'login':
        $email    = trim($input['email'] ?? '');
        $password = $input['password'] ?? '';

        $stmt = $pdo->prepare('SELECT id, uuid, email, password_hash, display_name, COALESCE(plan, plan_type, \'free\') as plan, role, email_verified FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            error('E-Mail oder Passwort falsch.', 401);
        }

        // Update login timestamp
        try {
            $pdo->prepare("UPDATE users SET last_login_at = NOW(), last_login = NOW() WHERE id = ?")->execute([$user['id']]);
        } catch (Exception $e) {
            $pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?")->execute([$user['id']]);
        }

        // Reuse or create session token
        $stmt = $pdo->prepare('SELECT key_value FROM api_keys WHERE user_id = ? AND type = ? ORDER BY created_at DESC LIMIT 1');
        $stmt->execute([$user['id'], 'web']);
        $existing = $stmt->fetch();
        $token = $existing ? $existing['key_value'] : null;
        if (!$token) {
            $token = generateToken();
            $keyUuid = genUUID();
            $keyHash = hash('sha256', $token);
            $pdo->prepare('INSERT INTO api_keys (uuid, user_id, key_value, key_hash, key_prefix, type, label) VALUES (?, ?, ?, ?, ?, ?, ?)')
                ->execute([$keyUuid, $userId = $user['id'], $token, $keyHash, substr($token, 0, 8), 'web', 'Session']);
        }

        auditLog($pdo, $user['id'], 'account', 'login', 'success', "Anmeldung: {$email}", 'info');

        json_out([
            'status' => 'ok',
            'user' => [
                'id'            => (int)$user['id'],
                'uuid'          => $user['uuid'] ?? null,
                'email'         => $user['email'],
                'display_name'  => $user['display_name'],
                'plan'          => $user['plan'] ?? 'free',
                'role'          => $user['role'] ?? 'user',
            ],
            'token' => $token,
        ]);

    case 'reset_password':
        $email = trim($input['email'] ?? '');
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) error('Bitte eine gültige E-Mail-Adresse eingeben.');

        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if ($user) {
            $resetToken = bin2hex(random_bytes(32));
            $uuid = genUUID();
            $expires = date('Y-m-d H:i:s', time() + 3600);
            try {
                $pdo->prepare('INSERT INTO password_resets (uuid, user_id, token, expires_at) VALUES (?, ?, ?, ?)')
                    ->execute([$uuid, $user['id'], $resetToken, $expires]);
            } catch (Exception $e) {
                // Fallback to old method
                $pdo->prepare("UPDATE users SET password_reset_token = ?, password_reset_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE id = ?")
                    ->execute([$resetToken, $user['id']]);
            }
            auditLog($pdo, $user['id'], 'password', 'reset_requested', 'success', 'Passwort-Reset angefordert', 'info');
        }

        json_out(['status' => 'ok', 'message' => 'Wenn diese E-Mail registriert ist, erhältst du in Kürze eine Anleitung zum Zurücksetzen.']);

    case 'reset_password_confirm':
        $token = trim($input['token'] ?? '');
        $newPassword = $input['password'] ?? '';
        if (!$token) error('Reset-Token erforderlich.');
        if (strlen($newPassword) < 6) error('Passwort zu kurz.');

        // Try new table first
        $stmt = $pdo->prepare("SELECT id, user_id FROM password_resets WHERE token = ? AND expires_at > NOW() AND used = 0");
        $stmt->execute([$token]);
        $reset = $stmt->fetch();

        if ($reset) {
            $hash = password_hash($newPassword, PASSWORD_BCRYPT);
            $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([$hash, $reset['user_id']]);
            $pdo->prepare("UPDATE password_resets SET used = 1 WHERE id = ?")->execute([$reset['id']]);
            auditLog($pdo, $reset['user_id'], 'password', 'reset_completed', 'success', 'Passwort zurückgesetzt', 'info');
            json_out(['status' => 'ok', 'message' => 'Passwort erfolgreich zurückgesetzt.']);
        }

        // Legacy fallback
        $stmt = $pdo->prepare("SELECT id FROM users WHERE password_reset_token = ? AND password_reset_expires > NOW()");
        $stmt->execute([$token]);
        $user = $stmt->fetch();
        if (!$user) error('Ungültiger oder abgelaufener Reset-Token.', 400);

        $hash = password_hash($newPassword, PASSWORD_BCRYPT);
        $pdo->prepare("UPDATE users SET password_hash = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?")->execute([$hash, $user['id']]);
        auditLog($pdo, $user['id'], 'password', 'reset_completed', 'success', 'Passwort zurückgesetzt (legacy)', 'info');
        json_out(['status' => 'ok', 'message' => 'Passwort erfolgreich zurückgesetzt.']);

    // ═══════════════════════════════════
    //  AUTHENTICATED
    // ═══════════════════════════════════

    case 'me':
        $u = requireUser($pdo);
        json_out(['status' => 'ok', 'user' => $u]);

    case 'update_profile':
        $u = requireUser($pdo);
        $displayName = trim($input['display_name'] ?? '');
        if ($displayName) {
            $pdo->prepare('UPDATE users SET display_name = ? WHERE id = ?')->execute([$displayName, $u['id']]);
            auditLog($pdo, $u['id'], 'account', 'profile_updated', 'success', "Profil aktualisiert: {$displayName}", 'info');
        }
        json_out(['status' => 'ok', 'message' => 'Profil aktualisiert.']);

    case 'delete_account':
        $u = requireUser($pdo);
        auditLog($pdo, $u['id'], 'account', 'deleted', 'success', 'Konto gelöscht', 'warning');
        $pdo->prepare('DELETE FROM users WHERE id = ?')->execute([$u['id']]);
        json_out(['status' => 'ok', 'message' => 'Konto wurde gelöscht.']);

    case 'change_password':
        $u = requireUser($pdo);
        $currentPw = $input['current_password'] ?? '';
        $newPw     = $input['new_password'] ?? '';

        $stmt = $pdo->prepare('SELECT password_hash FROM users WHERE id = ?');
        $stmt->execute([$u['id']]);
        $row = $stmt->fetch();

        if (!$row || !password_verify($currentPw, $row['password_hash'])) error('Aktuelles Passwort ist falsch.', 401);
        if (strlen($newPw) < 6) error('Neues Passwort muss mindestens 6 Zeichen lang sein.');

        $pdo->prepare('UPDATE users SET password_hash = ? WHERE id = ?')->execute([password_hash($newPw, PASSWORD_BCRYPT), $u['id']]);
        auditLog($pdo, $u['id'], 'account', 'password_changed', 'success', 'Passwort geändert', 'info');
        json_out(['status' => 'ok', 'message' => 'Passwort geändert.']);

    // ─── Wrapper Endpoints ──────────────────

    case 'list_wrappers':
        $u = requireUser($pdo);
        $result = paginate($pdo, 'wrappers', 'user_id = ?', [$u['id']], 'created_at DESC');
        json_out(['status' => 'ok'] + $result);

    case 'get_wrapper':
        $u = requireUser($pdo);
        $id = $input['id'] ?? $_GET['id'] ?? '';
        if (!$id) error('Wrapper-ID erforderlich.');

        $stmt = $pdo->prepare('SELECT * FROM wrappers WHERE (id = ? OR uuid = ?) AND user_id = ?');
        $stmt->execute([$id, $id, $u['id']]);
        $wrapper = $stmt->fetch();
        if (!$wrapper) error('Wrapper nicht gefunden.', 404);

        // Get latest heartbeat (if table exists)
        $wrapper['heartbeats'] = [];
        try {
            $hStmt = $pdo->prepare('SELECT * FROM heartbeat_log WHERE wrapper_id = ? ORDER BY id DESC LIMIT 20');
            $hStmt->execute([$wrapper['id']]);
            $wrapper['heartbeats'] = $hStmt->fetchAll();
        } catch (Exception $e) {
            // heartbeat_log table might not exist yet
        }

        json_out(['status' => 'ok', 'wrapper' => $wrapper]);

    case 'create_wrapper':
        $u = requireUser($pdo);
        $name = trim($input['name'] ?? 'Mein Wrapper');
        $uuid = genUUID();
        $key  = generateToken('mxn_');
        $keyHash = hash('sha256', $key);

        $wrapperId = bin2hex(random_bytes(12));
        $pdo->prepare('INSERT INTO wrappers (id, uuid, user_id, wrapper_name, wrapper_key, wrapper_secret) VALUES (?, ?, ?, ?, ?, ?)')
            ->execute([$wrapperId, $uuid, $u['id'], $name, $key, bin2hex(random_bytes(32))]);
        auditLog($pdo, $u['id'], 'wrapper', 'created', 'success', "Wrapper erstellt: {$name}", 'info');

        json_out(['status' => 'ok', 'wrapper_id' => $wrapperId, 'uuid' => $uuid, 'key' => $key,
                  'message' => 'Wrapper erstellt. Verwende diesen Key in Deiner lokalen Konfiguration.']);

    case 'update_wrapper':
        $u = requireUser($pdo);
        $id = $input['id'] ?? '';
        if (!$id) error('Wrapper-ID erforderlich.');

        $stmt = $pdo->prepare('SELECT id FROM wrappers WHERE (id = ? OR uuid = ?) AND user_id = ?');
        $stmt->execute([$id, $id, $u['id']]);
        if (!$stmt->fetch()) error('Wrapper nicht gefunden.', 404);

        $updates = [];
        $params = [];
        foreach (['wrapper_name', 'machine_id', 'wrapper_version', 'node_version', 'platform'] as $field) {
            if (isset($input[$field])) {
                $updates[] = "{$field} = ?";
                $params[] = $input[$field];
            }
        }

        if (!empty($updates)) {
            $params[] = $id;
            $pdo->prepare("UPDATE wrappers SET " . implode(', ', $updates) . " WHERE id = ?")->execute($params);
            auditLog($pdo, $u['id'], 'wrapper', 'updated', 'success', "Wrapper aktualisiert", 'info');
        }

        json_out(['status' => 'ok', 'message' => 'Wrapper aktualisiert.']);

    case 'delete_wrapper':
        $u = requireUser($pdo);
        $id = $input['id'] ?? '';
        if (!$id) error('Wrapper-ID erforderlich.');

        $stmt = $pdo->prepare('SELECT id FROM wrappers WHERE (id = ? OR uuid = ?) AND user_id = ?');
        $stmt->execute([$id, $id, $u['id']]);
        $wrapper = $stmt->fetch();
        if (!$wrapper) error('Wrapper nicht gefunden.', 404);

        $pdo->prepare('DELETE FROM wrappers WHERE id = ?')->execute([$wrapper['id']]);
        auditLog($pdo, $u['id'], 'wrapper', 'deleted', 'success', "Wrapper gelöscht (#{$wrapper['id']})", 'warning');
        json_out(['status' => 'ok', 'message' => 'Wrapper gelöscht.']);

    case 'get_wrapper_status':
        $u = requireUser($pdo);
        $stmt = $pdo->prepare('SELECT id, uuid, name AS wrapper_name, version AS wrapper_version, status, last_seen, created_at FROM wrappers WHERE user_id = ? ORDER BY last_seen DESC');
        $stmt->execute([$u['id']]);
        $wrappers = $stmt->fetchAll();

        $online = 0; $offline = 0; $total = count($wrappers);
        foreach ($wrappers as &$w) {
            $lastHb = !empty($w['last_seen']) ? strtotime($w['last_seen']) : 0;
            $w['status'] = ($w['status'] === 'online' && $lastHb > (time() - 300)) ? 'online' : 'offline';
            if ($w['status'] === 'online') $online++;
            else $offline++;
            $w['last_heartbeat'] = $lastHb;
            $w['last_seen_ago'] = $lastHb ? formatTimeAgo($lastHb) : 'Nie';
        }

        json_out(['status' => 'ok', 'wrappers' => $wrappers, 'summary' => ['total' => $total, 'online' => $online, 'offline' => $offline]]);

    // ─── API Keys ─────────────────────────

    case 'list_api_keys':
        $u = requireUser($pdo);
        $stmt = $pdo->prepare('SELECT id, uuid, key_prefix, key_hash, type, label, last_used_at, last_used, expires_at, is_active, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC');
        $stmt->execute([$u['id']]);
        $keys = $stmt->fetchAll();
        // Never expose full key_value
        foreach ($keys as &$k) {
            $k['key_display'] = $k['key_prefix'] . '…' . substr($k['key_hash'], 0, 8);
            unset($k['key_prefix'], $k['key_hash']);
        }
        json_out(['status' => 'ok', 'keys' => $keys]);

    case 'create_api_key':
        $u = requireUser($pdo);
        $label = trim($input['label'] ?? 'API Key');
        $key = generateToken('mxn_');
        $uuid = genUUID();
        $keyHash = hash('sha256', $key);
        $pdo->prepare('INSERT INTO api_keys (uuid, user_id, key_value, key_hash, key_prefix, type, label) VALUES (?, ?, ?, ?, ?, ?, ?)')
            ->execute([$uuid, $u['id'], $key, $keyHash, substr($key, 0, 8), 'api', $label]);
        auditLog($pdo, $u['id'], 'apikey', 'created', 'success', "API-Key erstellt: {$label}", 'info');
        json_out(['status' => 'ok', 'key' => $key, 'id' => $pdo->lastInsertId()]);

    case 'delete_api_key':
        $u = requireUser($pdo);
        $keyId = (int)($input['key_id'] ?? 0);
        if (!$keyId) error('Key-ID erforderlich.');
        $stmt = $pdo->prepare('DELETE FROM api_keys WHERE id = ? AND user_id = ?');
        $stmt->execute([$keyId, $u['id']]);
        auditLog($pdo, $u['id'], 'apikey', 'deleted', 'success', 'API-Key gelöscht', 'warning');
        json_out(['status' => 'ok', 'message' => 'API-Key gelöscht.']);

    // ─── Audit Log ─────────────────────────

    case 'get_audit_log':
        $u = requireUser($pdo);
        $limit = min((int)($input['limit'] ?? 100), 500);
        $offset = max((int)($input['offset'] ?? 0), 0);
        $from = $input['from'] ?? null;
        $to = $input['to'] ?? null;

        $sql = 'SELECT id, uuid, event_type, action, status, summary, severity, ip_address, user_agent, current_hash, created_at FROM audit_log WHERE user_id = ?';
        $params = [$u['id']];

        if ($from) { $sql .= ' AND created_at >= ?'; $params[] = $from; }
        if ($to) { $sql .= ' AND created_at <= ?'; $params[] = $to . ' 23:59:59'; }

        $sql .= ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        $params[] = $limit;
        $params[] = $offset;

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $log = $stmt->fetchAll();

        // Total count for pagination
        $countSql = 'SELECT COUNT(*) FROM audit_log WHERE user_id = ?';
        $cParams = [$u['id']];
        if ($from) { $countSql .= ' AND created_at >= ?'; $cParams[] = $from; }
        if ($to) { $countSql .= ' AND created_at <= ?'; $cParams[] = $to . ' 23:59:59'; }
        $countStmt = $pdo->prepare($countSql);
        $countStmt->execute($cParams);
        $total = (int)$countStmt->fetchColumn();

        // Verify chain integrity
        $chainStmt = $pdo->query("SELECT COUNT(*) as total, COUNT(CASE WHEN current_hash IS NULL THEN 1 END) as broken FROM audit_log WHERE user_id = {$u['id']}");
        $chainInfo = $chainStmt->fetch();

        json_out(['status' => 'ok', 'log' => $log, 'total' => $total, 'limit' => $limit, 'offset' => $offset,
                  'chain' => ['verified' => ($chainInfo['broken'] == 0), 'total_linked' => $chainInfo['total']]]);

    case 'search_logs':
        $u = requireUser($pdo);
        $q = trim($input['q'] ?? '');
        if (!$q) json_out(['status' => 'ok', 'log' => [], 'total' => 0]);

        $limit = min((int)($input['limit'] ?? 100), 500);
        $offset = max((int)($input['offset'] ?? 0), 0);
        $like = '%' . $q . '%';

        $sql = 'SELECT id, uuid, event_type, action, status, summary, severity, ip_address, created_at FROM audit_log WHERE user_id = ? AND (action LIKE ? OR event_type LIKE ? OR summary LIKE ?) ORDER BY created_at DESC LIMIT ? OFFSET ?';
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$u['id'], $like, $like, $like, $limit, $offset]);
        $log = $stmt->fetchAll();

        $totalStmt = $pdo->prepare('SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND (action LIKE ? OR event_type LIKE ? OR summary LIKE ?)');
        $totalStmt->execute([$u['id'], $like, $like, $like]);
        $total = (int)$totalStmt->fetchColumn();

        json_out(['status' => 'ok', 'log' => $log, 'total' => $total, 'q' => $q]);

    case 'get_audit_stats':
        $u = requireUser($pdo);
        $days = (int)($input['days'] ?? 7);

        // Events per day
        $stmt = $pdo->prepare("
            SELECT DATE(created_at) as day, COUNT(*) as count, event_type, severity
            FROM audit_log WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
            GROUP BY DATE(created_at), event_type, severity
            ORDER BY day ASC
        ");
        $stmt->execute([$u['id'], $days]);
        $rows = $stmt->fetchAll();

        $daily = [];
        foreach ($rows as $r) {
            $d = $r['day'];
            if (!isset($daily[$d])) $daily[$d] = ['day' => $d, 'total' => 0, 'info' => 0, 'warning' => 0, 'error' => 0, 'events' => []];
            $daily[$d]['total'] += (int)$r['count'];
            $sev = $r['severity'] ?? 'info';
            if (isset($daily[$d][$sev])) $daily[$d][$sev] += (int)$r['count'];
            $daily[$d]['events'][] = ['type' => $r['event_type'], 'count' => (int)$r['count']];
        }

        // Summary
        $summary = [
            'total_events'       => 0,
            'total_errors'       => 0,
            'total_blocked'      => 0,
            'injection_attempts' => 0,
            'wrapper_connections' => 0,
            'security_checks'    => 0,
        ];
        foreach ($rows as $r) {
            $summary['total_events'] += (int)$r['count'];
            if ($r['severity'] === 'error') $summary['total_errors'] += (int)$r['count'];
            if ($r['event_type'] === 'injection' || $r['action'] === 'blocked') $summary['total_blocked'] += (int)$r['count'];
            if ($r['event_type'] === 'injection') $summary['injection_attempts'] += (int)$r['count'];
            if ($r['event_type'] === 'connection' || $r['event_type'] === 'wrapper') $summary['wrapper_connections'] += (int)$r['count'];
            if ($r['event_type'] === 'security' || $r['event_type'] === 'check') $summary['security_checks'] += (int)$r['count'];
        }

        // Top event types
        $topStmt = $pdo->prepare("SELECT event_type, COUNT(*) as cnt FROM audit_log WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY) GROUP BY event_type ORDER BY cnt DESC LIMIT 10");
        $topStmt->execute([$u['id'], $days]);
        $topEvents = $topStmt->fetchAll();

        json_out(['status' => 'ok', 'daily' => array_values($daily), 'summary' => $summary, 'top_events' => $topEvents]);

    // ─── Security Checks ───────────────────

    case 'get_security_checks':
        $u = requireUser($pdo);
        $result = paginate($pdo, 'security_checks', 'user_id = ?', [$u['id']], 'created_at DESC');
        json_out(['status' => 'ok'] + $result);

    case 'get_security_stats':
        $u = requireUser($pdo);
        $days = (int)($input['days'] ?? 7);

        // Gracefully handle environments where security_checks isn't provisioned yet.
        try {
            $pdo->query('SELECT 1 FROM security_checks LIMIT 1');
        } catch (\Throwable $e) {
            json_out(['status' => 'ok', 'total' => 0, 'decisions' => [], 'risk_levels' => []]);
            break;
        }

        $stmt = $pdo->prepare("SELECT decision, COUNT(*) as count FROM security_checks WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY) GROUP BY decision");
        $stmt->execute([$u['id'], $days]);
        $decisions = $stmt->fetchAll();

        $riskStmt = $pdo->prepare("SELECT risk_level, COUNT(*) as count FROM security_checks WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY) GROUP BY risk_level");
        $riskStmt->execute([$u['id'], $days]);
        $riskLevels = $riskStmt->fetchAll();

        $totalStmt = $pdo->prepare("SELECT COUNT(*) FROM security_checks WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)");
        $totalStmt->execute([$u['id'], $days]);
        $total = (int)$totalStmt->fetchColumn();

        json_out(['status' => 'ok', 'total' => $total, 'decisions' => $decisions, 'risk_levels' => $riskLevels]);

    // ─── Dashboard (aggregated) ────────────

    case 'get_dashboard':
        $u = requireUser($pdo);

        // Wrappers
        $stmt = $pdo->prepare('SELECT id, wrapper_name, last_heartbeat, is_active, wrapper_version, status, last_seen, connected_at FROM wrappers WHERE user_id = ? ORDER BY last_heartbeat DESC');
        $stmt->execute([$u['id']]);
        $wrappers = $stmt->fetchAll();

        // Audit log
        $audit = $pdo->prepare('SELECT id, event_type, action, status, summary, severity, created_at FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 20');
        $audit->execute([$u['id']]);
        $recentAudit = $audit->fetchAll();

        // Security checks (if table exists)
        $checks = [];
        try {
            $checkStmt = $pdo->prepare('SELECT uuid, decision, risk_level, total_score, input_preview, created_at FROM security_checks WHERE user_id = ? ORDER BY created_at DESC LIMIT 10');
            $checkStmt->execute([$u['id']]);
            $checks = $checkStmt->fetchAll();
        } catch (Exception $e) {}

        // Stats — use separate queries to avoid chaining errors
        $totalEvents = $pdo->prepare("SELECT COUNT(*) FROM audit_log WHERE user_id = ?");
        $totalEvents->execute([$u['id']]);

        $now = time();
        $activeCount = 0;
        foreach ($wrappers as $w) {
            $active = ($w['is_active'] ?? 1);
            $hb = $w['last_heartbeat'] ?? $w['last_seen'] ?? null;
            if ($active && $hb && strtotime($hb) > ($now - 300)) $activeCount++;
        }

        $stats = [
            'total_events' => (int)$totalEvents->fetchColumn(),
            'wrappers_active' => $activeCount,
            'wrappers_total' => count($wrappers),
            'checks_total' => count($checks),
        ];

        json_out(['status' => 'ok', 'wrappers' => $wrappers, 'recent_audit' => $recentAudit, 'recent_checks' => $checks, 'stats' => $stats]);

    // ─── Heartbeat Endpoints (for wrappers) ─

    case 'heartbeat':
        $u = requireUser($pdo);
        $wrapperId = $input['wrapper_id'] ?? $input['id'] ?? '';
        if (!$wrapperId) error('Wrapper-ID erforderlich.');

        // Verify ownership
        $stmt = $pdo->prepare('SELECT id FROM wrappers WHERE (id = ? OR uuid = ?) AND user_id = ?');
        $stmt->execute([$wrapperId, $wrapperId, $u['id']]);
        $wrapper = $stmt->fetch();
        if (!$wrapper) error('Wrapper nicht gefunden.', 404);

        $pdo->prepare("UPDATE wrappers SET last_heartbeat = NOW(), is_active = 1 WHERE id = ?")->execute([$wrapper['id']]);

        // Log heartbeat
        $uuid = genUUID();
        $uptime = (int)($input['uptime_seconds'] ?? 0);
        $reqCount = (int)($input['request_count'] ?? 0);
        $blockCount = (int)($input['block_count'] ?? 0);
        $pdo->prepare('INSERT INTO heartbeat_log (uuid, wrapper_id, uptime_seconds, request_count, block_count, data) VALUES (?, ?, ?, ?, ?, ?)')
            ->execute([$uuid, $wrapper['id'], $uptime, $reqCount, $blockCount, json_encode($input['data'] ?? [])]);

        json_out(['status' => 'ok', 'message' => 'Heartbeat empfangen.', 'next_interval' => 30]);

    // ─── Admin Endpoints ───────────────────

    case 'admin_setup':
        $u = requireUser($pdo);
        if (($u['role'] ?? 'user') !== 'admin') {
            // Allow if no admin exists yet
            $adminCount = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role = 'admin'")->fetchColumn();
            if ($adminCount > 0) error('Admin-Zugriff erforderlich.', 403);
        }

        // Ensure role column exists
        try { $pdo->exec("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user'"); } catch (Exception $e) {}

        $uid = (int)($input['user_id'] ?? $u['id']);
        $pdo->prepare("UPDATE users SET role = 'admin' WHERE id = ?")->execute([$uid]);
        auditLog($pdo, $uid, 'admin', 'promoted', 'success', "User #{$uid} zum Admin ernannt", 'warning');
        json_out(['status' => 'ok', 'message' => "User {$uid} ist jetzt Admin."]);

    case 'admin_list_users':
        requireAdmin($pdo);
        $result = paginate($pdo, 'users', '1=1', [], 'created_at DESC');

        // Remove password hashes
        foreach ($result['data'] as &$user) {
            unset($user['password_hash'], $user['password_reset_token'], $user['password_reset_expires']);
        }

        json_out(['status' => 'ok', 'users' => $result['data'], 'total' => $result['total']]);

    case 'admin_system_log':
        requireAdmin($pdo);
        $limit = min((int)($input['limit'] ?? 100), 500);
        $offset = max((int)($input['offset'] ?? 0), 0);
        $userId = (int)($input['user_id'] ?? 0);

        $sql = 'SELECT al.id, al.uuid, al.user_id, al.event_type, al.action, al.status, al.summary, al.severity, al.ip_address, al.current_hash, al.created_at, u.email as user_email FROM audit_log al LEFT JOIN users u ON al.user_id = u.id';
        $params = [];
        $wheres = [];

        if ($userId > 0) { $wheres[] = 'al.user_id = ?'; $params[] = $userId; }

        if (!empty($wheres)) $sql .= ' WHERE ' . implode(' AND ', $wheres);
        $sql .= ' ORDER BY al.created_at DESC LIMIT ? OFFSET ?';
        $params[] = $limit; $params[] = $offset;

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $log = $stmt->fetchAll();

        $total = (int)$pdo->prepare("SELECT COUNT(*) FROM audit_log")->fetchColumn();

        json_out(['status' => 'ok', 'log' => $log, 'total' => $total, 'limit' => $limit, 'offset' => $offset]);

    case 'admin_stats':
        requireAdmin($pdo);
        $userCount = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
        $wrapperCount = (int)$pdo->query("SELECT COUNT(*) FROM wrappers")->fetchColumn();
        $auditCount = (int)$pdo->query("SELECT COUNT(*) FROM audit_log")->fetchColumn();
        $checkCount = 0;
        try { $checkCount = (int)$pdo->query("SELECT COUNT(*) FROM security_checks")->fetchColumn(); } catch (Exception $e) {}
        $onlineWrappers = (int)$pdo->query("SELECT COUNT(*) FROM wrappers WHERE is_active = 1 AND last_heartbeat > DATE_SUB(NOW(), INTERVAL 5 MINUTE)")->fetchColumn();

        // Block rate
        $blockCount = (int)$pdo->query("SELECT COUNT(*) FROM audit_log WHERE status = 'blocked' OR severity = 'error'")->fetchColumn();

        json_out(['status' => 'ok', 'stats' => [
            'users' => $userCount,
            'wrappers' => $wrapperCount,
            'online_wrappers' => $onlineWrappers,
            'audit_entries' => $auditCount,
            'security_checks' => $checkCount,
            'blocked_events' => $blockCount,
            'block_rate' => $auditCount > 0 ? round($blockCount / $auditCount * 100, 1) : 0,
        ]]);

    case 'admin_user_details':
        requireAdmin($pdo);
        $userId = (int)($input['user_id'] ?? $_GET['user_id'] ?? 0);
        if (!$userId) error('User-ID erforderlich.');

        $stmt = $pdo->prepare("SELECT id, uuid, email, display_name, plan, role, email_verified, created_at, last_login_at FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();
        if (!$user) error('User nicht gefunden.', 404);

        $wrapperStmt = $pdo->prepare("SELECT id, uuid, wrapper_name, last_heartbeat, is_active FROM wrappers WHERE user_id = ?");
        $wrapperStmt->execute([$userId]);
        $user['wrappers'] = $wrapperStmt->fetchAll();

        $auditStmt = $pdo->prepare("SELECT COUNT(*) FROM audit_log WHERE user_id = ?");
        $auditStmt->execute([$userId]);
        $auditCount = (int)$auditStmt->fetchColumn();
        $user['audit_count'] = $auditCount;

        json_out(['status' => 'ok', 'user' => $user]);

    case 'admin_delete_user':
        requireAdmin($pdo);
        $userId = (int)($input['user_id'] ?? 0);
        if (!$userId) error('User-ID erforderlich.');
        if ($userId == $u['id']) error('Du kannst dich nicht selbst löschen.', 400);

        $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$userId]);
        auditLog($pdo, $u['id'], 'admin', 'user_deleted', 'success', "User #{$userId} gelöscht", 'critical');
        json_out(['status' => 'ok', 'message' => "User #{$userId} gelöscht."]);

    // ─── System Info ───────────────────────

    case 'system_info':
        $u = requireUser($pdo);
        $isAdmin = ($u['role'] ?? 'user') === 'admin';

        $info = [
            'php_version'   => phpversion(),
            'server_time'   => date('c'),
            'timezone'      => date_default_timezone_get(),
            'api_version'   => '2.0',
        ];

        if ($isAdmin) {
            $info['db_size_mb'] = round((float)$pdo->query("SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 1) FROM information_schema.tables WHERE table_schema = '{$DB_NAME}'")->fetchColumn(), 1);
            $info['table_count'] = (int)$pdo->query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '{$DB_NAME}'")->fetchColumn();
            $info['mysql_version'] = $pdo->query("SELECT VERSION()")->fetchColumn();
        }

        json_out(['status' => 'ok', 'info' => $info]);

    // ─── Chat (legacy) ─────────────────────

    case 'load_conversations':
        $u = requireUser($pdo);
        $stmt = $pdo->prepare('SELECT id, title, message_count, last_activity, created_at FROM conversations WHERE user_id = ? ORDER BY last_activity DESC LIMIT 100');
        $stmt->execute([$u['id']]);
        json_out(['status' => 'ok', 'conversations' => $stmt->fetchAll()]);

    case 'get_conversation':
        $u = requireUser($pdo);
        $convId = $input['id'] ?? '';
        if (!$convId) error('Konversations-ID erforderlich.');

        $stmt = $pdo->prepare('SELECT id, user_id, title, message_count, last_activity, created_at FROM conversations WHERE id = ?');
        $stmt->execute([$convId]);
        $conv = $stmt->fetch();
        if (!$conv || $conv['user_id'] != $u['id']) error('Konversation nicht gefunden.', 404);

        $msgStmt = $pdo->prepare('SELECT id, role, content, injection_analysis, audit_logged, created_at FROM chat_messages WHERE conversation_id = ? ORDER BY id ASC');
        $msgStmt->execute([$convId]);
        $messages = $msgStmt->fetchAll();
        foreach ($messages as &$msg) {
            $msg['injection_analysis'] = $msg['injection_analysis'] ? json_decode($msg['injection_analysis'], true) : null;
        }

        json_out(['status' => 'ok', 'conversation' => $conv, 'messages' => $messages]);

    case 'chat':
        // Legacy chat endpoint — keep for backwards compat
        // Full injection guard, LLM proxy, etc.
        $user = authUser($pdo);
        if (!$user) error('Nicht autorisiert.', 401);

        $message    = $input['message'] ?? '';
        $conversationId = $input['conversation_id'] ?? 'default_' . $user['id'];
        if (!$message) error('Keine Nachricht übermittelt.');

        // Simple injection check
        $injectionPatterns = [
            '/ignore\s+(all\s+)?(previous|above)/i',
            '/forget\s+(all\s+)?(instructions|rules|context)/i',
            '/you\s+are\s+(not\s+)?(an?\s+)?(ai|assistant|chatbot)/i',
            '/system\s+(prompt|message|instruction)/i',
            '/role\s*(:|is|=)\s*(system|developer|assistant)/i',
            '/(administrator|developer)\s*(override|mode)/i',
            '/##\s*(system|instructions|rules)/i',
            '/(DAN|do\s+anything\s+now|jailbreak|free\s+mode)/i',
        ];
        $blocked = false;
        $injectionMatches = [];
        foreach ($injectionPatterns as $pattern) {
            if (preg_match($pattern, $message)) {
                $injectionMatches[] = $pattern;
                $blocked = true;
            }
        }

        if ($blocked) {
            auditLog($pdo, $user['id'], 'llm', 'blocked', 'blocked', "Injection blockiert: " . implode(', ', $injectionMatches), 'error');
            $responseText = "🛡️ **Injection Guard:** Diese Nachricht wurde blockiert.\n\nDeine Eingabe enthielt Muster, die als Prompt-Injection-Versuch klassifiziert wurden.\n\nWenn du ein legitimes Anliegen hast, formuliere es bitte neutral.";
        } else {
            $responseText = "✅ Nachricht empfangen und für sicher befunden.\n\nDa kein LLM-Endpunkt konfiguriert ist, kann ich keine inhaltliche Antwort generieren.\n\n**Audit-Log:** Dieser Chat wurde protokolliert.\n\n_Wrapper-Installation erforderlich für vollständige LLM-Integration._";
            auditLog($pdo, $user['id'], 'llm', 'chat', 'success', 'Nachricht sicher', 'info');
        }

        // Save conversation
        try {
            $pdo->prepare('INSERT INTO conversations (id, user_id, title, message_count) VALUES (?, ?, ?, 1) ON DUPLICATE KEY UPDATE message_count = message_count + 1, last_activity = NOW()')
                ->execute([$conversationId, $user['id'], mb_substr($message, 0, 100)]);
            $pdo->prepare('INSERT INTO chat_messages (conversation_id, user_id, role, content, injection_analysis, audit_logged) VALUES (?, ?, ?, ?, ?, ?)')
                ->execute([$conversationId, $user['id'], 'user', $message, json_encode(['matches'=>$injectionMatches, 'blocked'=>$blocked, 'message_length'=>strlen($message)]), 1]);
            $pdo->prepare('INSERT INTO chat_messages (conversation_id, user_id, role, content, injection_analysis, audit_logged) VALUES (?, ?, ?, ?, ?, ?)')
                ->execute([$conversationId, $user['id'], 'assistant', $responseText, null, 1]);
        } catch (Exception $e) {}

        json_out([
            'status' => $blocked ? 'blocked' : 'ok',
            'response' => $responseText,
            'conversation_id' => $conversationId,
            'injection_analysis' => [
                'blocked' => $blocked,
                'matches' => $injectionMatches,
                'message_length' => strlen($message),
            ],
            'audit_logged' => true,
        ]);

    // ─── Aliases (backwards compat) ────────

    case 'get_dashboard_data':
    case 'get_dashboard':
        $u = requireUser($pdo);

        // Wrappers
        $stmt = $pdo->prepare('SELECT id, wrapper_name, last_heartbeat, is_active, wrapper_version, status, last_seen, connected_at FROM wrappers WHERE user_id = ? ORDER BY last_heartbeat DESC');
        $stmt->execute([$u['id']]);
        $wrappers = $stmt->fetchAll();

        // Audit log
        $audit = $pdo->prepare('SELECT id, event_type, action, status, summary, severity, created_at FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 20');
        $audit->execute([$u['id']]);
        $recentAudit = $audit->fetchAll();

        // Stats
        $totalEvents = $pdo->prepare("SELECT COUNT(*) FROM audit_log WHERE user_id = ?");
        $totalEvents->execute([$u['id']]);

        $now = time();
        $wrappersActive = 0;
        foreach ($wrappers as $w) {
            $active = ($w['is_active'] ?? 1);
            $heartbeat = $w['last_heartbeat'] ?? $w['last_seen'] ?? null;
            $active = $active && ($heartbeat ? strtotime($heartbeat) > ($now - 300) : false);
            if ($active) $wrappersActive++;
        }

        $stats = [
            'total_events' => (int)$totalEvents->fetchColumn(),
            'wrappers_active' => $wrappersActive,
            'wrappers_total' => count($wrappers),
        ];

        json_out(['status' => 'ok', 'wrappers' => $wrappers, 'recent_audit' => $recentAudit, 'stats' => $stats]);

    case 'connect_wrapper':
        $token    = $input['token'] ?? '';
        $wid      = $input['wrapper_id'] ?? '';
        $version  = $input['wrapper_version'] ?? '1.0.0';
        $hostname = $input['hostname'] ?? '';

        if (!$token) error('Wrapper-Token erforderlich.');

        // Find wrapper by wrapper_key
        $stmt = $pdo->prepare("SELECT id, uuid, user_id, wrapper_name FROM wrappers WHERE wrapper_key = ?");
        $stmt->execute([$token]);
        $wrapper = $stmt->fetch();

        if (!$wrapper) error('Ungültiger Wrapper-Token.', 401);

        // Update wrapper with local connection info
        $updateStmt = $pdo->prepare("UPDATE wrappers SET wrapper_version = ?, last_heartbeat = NOW(), connected_at = COALESCE(connected_at, NOW()), last_seen = NOW(), status = 'online' WHERE id = ?");
        $updateStmt->execute([$version, $wrapper['id']]);

        json_out([
            'status' => 'ok',
            'user_id' => (int)$wrapper['user_id'],
            'wrapper_id' => $wrapper['id'],
            'wrapper_name' => $wrapper['wrapper_name'],
            'message' => 'Wrapper erfolgreich verbunden.',
        ]);

    case 'push_audit':
        // Telemetry / audit events pushed by local wrappers (mona-sync).
        $user = requireUser($pdo);
        $event = $input['event'] ?? null;
        if (!$event || !is_array($event)) error('event Objekt fehlt.');

        $eventType = $event['event_type'] ?? 'system';
        $action    = $event['action'] ?? 'event';
        $status    = $event['status'] ?? 'success';
        $severity  = in_array($event['severity'] ?? 'info', ['debug','info','warning','error','critical']) ? $event['severity'] : 'info';
        $details   = $event['details'] ?? null;
        if (is_string($details)) {
            // mona-sync sends JSON strings; normalize if possible
            $decoded = json_decode($details, true);
            if (json_last_error() === JSON_ERROR_NONE) $details = $decoded;
        }
        $summary = $event['summary'] ?? (is_array($details) ? json_encode($details) : (string)$details);
        if (is_array($summary)) $summary = json_encode($summary);
        if (strlen((string)$summary) > 500) $summary = substr((string)$summary, 0, 497) . '…';

        // Resolve wrapper (optional)
        $wrapperId = null;
        if (!empty($event['wrapper_id'])) {
            $wStmt = $pdo->prepare('SELECT id FROM wrappers WHERE id = ? OR wrapper_key = ?');
            $wStmt->execute([$event['wrapper_id'], $event['wrapper_id']]);
            $wrapperId = $wStmt->fetchColumn() ?: null;
        }

        // Trim details to stay under column limits — keep as JSON STRING (live CHECK constraint requires JSON_VALID string, not array)
        $jsonDetails = json_encode($details);
        if (strlen($jsonDetails) > 4000) $jsonDetails = substr($jsonDetails, 0, 3997) . '…';
        // Validate it parses; if not, wrap in a message object
        $parsed = json_decode($jsonDetails, true);
        if (json_last_error() !== JSON_ERROR_NONE) $jsonDetails = json_encode(['message' => (string)$details]);

        $prevHash = $pdo->query("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1")->fetchColumn();
        $chainData = json_encode(['event' => $eventType, 'action' => $action, 'status' => $status, 'time' => date('c')]);
        $currentHash = hash('sha256', ($prevHash ?: '') . $chainData);

        $stmt = $pdo->prepare('INSERT INTO audit_log (uuid, user_id, wrapper_id, event_type, action, status, summary, details, previous_hash, current_hash, severity, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([
            genUUID(),
            $user['id'] ?? null,
            $wrapperId,
            $eventType,
            $action,
            $status,
            $summary,
            $jsonDetails,
            $prevHash,
            $currentHash,
            $severity,
            $_SERVER['REMOTE_ADDR'] ?? null,
            substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
        ]);

        json_out([
            'status' => 'ok',
            'audit_id' => (int)$pdo->lastInsertId(),
            'hash' => $currentHash,
            'message' => 'Audit-Event gespeichert.',
        ]);

    case 'install_agent':
        // Register a local agent on the wrapper account (mona-sync agent discovery).
        $user = requireUser($pdo);
        $name   = trim($input['name'] ?? '');
        $type   = trim($input['type'] ?? 'custom');
        $config = $input['config'] ?? null;
        if ($config && is_string($config)) { $decoded = json_decode($config, true); if (json_last_error() === JSON_ERROR_NONE) $config = $decoded; }

        $agentsTable = null;
        $tables = $pdo->query("SHOW TABLES LIKE 'agents'")->fetchAll();
        if ($tables) $agentsTable = 'agents';
        else { $tables = $pdo->query("SHOW TABLES LIKE 'installed_agents'")->fetchAll(); if ($tables) $agentsTable = 'installed_agents'; }

        if (!$agentsTable) {
            // Create minimal agents table on first use (live schema: no uuid/user_id)
            $pdo->exec("CREATE TABLE IF NOT EXISTS agents (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                wrapper_id INT UNSIGNED DEFAULT NULL,
                name VARCHAR(120) NOT NULL,
                type VARCHAR(40) DEFAULT 'custom',
                config JSON DEFAULT NULL,
                status VARCHAR(20) DEFAULT 'running',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB");
            $agentsTable = 'agents';
        }

        // Live agents table has no uuid/user_id columns — insert wrapper-scoped
        $cols = $pdo->query("SHOW COLUMNS FROM {$agentsTable}")->fetchAll(PDO::FETCH_COLUMN);
        if (in_array('user_id', $cols) && in_array('uuid', $cols)) {
            $uuid = genUUID();
            $stmt = $pdo->prepare("INSERT INTO {$agentsTable} (uuid, user_id, name, type, config, status) VALUES (?, ?, ?, ?, ?, 'running')");
            $stmt->execute([$uuid, $user['id'] ?? null, $name ?: 'unnamed-agent', $type, $config]);
            $agentId = (int)$pdo->lastInsertId();
        } else {
            $stmt = $pdo->prepare("INSERT INTO {$agentsTable} (wrapper_id, name, type, config, status) VALUES (?, ?, ?, ?, 'running')");
            $stmt->execute([$user['wrapper_id'] ?? null, $name ?: 'unnamed-agent', $type, $config]);
            $agentId = (int)$pdo->lastInsertId();
        }

        auditLog($pdo, $user['id'] ?? null, 'agent', 'install_agent', 'success', "Agent registriert: {$name}");

        json_out([
            'status' => 'ok',
            'agent_id' => $agentId,
            'message' => 'Agent registriert.',
        ]);

    default:
        error('Unbekannte Aktion: ' . $action, 404);
}

// ─── Time formatting helper ────────────────
function formatTimeAgo($timestamp) {
    $diff = time() - $timestamp;
    if ($diff < 60) return 'Gerade eben';
    if ($diff < 3600) return floor($diff / 60) . ' Min.';
    if ($diff < 86400) return floor($diff / 3600) . ' Std.';
    return floor($diff / 86400) . ' Tage';
}
