<?php
/**
 * Authentication & Session Management
 * Secure Role-Based Access Control (RBAC) Admin Panel
 */

if (!defined('APP_INIT')) {
    define('APP_INIT', true);
}

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/permissions.php';

// -------------------------------------------------------
// Secure Session Configuration
// -------------------------------------------------------
function startSecureSession(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'secure'   => false, // Set true in HTTPS production
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
    }
}

// -------------------------------------------------------
// Rate Limiting: Login Attempts
// -------------------------------------------------------
function getLoginAttempts(string $ip, string $email): int {
    try {
        $db = getDB();
        $window = date('Y-m-d H:i:s', strtotime('-15 minutes'));
        $stmt = $db->prepare(
            "SELECT COUNT(*) FROM login_attempts 
             WHERE (ip_address = ? OR email = ?) AND attempted_at >= ?"
        );
        $stmt->execute([$ip, $email, $window]);
        return (int)$stmt->fetchColumn();
    } catch (Throwable $e) {
        return 0;
    }
}

function recordLoginAttempt(string $ip, string $email): void {
    try {
        $db = getDB();
        $stmt = $db->prepare(
            "INSERT INTO login_attempts (ip_address, email, attempted_at) VALUES (?, ?, CURRENT_TIMESTAMP)"
        );
        $stmt->execute([$ip, $email]);
    } catch (Throwable $e) {
        // fail silently
    }
}

function clearLoginAttempts(string $ip, string $email): void {
    try {
        $db = getDB();
        $stmt = $db->prepare(
            "DELETE FROM login_attempts WHERE ip_address = ? OR email = ?"
        );
        $stmt->execute([$ip, $email]);
    } catch (Throwable $e) {}
}

function getMaxLoginAttempts(): int {
    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT key_value FROM system_settings WHERE key_name = 'max_login_attempts'");
        $stmt->execute();
        return (int)($stmt->fetchColumn() ?: 5);
    } catch (Throwable $e) {
        return 5;
    }
}

// -------------------------------------------------------
// Core Auth Functions
// -------------------------------------------------------

/**
 * Check if the current user is authenticated.
 */
function isAuthenticated(): bool {
    startSecureSession();
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

/**
 * Redirect unauthenticated users to login.
 */
function requireLogin(): void {
    if (!isAuthenticated()) {
        $redirect = urlencode($_SERVER['REQUEST_URI'] ?? '');
        header("Location: /auth/login.php?redirect=$redirect");
        exit;
    }
    // Session timeout check
    $timeout = 30 * 60; // 30 minutes
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout) {
        session_unset();
        session_destroy();
        header("Location: /auth/login.php?reason=timeout");
        exit;
    }
    $_SESSION['last_activity'] = time();
}

/**
 * Get the currently logged-in user's full data.
 */
function getCurrentUser(): ?array {
    if (!isAuthenticated()) {
        return null;
    }
    if (isset($_SESSION['user_cache'])) {
        return $_SESSION['user_cache'];
    }
    try {
        $db = getDB();
        $stmt = $db->prepare(
            "SELECT u.id, u.name, u.email, u.is_active, u.last_login_at, u.created_at,
                    r.id AS role_id, r.name AS role_name, r.slug AS role_slug
             FROM users u
             JOIN roles r ON u.role_id = r.id
             WHERE u.id = ? AND u.is_active = 1"
        );
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch();
        if (!$user) {
            // User deactivated mid-session
            session_unset();
            session_destroy();
            header("Location: /auth/login.php?reason=deactivated");
            exit;
        }
        $_SESSION['user_cache'] = $user;
        return $user;
    } catch (Throwable $e) {
        return null;
    }
}

/**
 * Attempt login. Returns ['success'=>bool, 'error'=>string|null, 'user'=>array|null]
 */
function attemptLogin(string $email, string $password, string $ip): array {
    $maxAttempts = getMaxLoginAttempts();
    $attempts = getLoginAttempts($ip, $email);

    if ($attempts >= $maxAttempts) {
        logSecurityEvent(null, 'LOGIN_BLOCKED', "Rate limit exceeded for $email from $ip", $ip, 'DENIED');
        return ['success' => false, 'error' => 'Too many failed attempts. Please wait 15 minutes before trying again.'];
    }

    try {
        $db = getDB();
        $stmt = $db->prepare(
            "SELECT u.id, u.name, u.email, u.password_hash, u.is_active,
                    r.id AS role_id, r.name AS role_name, r.slug AS role_slug
             FROM users u JOIN roles r ON u.role_id = r.id
             WHERE u.email = ?"
        );
        $stmt->execute([strtolower(trim($email))]);
        $user = $stmt->fetch();

        if (!$user) {
            recordLoginAttempt($ip, $email);
            logSecurityEvent(null, 'LOGIN_FAILED', "No account found for email: $email", $ip, 'FAILED');
            return ['success' => false, 'error' => 'Invalid email or password.'];
        }

        if (!$user['is_active']) {
            logSecurityEvent($user['id'], 'LOGIN_DENIED', "Inactive account login attempt: $email", $ip, 'DENIED');
            return ['success' => false, 'error' => 'Your account has been deactivated. Contact an administrator.'];
        }

        if (!password_verify($password, $user['password_hash'])) {
            recordLoginAttempt($ip, $email);
            logSecurityEvent($user['id'], 'LOGIN_FAILED', "Wrong password for: $email", $ip, 'FAILED');
            return ['success' => false, 'error' => 'Invalid email or password.'];
        }

        // Successful login
        clearLoginAttempts($ip, $email);

        // Regenerate session ID to prevent fixation
        session_regenerate_id(true);

        $_SESSION['user_id']       = $user['id'];
        $_SESSION['user_role']     = $user['role_slug'];
        $_SESSION['last_activity'] = time();
        unset($_SESSION['user_cache']);

        // Update last_login_at
        $upd = $db->prepare("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?");
        $upd->execute([$user['id']]);

        logSecurityEvent($user['id'], 'LOGIN_SUCCESS', "User '{$user['email']}' logged in successfully.", $ip, 'SUCCESS');

        return ['success' => true, 'error' => null, 'user' => $user];

    } catch (Throwable $e) {
        return ['success' => false, 'error' => 'A system error occurred. Please try again.'];
    }
}

/**
 * Log out the current user.
 */
function performLogout(): void {
    startSecureSession();
    $user = getCurrentUser();
    $ip   = getClientIP();
    if ($user) {
        logSecurityEvent($user['id'], 'LOGOUT', "User '{$user['email']}' logged out.", $ip, 'SUCCESS');
    }
    session_unset();
    session_destroy();
    session_start();
    session_regenerate_id(true);
}

/**
 * Get the client's IP address safely.
 */
function getClientIP(): string {
    foreach (['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = trim(explode(',', $_SERVER[$key])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

/**
 * Log a security event to the audit_logs table.
 */
function logSecurityEvent(?int $userId, string $eventType, string $description, string $ip = '', string $status = 'SUCCESS'): void {
    if (empty($ip)) {
        $ip = getClientIP();
    }
    try {
        $db = getDB();
        $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 255);
        $stmt = $db->prepare(
            "INSERT INTO audit_logs (user_id, event_type, description, ip_address, user_agent, status, created_at)
             VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)"
        );
        $stmt->execute([$userId, $eventType, $description, $ip, $ua, $status]);
    } catch (Throwable $e) {
        // fail silently — never break the application for a log error
    }
}
