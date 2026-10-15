<?php
/**
 * CSRF Protection
 * Generates and validates CSRF tokens to prevent cross-site request forgery.
 */

if (!defined('APP_INIT')) {
    define('APP_INIT', true);
}

function csrfStart(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

/**
 * Generate (or reuse) a CSRF token for the current session.
 */
function csrfToken(): string {
    csrfStart();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Output a hidden CSRF input field.
 */
function csrfField(): string {
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrfToken()) . '">';
}

/**
 * Validate the submitted CSRF token against the session token.
 * Rejects the request with 403 if invalid.
 */
function csrfVerify(): void {
    csrfStart();
    $submitted = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $expected  = $_SESSION['csrf_token'] ?? '';

    if (empty($submitted) || empty($expected) || !hash_equals($expected, $submitted)) {
        require_once __DIR__ . '/auth.php';
        $user = getCurrentUser();
        logSecurityEvent(
            $user['id'] ?? null,
            'CSRF_VALIDATION_FAILED',
            'Invalid or missing CSRF token on ' . ($_SERVER['REQUEST_URI'] ?? ''),
            getClientIP(),
            'DENIED'
        );
        http_response_code(403);
        die(json_encode(['error' => 'Invalid CSRF token. Request rejected.']));
    }

    // Rotate token after successful POST to further limit replay
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
