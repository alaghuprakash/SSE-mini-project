<?php
/**
 * Application Entry Point (index.php)
 * Redirects to dashboard if logged in, else to login.
 */
define('APP_INIT', true);
require_once __DIR__ . '/includes/auth.php';

startSecureSession();

if (isAuthenticated()) {
    header('Location: /admin/dashboard.php');
} else {
    header('Location: /auth/login.php');
}
exit;
