<?php
/**
 * Logout Handler
 * Destroys the session and redirects to login.
 */
define('APP_INIT', true);
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/functions.php';

startSecureSession();

// CSRF check on POST; for GET allow direct logout link
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify();
}

performLogout();
redirect('/auth/login.php?reason=logout');
