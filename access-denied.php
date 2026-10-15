<?php
/**
 * Access Denied — HTTP 403
 * Shown when an authenticated user lacks permission.
 */
if (!defined('APP_INIT')) { define('APP_INIT', true); }
// May be included from requirePermission() or opened directly
if (file_exists(__DIR__ . '/includes/functions.php')) {
    require_once __DIR__ . '/includes/functions.php';
}
$isDirectAccess = (basename($_SERVER['SCRIPT_FILENAME']) === 'access-denied.php');
?>
<?php if ($isDirectAccess): ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 — Access Denied | CyberSec RBAC Portal</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <link href="/assets/css/style.css" rel="stylesheet">
</head>
<body>
<?php endif; ?>

<div class="access-denied-wrapper">
    <div style="text-align:center;max-width:500px;">
        <div style="font-size:5rem;color:rgba(248,113,113,0.7);margin-bottom:1rem;animation:pulse-glow 2s infinite;">
            <i class="fa-solid fa-shield-xmark"></i>
        </div>
        <h1 class="text-white mb-2" style="font-size:1.5rem;font-weight:700;">Access Denied</h1>
        <p class="text-danger" style="font-size:1.75rem;font-weight:800;letter-spacing:0.1em;">403</p>
        <p class="text-muted mb-4" style="font-size:0.9rem;">
            You do not have permission to access this resource.<br>
            This event has been recorded in the security audit log.
        </p>
        <div class="d-flex gap-3 justify-content-center flex-wrap">
            <a href="/admin/dashboard.php" class="btn btn-cyber">
                <i class="fa-solid fa-gauge-high me-2"></i>Back to Dashboard
            </a>
            <a href="javascript:history.back()" class="btn btn-outline-secondary">
                <i class="fa-solid fa-arrow-left me-2"></i>Go Back
            </a>
        </div>
        <div class="mt-4 p-3 rounded" style="background:rgba(248,113,113,0.07);border:1px solid rgba(248,113,113,0.2);font-size:0.78rem;color:var(--text-muted);">
            <i class="fa-solid fa-circle-info me-1"></i>
            If you believe this is an error, contact your system administrator.
        </div>
    </div>
</div>

<?php if ($isDirectAccess): ?>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
<?php endif; ?>
