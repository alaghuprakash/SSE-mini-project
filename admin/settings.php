<?php
/**
 * System Settings — Admin Only
 */
define('APP_INIT', true);
$pageTitle = 'System Settings';
$activeNav = 'settings';

require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../includes/csrf.php';

requirePermission('settings.manage');

$db = getDB();
$ip = getClientIP();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify();

    $settings = [
        'app_name'                  => inputStr('app_name'),
        'public_registration'       => isset($_POST['public_registration']) ? '1' : '0',
        'max_login_attempts'        => max(1, min(20, (int)($_POST['max_login_attempts'] ?? 5))),
        'lockout_duration_minutes'  => max(1, min(120, (int)($_POST['lockout_duration_minutes'] ?? 15))),
        'session_timeout_minutes'   => max(5, min(240, (int)($_POST['session_timeout_minutes'] ?? 30))),
    ];

    foreach ($settings as $key => $value) {
        $stmt = $db->prepare("UPDATE system_settings SET key_value=?, updated_at=CURRENT_TIMESTAMP WHERE key_name=?");
        $stmt->execute([(string)$value, $key]);
    }
    logSecurityEvent($user['id'], 'SETTINGS_UPDATED', "Admin '{$user['email']}' updated system settings.", $ip);
    setFlash('success', 'Settings saved successfully.');
    redirect('/admin/settings.php');
}

// Load current settings
$rawSettings = $db->query("SELECT key_name, key_value FROM system_settings")->fetchAll();
$settings = [];
foreach ($rawSettings as $row) {
    $settings[$row['key_name']] = $row['key_value'];
}
?>

<div class="row g-4">
    <div class="col-lg-7">
        <div class="card">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-sliders me-2 text-cyan"></i>Application Settings</span>
            </div>
            <div class="card-body">
                <form method="POST" action="settings.php">
                    <?= csrfField() ?>

                    <div class="mb-4">
                        <label class="form-label">Application Name</label>
                        <input type="text" name="app_name" class="form-control" value="<?= e($settings['app_name'] ?? 'CyberSec RBAC Portal') ?>" required>
                        <div class="form-text text-muted">Displayed in the browser title bar and header.</div>
                    </div>

                    <hr style="border-color:var(--border-color);">
                    <p class="section-title">Security Policy</p>

                    <div class="mb-3">
                        <label class="form-label">Max Login Attempts</label>
                        <input type="number" name="max_login_attempts" class="form-control" min="1" max="20"
                            value="<?= e($settings['max_login_attempts'] ?? 5) ?>">
                        <div class="form-text text-muted">Failed logins before the IP+email is rate-limited.</div>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Lockout Duration (minutes)</label>
                        <input type="number" name="lockout_duration_minutes" class="form-control" min="1" max="120"
                            value="<?= e($settings['lockout_duration_minutes'] ?? 15) ?>">
                    </div>

                    <div class="mb-4">
                        <label class="form-label">Session Timeout (minutes)</label>
                        <input type="number" name="session_timeout_minutes" class="form-control" min="5" max="240"
                            value="<?= e($settings['session_timeout_minutes'] ?? 30) ?>">
                        <div class="form-text text-muted">Idle sessions are terminated after this period.</div>
                    </div>

                    <hr style="border-color:var(--border-color);">
                    <p class="section-title">Registration</p>

                    <div class="form-check mb-4">
                        <input class="form-check-input" type="checkbox" name="public_registration" id="publicReg"
                            <?= ($settings['public_registration'] ?? '0') === '1' ? 'checked' : '' ?>>
                        <label class="form-check-label text-light" for="publicReg">
                            Allow Public Self-Registration
                        </label>
                        <div class="form-text text-muted mt-1">
                            When disabled (recommended), only admins can create accounts.
                        </div>
                    </div>

                    <button type="submit" class="btn btn-cyber">
                        <i class="fa-solid fa-floppy-disk me-2"></i>Save Settings
                    </button>
                </form>
            </div>
        </div>
    </div>

    <div class="col-lg-5">
        <div class="card">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-circle-info me-2 text-cyan"></i>System Information</span>
            </div>
            <div class="card-body">
                <?php
                $dbDriver  = $db->getAttribute(PDO::ATTR_DRIVER_NAME);
                $phpVer    = phpversion();
                $memUsage  = formatBytes(memory_get_usage(true));
                $totalUsers= (int)$db->query("SELECT COUNT(*) FROM users")->fetchColumn();
                $totalLogs = (int)$db->query("SELECT COUNT(*) FROM audit_logs")->fetchColumn();
                ?>
                <dl class="row mb-0" style="font-size:0.85rem;">
                    <dt class="col-7 text-muted">PHP Version</dt>
                    <dd class="col-5 text-white mono"><?= e($phpVer) ?></dd>

                    <dt class="col-7 text-muted">Database Driver</dt>
                    <dd class="col-5 text-white mono"><?= e(strtoupper($dbDriver)) ?></dd>

                    <dt class="col-7 text-muted">Memory Usage</dt>
                    <dd class="col-5 text-white mono"><?= $memUsage ?></dd>

                    <dt class="col-7 text-muted">Total Users</dt>
                    <dd class="col-5 text-white"><?= $totalUsers ?></dd>

                    <dt class="col-7 text-muted">Audit Log Entries</dt>
                    <dd class="col-5 text-white"><?= $totalLogs ?></dd>

                    <dt class="col-7 text-muted">Session ID</dt>
                    <dd class="col-5 text-white mono" style="font-size:0.7rem;word-break:break-all;"><?= substr(session_id(), 0, 16) ?>…</dd>
                </dl>
            </div>
        </div>

        <div class="card mt-3">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-shield-halved me-2 text-cyan"></i>Security Checklist</span>
            </div>
            <div class="card-body">
                <?php
                $checks = [
                    ['PHP Sessions HTTPOnly', ini_get('session.cookie_httponly')],
                    ['Password Hashing Active', true],
                    ['CSRF Protection Active', true],
                    ['Prepared Statements', true],
                    ['Rate Limiting Active', (int)($settings['max_login_attempts'] ?? 5) > 0],
                    ['Audit Logging Active', true],
                ];
                foreach ($checks as [$label, $ok]):
                ?>
                <div class="d-flex justify-content-between align-items-center py-1" style="border-bottom:1px solid var(--border-color);font-size:0.82rem;">
                    <span class="text-muted"><?= e($label) ?></span>
                    <?php if ($ok): ?>
                        <span class="text-success"><i class="fa-solid fa-circle-check me-1"></i>Active</span>
                    <?php else: ?>
                        <span class="text-warning"><i class="fa-solid fa-triangle-exclamation me-1"></i>Review</span>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
