<?php
/**
 * User Profile Page
 * Logged-in users can view and update their own profile.
 */
define('APP_INIT', true);
$pageTitle = 'My Profile';
$activeNav = 'profile';

require_once __DIR__ . '/includes/header.php';
require_once __DIR__ . '/includes/csrf.php';

$db = getDB();
$ip = getClientIP();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify();
    $action = $_POST['action'] ?? '';

    if ($action === 'update_profile') {
        $name = inputStr('name');
        if (strlen($name) < 2) {
            setFlash('error', 'Name must be at least 2 characters.');
        } else {
            $db->prepare("UPDATE users SET name=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")->execute([$name, $user['id']]);
            unset($_SESSION['user_cache']); // Invalidate cache
            setFlash('success', 'Profile updated.');
            logSecurityEvent($user['id'], 'USER_UPDATED', "User '{$user['email']}' updated their own profile.", $ip);
        }
        redirect('/profile.php');
    }

    if ($action === 'change_password') {
        $current = $_POST['current_password'] ?? '';
        $new     = $_POST['new_password'] ?? '';
        $confirm = $_POST['confirm_password'] ?? '';

        // Fetch current hash
        $stmt = $db->prepare("SELECT password_hash FROM users WHERE id=?");
        $stmt->execute([$user['id']]);
        $hash = $stmt->fetchColumn();

        if (!password_verify($current, $hash)) {
            setFlash('error', 'Current password is incorrect.');
        } elseif (strlen($new) < 8) {
            setFlash('error', 'New password must be at least 8 characters.');
        } elseif ($new !== $confirm) {
            setFlash('error', 'Passwords do not match.');
        } else {
            $newHash = password_hash($new, PASSWORD_DEFAULT);
            $db->prepare("UPDATE users SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")->execute([$newHash, $user['id']]);
            logSecurityEvent($user['id'], 'USER_UPDATED', "User '{$user['email']}' changed their password.", $ip, 'WARNING');
            setFlash('success', 'Password changed successfully.');
        }
        redirect('/profile.php');
    }
}

// Refresh user data
$stmt = $db->prepare("SELECT u.*, r.name AS role_name, r.slug AS role_slug FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?");
$stmt->execute([$user['id']]);
$profile = $stmt->fetch();

// Recent audit events for this user
$myLogs = $db->prepare("SELECT * FROM audit_logs WHERE user_id=? ORDER BY created_at DESC LIMIT 8");
$myLogs->execute([$user['id']]);
$myLogs = $myLogs->fetchAll();
?>

<div class="row g-4">
    <!-- Profile Info -->
    <div class="col-lg-4">
        <div class="card text-center mb-3">
            <div class="card-body py-4">
                <div class="mx-auto mb-3 sidebar-avatar" style="width:72px;height:72px;font-size:1.4rem;">
                    <?= strtoupper(substr($profile['name'], 0, 2)) ?>
                </div>
                <h5 class="text-white mb-1"><?= e($profile['name']) ?></h5>
                <div class="text-muted mb-2" style="font-size:0.83rem;"><?= e($profile['email']) ?></div>
                <span class="role-badge <?= roleBadgeClass($profile['role_slug']) ?>">
                    <i class="fa-solid fa-circle-dot me-1"></i><?= e($profile['role_name']) ?>
                </span>

                <hr style="border-color:var(--border-color);margin:1rem 0;">

                <dl class="text-start" style="font-size:0.82rem;">
                    <dt class="text-muted">Account Status</dt>
                    <dd><?= $profile['is_active'] ? '<span class="status-active">Active</span>' : '<span class="status-inactive">Inactive</span>' ?></dd>
                    <dt class="text-muted mt-2">Member Since</dt>
                    <dd><?= formatDate($profile['created_at']) ?></dd>
                    <dt class="text-muted mt-2">Last Login</dt>
                    <dd><?= $profile['last_login_at'] ? formatDate($profile['last_login_at']) : '—' ?></dd>
                </dl>
            </div>
        </div>

        <!-- Permissions card -->
        <div class="card">
            <div class="card-header">
                <span class="card-title" style="font-size:0.82rem;"><i class="fa-solid fa-key me-2 text-cyan"></i>My Permissions</span>
            </div>
            <div class="card-body py-2">
                <?php
                $myPerms = loadRolePermissions($profile['role_slug']);
                $allPerms = getAllPermissions();
                foreach ($allPerms as $p):
                    $granted = in_array($p['slug'], $myPerms);
                ?>
                <div class="d-flex justify-content-between align-items-center py-1" style="border-bottom:1px solid var(--border-color);font-size:0.78rem;">
                    <span class="text-muted"><?= e($p['name']) ?></span>
                    <?php if ($granted): ?>
                        <i class="fa-solid fa-check text-success"></i>
                    <?php else: ?>
                        <i class="fa-solid fa-xmark text-danger" style="opacity:0.4;"></i>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <!-- Edit Forms -->
    <div class="col-lg-8">
        <!-- Update Profile -->
        <div class="card mb-3">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-user-pen me-2 text-cyan"></i>Update Profile</span>
            </div>
            <div class="card-body">
                <form method="POST" action="profile.php">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="update_profile">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label class="form-label">Full Name</label>
                            <input type="text" name="name" class="form-control" value="<?= e($profile['name']) ?>" required>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Email Address</label>
                            <input type="email" class="form-control" value="<?= e($profile['email']) ?>" disabled>
                            <div class="form-text text-muted">Contact an admin to change email.</div>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-cyber btn-sm mt-3">
                        <i class="fa-solid fa-floppy-disk me-1"></i>Save Changes
                    </button>
                </form>
            </div>
        </div>

        <!-- Change Password -->
        <div class="card mb-3">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-lock me-2 text-cyan"></i>Change Password</span>
            </div>
            <div class="card-body">
                <form method="POST" action="profile.php">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="change_password">
                    <div class="mb-3">
                        <label class="form-label">Current Password</label>
                        <input type="password" name="current_password" class="form-control" required autocomplete="current-password">
                    </div>
                    <div class="row g-3 mb-3">
                        <div class="col-md-6">
                            <label class="form-label">New Password</label>
                            <input type="password" id="password" name="new_password" class="form-control" required minlength="8" autocomplete="new-password">
                            <div class="password-strength-bar mt-1"><div class="password-strength-fill"></div></div>
                            <small class="text-muted" id="strengthLabel"></small>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Confirm New Password</label>
                            <input type="password" name="confirm_password" class="form-control" required minlength="8" autocomplete="new-password">
                        </div>
                    </div>
                    <button type="submit" class="btn btn-outline-cyber btn-sm">
                        <i class="fa-solid fa-key me-1"></i>Update Password
                    </button>
                </form>
            </div>
        </div>

        <!-- My Recent Activity -->
        <div class="card">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-clock-rotate-left me-2 text-cyan"></i>My Recent Activity</span>
            </div>
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead><tr><th>Event</th><th>Status</th><th>IP</th><th>Time</th></tr></thead>
                    <tbody>
                    <?php if (empty($myLogs)): ?>
                        <tr><td colspan="4" class="text-center text-muted py-4">No activity recorded.</td></tr>
                    <?php else: foreach ($myLogs as $log): ?>
                        <tr>
                            <td style="font-size:0.82rem;"><?= e(formatEventType($log['event_type'])) ?></td>
                            <td><span class="badge <?= auditStatusBadge($log['status']) ?>"><?= e($log['status']) ?></span></td>
                            <td class="mono text-muted" style="font-size:0.75rem;"><?= e($log['ip_address']) ?></td>
                            <td style="font-size:0.78rem;color:var(--text-muted);"><?= formatDate($log['created_at']) ?></td>
                        </tr>
                    <?php endforeach; endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
