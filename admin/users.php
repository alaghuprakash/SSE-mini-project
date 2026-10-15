<?php
/**
 * User Management — Admin Only
 * List, search, create, edit, activate/deactivate, delete users.
 */
define('APP_INIT', true);
$pageTitle = 'User Management';
$activeNav = 'users';

require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../includes/csrf.php';

requirePermission('users.view');

$db = getDB();
$ip = getClientIP();

// -------------------------------------------------------
// POST Handlers (Create / Update / Toggle / Delete)
// -------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify();
    $action = $_POST['action'] ?? '';

    // --- CREATE USER ---
    if ($action === 'create') {
        requirePermission('users.create');

        $name     = inputStr('name');
        $email    = strtolower(trim($_POST['email'] ?? ''));
        $password = $_POST['password'] ?? '';
        $roleId   = inputInt('role_id');
        $isActive = isset($_POST['is_active']) ? 1 : 0;

        $errors = [];
        if (empty($name))     $errors[] = 'Name is required.';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Valid email required.';
        if (strlen($password) < 8) $errors[] = 'Password must be at least 8 characters.';
        if (!$roleId)         $errors[] = 'Please select a role.';

        // Check duplicate email
        $existing = $db->prepare("SELECT id FROM users WHERE email = ?");
        $existing->execute([$email]);
        if ($existing->fetchColumn()) $errors[] = 'Email is already registered.';

        // Admin guard: prevent non-admin from creating admin accounts
        if ($roleId) {
            $roleRow = $db->prepare("SELECT slug FROM roles WHERE id=?");
            $roleRow->execute([$roleId]);
            $targetSlug = $roleRow->fetchColumn();
            if ($targetSlug === 'admin' && $user['role_slug'] !== 'admin') {
                $errors[] = 'Only administrators can create administrator accounts.';
            }
        }

        if (empty($errors)) {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $db->prepare("INSERT INTO users (name, email, password_hash, role_id, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)");
            $stmt->execute([$name, $email, $hash, $roleId, $isActive]);
            $newId = $db->lastInsertId();
            logSecurityEvent($user['id'], 'USER_CREATED', "Admin '{$user['email']}' created user '$email' (ID $newId).", $ip);
            setFlash('success', "User '$name' created successfully.");
        } else {
            setFlash('error', implode(' ', $errors));
        }
        redirect('/admin/users.php');
    }

    // --- UPDATE USER ---
    if ($action === 'update') {
        requirePermission('users.update');

        $userId   = inputInt('user_id');
        $name     = inputStr('name');
        $email    = strtolower(trim($_POST['email'] ?? ''));
        $roleId   = inputInt('role_id');
        $isActive = isset($_POST['is_active']) ? 1 : 0;
        $newPwd   = $_POST['new_password'] ?? '';

        if (!$userId) { setFlash('error', 'Invalid user ID.'); redirect('/admin/users.php'); }

        // Prevent elevating own privileges
        if ($userId === (int)$user['id']) {
            $roleRow = $db->prepare("SELECT slug FROM roles WHERE id=?");
            $roleRow->execute([$roleId]);
            $targetSlug = $roleRow->fetchColumn();
            $mySlug = $user['role_slug'];
            if ($targetSlug !== $mySlug) {
                logSecurityEvent($user['id'], 'UNAUTHORIZED_ACCESS', "User attempted to change own role via users.php.", $ip, 'DENIED');
                setFlash('error', 'You cannot change your own role.');
                redirect('/admin/users.php');
            }
        }

        // Prevent removing last admin
        if ($isActive === 0 || ($roleId && /* changing role */ true)) {
            $targetRow = $db->prepare("SELECT r.slug FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?");
            $targetRow->execute([$userId]);
            $targetCurrentSlug = $targetRow->fetchColumn();

            $newRoleRow = $db->prepare("SELECT slug FROM roles WHERE id=?");
            $newRoleRow->execute([$roleId]);
            $newSlug = $newRoleRow->fetchColumn();

            if ($targetCurrentSlug === 'admin' && ($newSlug !== 'admin' || $isActive === 0)) {
                $adminCount = (int)$db->query("SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id=r.id WHERE r.slug='admin' AND u.is_active=1")->fetchColumn();
                if ($adminCount <= 1 && $userId !== (int)$user['id']) {
                    setFlash('error', 'Cannot remove the last active administrator.');
                    redirect('/admin/users.php');
                }
            }
        }

        $fields = ['name=?','email=?','role_id=?','is_active=?','updated_at=CURRENT_TIMESTAMP'];
        $params = [$name, $email, $roleId, $isActive];
        if (!empty($newPwd) && strlen($newPwd) >= 8) {
            $fields[] = 'password_hash=?';
            $params[] = password_hash($newPwd, PASSWORD_DEFAULT);
        }
        $params[] = $userId;
        $db->prepare("UPDATE users SET ".implode(',', $fields)." WHERE id=?")->execute($params);

        logSecurityEvent($user['id'], 'USER_UPDATED', "Admin '{$user['email']}' updated user ID $userId.", $ip);
        setFlash('success', 'User updated successfully.');
        redirect('/admin/users.php');
    }

    // --- TOGGLE ACTIVE ---
    if ($action === 'toggle_active') {
        requirePermission('users.update');
        $userId   = inputInt('user_id');
        $targetRow = $db->prepare("SELECT u.is_active, r.slug FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?");
        $targetRow->execute([$userId]);
        $target = $targetRow->fetch();
        if ($target && $target['slug'] === 'admin' && $target['is_active'] == 1) {
            $adminCount = (int)$db->query("SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id=r.id WHERE r.slug='admin' AND u.is_active=1")->fetchColumn();
            if ($adminCount <= 1) { setFlash('error', 'Cannot deactivate the last active administrator.'); redirect('/admin/users.php'); }
        }
        $newStatus = $target['is_active'] ? 0 : 1;
        $db->prepare("UPDATE users SET is_active=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")->execute([$newStatus, $userId]);
        $label = $newStatus ? 'activated' : 'deactivated';
        logSecurityEvent($user['id'], 'USER_UPDATED', "Admin '{$user['email']}' $label user ID $userId.", $ip);
        setFlash('success', "User account $label.");
        redirect('/admin/users.php');
    }

    // --- DELETE USER ---
    if ($action === 'delete') {
        requirePermission('users.delete');
        $userId = inputInt('user_id');
        $targetRow = $db->prepare("SELECT email, r.slug FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?");
        $targetRow->execute([$userId]);
        $target = $targetRow->fetch();
        if ($target && $target['slug'] === 'admin') {
            $adminCount = (int)$db->query("SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id=r.id WHERE r.slug='admin' AND u.is_active=1")->fetchColumn();
            if ($adminCount <= 1) { setFlash('error', 'Cannot delete the last active administrator.'); redirect('/admin/users.php'); }
        }
        if ($userId === (int)$user['id']) { setFlash('error', 'Cannot delete your own account.'); redirect('/admin/users.php'); }
        $db->prepare("DELETE FROM users WHERE id=?")->execute([$userId]);
        logSecurityEvent($user['id'], 'USER_DELETED', "Admin '{$user['email']}' deleted user '{$target['email']}'.", $ip, 'WARNING');
        setFlash('success', 'User deleted.');
        redirect('/admin/users.php');
    }
}

// -------------------------------------------------------
// GET: List Users with Search & Pagination
// -------------------------------------------------------
$search  = inputStr('q', $_GET);
$page    = max(1, (int)($_GET['page'] ?? 1));
$perPage = 12;

$whereClause = '1=1';
$params = [];
if ($search) {
    $whereClause .= " AND (u.name LIKE ? OR u.email LIKE ?)";
    $params[] = "%$search%";
    $params[] = "%$search%";
}

$countSql = "SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id=r.id WHERE $whereClause";
$dataSql  = "SELECT u.*, r.name AS role_name, r.slug AS role_slug
             FROM users u JOIN roles r ON u.role_id=r.id
             WHERE $whereClause ORDER BY u.created_at DESC";

$paged = paginate($db, $countSql, $dataSql, $params, $page, $perPage);
$users = $paged['data'];

// All roles for dropdowns
$roles = $db->query("SELECT id, name, slug FROM roles ORDER BY id")->fetchAll();

// Fetch user being edited (if ?edit=ID)
$editUser = null;
if (isset($_GET['edit'])) {
    $eid = (int)$_GET['edit'];
    $stmt = $db->prepare("SELECT * FROM users WHERE id=?");
    $stmt->execute([$eid]);
    $editUser = $stmt->fetch();
}
?>

<div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
    <div>
        <p class="text-muted mb-0" style="font-size:0.85rem;">
            <?= $paged['total'] ?> user<?= $paged['total'] !== 1 ? 's' : '' ?> found
        </p>
    </div>
    <div class="d-flex gap-2">
        <?php if (hasPermission('users.create')): ?>
        <button class="btn btn-cyber btn-sm" data-bs-toggle="modal" data-bs-target="#createUserModal">
            <i class="fa-solid fa-user-plus me-1"></i>Add User
        </button>
        <?php endif; ?>
    </div>
</div>

<!-- Search -->
<form method="GET" action="users.php" data-autosearch class="mb-3">
    <div class="input-group" style="max-width:380px;">
        <span class="input-group-text" style="background:rgba(7,12,27,0.8);border-color:var(--border-color);color:var(--text-muted);">
            <i class="fa-solid fa-magnifying-glass fa-sm"></i>
        </span>
        <input type="search" name="q" class="form-control" placeholder="Search users by name or email…" value="<?= e($search) ?>">
    </div>
</form>

<!-- User Table -->
<div class="card">
    <div class="table-responsive">
        <table class="table table-hover mb-0">
            <thead>
                <tr>
                    <th>#</th>
                    <th>User</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Last Login</th>
                    <th>Created</th>
                    <?php if (hasPermission('users.update') || hasPermission('users.delete')): ?>
                    <th>Actions</th>
                    <?php endif; ?>
                </tr>
            </thead>
            <tbody>
            <?php if (empty($users)): ?>
                <tr>
                    <td colspan="7" class="text-center text-muted py-5">
                        <i class="fa-solid fa-users fa-2x mb-2 d-block" style="opacity:0.3;"></i>
                        No users found<?= $search ? " for \"$search\"" : '' ?>.
                    </td>
                </tr>
            <?php else: foreach ($users as $u): ?>
                <tr>
                    <td class="text-muted mono"><?= $u['id'] ?></td>
                    <td>
                        <div class="d-flex align-items-center gap-2">
                            <div class="sidebar-avatar" style="width:32px;height:32px;font-size:0.7rem;flex-shrink:0;">
                                <?= strtoupper(substr($u['name'], 0, 2)) ?>
                            </div>
                            <div>
                                <div style="font-size:0.85rem;font-weight:500;"><?= e($u['name']) ?></div>
                                <div style="font-size:0.75rem;color:var(--text-muted);"><?= e($u['email']) ?></div>
                            </div>
                        </div>
                    </td>
                    <td>
                        <span class="role-badge <?= roleBadgeClass($u['role_slug']) ?>"><?= e($u['role_name']) ?></span>
                    </td>
                    <td>
                        <?php if ($u['is_active']): ?>
                            <span class="status-active"><i class="fa-solid fa-circle me-1" style="font-size:0.5rem;"></i>Active</span>
                        <?php else: ?>
                            <span class="status-inactive"><i class="fa-solid fa-circle me-1" style="font-size:0.5rem;"></i>Inactive</span>
                        <?php endif; ?>
                    </td>
                    <td style="font-size:0.8rem;color:var(--text-muted);"><?= $u['last_login_at'] ? formatDate($u['last_login_at']) : '—' ?></td>
                    <td style="font-size:0.8rem;color:var(--text-muted);"><?= formatDate($u['created_at']) ?></td>
                    <?php if (hasPermission('users.update') || hasPermission('users.delete')): ?>
                    <td>
                        <div class="d-flex gap-1">
                            <?php if (hasPermission('users.update')): ?>
                            <a href="users.php?edit=<?= $u['id'] ?>" class="btn btn-outline-secondary btn-sm" title="Edit user">
                                <i class="fa-solid fa-pen fa-sm"></i>
                            </a>
                            <form method="POST" action="users.php" class="d-inline">
                                <?= csrfField() ?>
                                <input type="hidden" name="action" value="toggle_active">
                                <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                <button type="submit" class="btn btn-outline-secondary btn-sm"
                                    title="<?= $u['is_active'] ? 'Deactivate' : 'Activate' ?>"
                                    data-confirm="<?= $u['is_active'] ? 'Deactivate this user?' : 'Activate this user?' ?>">
                                    <i class="fa-solid <?= $u['is_active'] ? 'fa-toggle-on text-success' : 'fa-toggle-off text-danger' ?> fa-sm"></i>
                                </button>
                            </form>
                            <?php endif; ?>
                            <?php if (hasPermission('users.delete') && $u['id'] != $user['id']): ?>
                            <form method="POST" action="users.php" class="d-inline">
                                <?= csrfField() ?>
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                <button type="submit" class="btn btn-outline-secondary btn-sm text-danger"
                                    data-confirm="Permanently delete '<?= e($u['name']) ?>'? This cannot be undone.">
                                    <i class="fa-solid fa-trash fa-sm"></i>
                                </button>
                            </form>
                            <?php endif; ?>
                        </div>
                    </td>
                    <?php endif; ?>
                </tr>
            <?php endforeach; endif; ?>
            </tbody>
        </table>
    </div>
    <?php if ($paged['totalPages'] > 1): ?>
    <div class="card-body pt-0 d-flex justify-content-between align-items-center flex-wrap gap-2">
        <small class="text-muted">
            Page <?= $paged['page'] ?> of <?= $paged['totalPages'] ?> (<?= $paged['total'] ?> total)
        </small>
        <?= renderPagination($paged, 'users.php?q=' . urlencode($search)) ?>
    </div>
    <?php endif; ?>
</div>

<!-- ===== CREATE USER MODAL ===== -->
<?php if (hasPermission('users.create')): ?>
<div class="modal fade" id="createUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content" style="background:var(--bg-secondary);border:1px solid var(--border-glow);">
            <div class="modal-header" style="border-color:var(--border-color);">
                <h5 class="modal-title text-white"><i class="fa-solid fa-user-plus me-2 text-cyan"></i>Create New User</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="users.php">
                <?= csrfField() ?>
                <input type="hidden" name="action" value="create">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Full Name</label>
                        <input type="text" name="name" class="form-control" placeholder="John Doe" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Email Address</label>
                        <input type="email" name="email" class="form-control" placeholder="user@example.com" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input type="password" id="password" name="password" class="form-control" placeholder="Min. 8 characters" required minlength="8">
                        <div class="password-strength-bar mt-1"><div class="password-strength-fill"></div></div>
                        <small class="text-muted" id="strengthLabel"></small>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Role</label>
                        <select name="role_id" class="form-select" required>
                            <option value="">— Select Role —</option>
                            <?php foreach ($roles as $role): ?>
                                <?php if ($role['slug'] === 'admin' && $user['role_slug'] !== 'admin') continue; ?>
                                <option value="<?= $role['id'] ?>"><?= e($role['name']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="is_active" id="isActiveCreate" checked>
                        <label class="form-check-label text-light" for="isActiveCreate">Account Active</label>
                    </div>
                </div>
                <div class="modal-footer" style="border-color:var(--border-color);">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-cyber"><i class="fa-solid fa-user-plus me-1"></i>Create User</button>
                </div>
            </form>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- ===== EDIT USER MODAL (auto-open if ?edit=ID) ===== -->
<?php if ($editUser && hasPermission('users.update')): ?>
<div class="modal fade" id="editUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content" style="background:var(--bg-secondary);border:1px solid var(--border-glow);">
            <div class="modal-header" style="border-color:var(--border-color);">
                <h5 class="modal-title text-white"><i class="fa-solid fa-user-pen me-2 text-cyan"></i>Edit User</h5>
                <a href="users.php" class="btn-close btn-close-white"></a>
            </div>
            <form method="POST" action="users.php">
                <?= csrfField() ?>
                <input type="hidden" name="action" value="update">
                <input type="hidden" name="user_id" value="<?= $editUser['id'] ?>">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Full Name</label>
                        <input type="text" name="name" class="form-control" value="<?= e($editUser['name']) ?>" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Email Address</label>
                        <input type="email" name="email" class="form-control" value="<?= e($editUser['email']) ?>" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">New Password <span class="text-muted">(leave blank to keep current)</span></label>
                        <input type="password" name="new_password" class="form-control" placeholder="Min. 8 characters" minlength="8">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Role</label>
                        <select name="role_id" class="form-select" required>
                            <?php foreach ($roles as $role): ?>
                                <?php if ($role['slug'] === 'admin' && $user['role_slug'] !== 'admin') continue; ?>
                                <option value="<?= $role['id'] ?>" <?= $role['id'] == $editUser['role_id'] ? 'selected' : '' ?>>
                                    <?= e($role['name']) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="is_active" id="isActiveEdit" <?= $editUser['is_active'] ? 'checked' : '' ?>>
                        <label class="form-check-label text-light" for="isActiveEdit">Account Active</label>
                    </div>
                </div>
                <div class="modal-footer" style="border-color:var(--border-color);">
                    <a href="users.php" class="btn btn-outline-secondary">Cancel</a>
                    <button type="submit" class="btn btn-cyber"><i class="fa-solid fa-floppy-disk me-1"></i>Save Changes</button>
                </div>
            </form>
        </div>
    </div>
</div>
<script>
document.addEventListener('DOMContentLoaded', () => {
    new bootstrap.Modal(document.getElementById('editUserModal')).show();
});
</script>
<?php endif; ?>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
