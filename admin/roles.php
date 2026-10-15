<?php
/**
 * Dynamic Roles & Permissions Management Hub — Admin Only
 *
 * Provides:
 * 1. Interactive Permission Matrix with live toggle & batch module controls
 * 2. Custom Role creation (with templates & auto-slug)
 * 3. Role deletion (protected system roles & user-assignment safeguards)
 * 4. Interactive RBAC Policy Simulator & Enforcement Analyzer
 * 5. Full audit logging on every policy alteration
 */
define('APP_INIT', true);
$pageTitle = 'Roles & Permissions Hub';
$activeNav = 'roles';

require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../includes/csrf.php';

requirePermission('roles.manage');

$db = getDB();
$ip = getClientIP();

// -------------------------------------------------------
// POST Handlers (Update Matrix / Create / Edit / Delete)
// -------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify();
    $action = $_POST['action'] ?? '';

    // --- 1. UPDATE PERMISSIONS MATRIX ---
    if ($action === 'update_matrix') {
        $matrix = $_POST['matrix'] ?? []; // matrix[role_id] = [perm_id, ...]
        $allRoles = $db->query("SELECT id, name, slug FROM roles")->fetchAll();
        $allPerms = getAllPermissions();
        $allPermIds = array_column($allPerms, 'id');

        $updatedCount = 0;
        foreach ($allRoles as $r) {
            $rId = (int)$r['id'];
            $selected = isset($matrix[$rId]) && is_array($matrix[$rId])
                ? array_map('intval', $matrix[$rId])
                : [];

            // Filter to only existing permission IDs
            $validSelected = array_intersect($selected, $allPermIds);
            if (syncRolePermissions($rId, $validSelected)) {
                $updatedCount++;
            }
        }

        logSecurityEvent(
            $user['id'],
            'ROLE_CHANGED',
            "Admin '{$user['email']}' updated the permissions matrix for {$updatedCount} role(s).",
            $ip,
            'SUCCESS'
        );

        setFlash('success', 'RBAC policy matrix successfully updated and active immediately.');
        redirect('/admin/roles.php');
    }

    // --- 2. CREATE CUSTOM ROLE ---
    if ($action === 'create_role') {
        $name        = inputStr('name');
        $slug        = inputStr('slug');
        $description = inputStr('description');
        $preset      = inputStr('preset');
        $initialPerms = $_POST['permissions'] ?? [];
        if (!is_array($initialPerms)) {
            $initialPerms = [];
        }
        $initialPerms = array_map('intval', $initialPerms);

        // If a preset was picked and checkboxes left blank, import preset permissions
        if (empty($initialPerms) && !empty($preset)) {
            if ($preset === 'viewer' || $preset === 'editor') {
                $stmt = $db->prepare("SELECT permission_id FROM role_permissions rp JOIN roles r ON rp.role_id=r.id WHERE r.slug = ?");
                $stmt->execute([$preset]);
                $initialPerms = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
            } elseif ($preset === 'all') {
                $stmt = $db->query("SELECT id FROM permissions");
                $initialPerms = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
            }
        }

        $res = createRole($name, $slug, $description, $initialPerms);
        if ($res['success']) {
            logSecurityEvent(
                $user['id'],
                'ROLE_CHANGED',
                "Admin '{$user['email']}' created custom role '{$name}' (slug: {$res['slug']}) with " . count($initialPerms) . " permissions.",
                $ip,
                'SUCCESS'
            );
            setFlash('success', "Custom role '{$name}' successfully created.");
        } else {
            setFlash('error', $res['error']);
        }
        redirect('/admin/roles.php');
    }

    // --- 3. EDIT ROLE DETAILS ---
    if ($action === 'update_role') {
        $roleId      = inputInt('role_id');
        $name        = inputStr('name');
        $description = inputStr('description');

        if ($roleId) {
            $stmt = $db->prepare("SELECT slug, name FROM roles WHERE id = ?");
            $stmt->execute([$roleId]);
            $rInfo = $stmt->fetch();

            if ($rInfo) {
                // System roles cannot be renamed, but their descriptions can be updated
                if (in_array($rInfo['slug'], ['admin', 'editor', 'viewer'], true)) {
                    $db->prepare("UPDATE roles SET description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
                       ->execute([$description, $roleId]);
                } else {
                    $newName = !empty($name) ? $name : $rInfo['name'];
                    $db->prepare("UPDATE roles SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
                       ->execute([$newName, $description, $roleId]);
                }

                logSecurityEvent($user['id'], 'ROLE_CHANGED', "Admin updated details for role ID {$roleId} ({$rInfo['slug']}).", $ip);
                setFlash('success', "Role '{$rInfo['name']}' updated.");
            }
        }
        redirect('/admin/roles.php');
    }

    // --- 4. DELETE CUSTOM ROLE ---
    if ($action === 'delete_role') {
        $roleId = inputInt('role_id');
        if ($roleId) {
            $res = deleteRole($roleId);
            if ($res['success']) {
                logSecurityEvent(
                    $user['id'],
                    'ROLE_CHANGED',
                    "Admin deleted custom role '{$res['name']}' (ID {$roleId}).",
                    $ip,
                    'WARNING'
                );
                setFlash('success', "Role '{$res['name']}' successfully removed.");
            } else {
                setFlash('error', $res['error']);
            }
        }
        redirect('/admin/roles.php');
    }
}

// -------------------------------------------------------
// Data Retrieval
// -------------------------------------------------------
$roles = $db->query("
    SELECT r.*,
           (SELECT COUNT(*) FROM users u WHERE u.role_id = r.id) AS user_count,
           (SELECT COUNT(*) FROM role_permissions rp WHERE rp.role_id = r.id) AS perm_count
    FROM roles r
    ORDER BY r.id
")->fetchAll();

$permissions = getAllPermissions();
$totalPermissions = count($permissions);

// Group permissions by module
$grouped = [];
foreach ($permissions as $perm) {
    $grouped[$perm['module']][] = $perm;
}

// Map of role_id => array of permission IDs
$rolePermMap = [];
$rpRows = $db->query("SELECT role_id, permission_id FROM role_permissions")->fetchAll();
foreach ($rpRows as $rp) {
    $rolePermMap[(int)$rp['role_id']][(int)$rp['permission_id']] = true;
}

// System vs custom roles count
$customRolesCount = 0;
foreach ($roles as $r) {
    if (!in_array($r['slug'], ['admin', 'editor', 'viewer'], true)) {
        $customRolesCount++;
    }
}
?>

<!-- ================= PAGE HEADER ================= -->
<div class="d-flex align-items-center justify-content-between mb-4 flex-wrap gap-3">
    <div>
        <h1 class="h4 text-white mb-1">
            <i class="fa-solid fa-key me-2 text-cyan"></i>Roles & Permissions Hub
        </h1>
        <p class="text-muted mb-0" style="font-size:0.875rem;">
            Dynamic Role-Based Access Control matrix, permission assignment, and live policy simulator.
        </p>
    </div>
    <div class="d-flex align-items-center gap-2">
        <a href="#simulatorSection" class="btn btn-outline-cyber btn-sm">
            <i class="fa-solid fa-flask-vial me-1"></i>Policy Simulator
        </a>
        <button type="button" class="btn btn-cyber btn-sm" data-bs-toggle="modal" data-bs-target="#createRoleModal">
            <i class="fa-solid fa-plus me-1"></i>New Custom Role
        </button>
    </div>
</div>

<!-- ================= STATS SUMMARY ================= -->
<div class="row g-3 mb-4">
    <div class="col-6 col-md-3">
        <div class="card stat-card">
            <div class="card-body d-flex align-items-center gap-3 p-3">
                <div class="stat-icon cyan"><i class="fa-solid fa-user-shield"></i></div>
                <div>
                    <div class="stat-value"><?= count($roles) ?></div>
                    <div class="stat-label">Active Roles</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-3">
        <div class="card stat-card">
            <div class="card-body d-flex align-items-center gap-3 p-3">
                <div class="stat-icon purple"><i class="fa-solid fa-lock"></i></div>
                <div>
                    <div class="stat-value"><?= $totalPermissions ?></div>
                    <div class="stat-label">Granular Privileges</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-3">
        <div class="card stat-card">
            <div class="card-body d-flex align-items-center gap-3 p-3">
                <div class="stat-icon blue"><i class="fa-solid fa-cubes-stacked"></i></div>
                <div>
                    <div class="stat-value"><?= count($grouped) ?></div>
                    <div class="stat-label">Secure Modules</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-3">
        <div class="card stat-card">
            <div class="card-body d-flex align-items-center gap-3 p-3">
                <div class="stat-icon green"><i class="fa-solid fa-shield-halved"></i></div>
                <div>
                    <div class="stat-value"><?= $customRolesCount ?></div>
                    <div class="stat-label">Custom Roles</div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ================= PERMISSION MATRIX ================= -->
<div class="card mb-4">
    <div class="card-header d-flex align-items-center justify-content-between flex-wrap gap-2">
        <div class="d-flex align-items-center gap-2">
            <span class="card-title mb-0"><i class="fa-solid fa-table-cells me-2 text-cyan"></i>Access Control Matrix</span>
            <span class="badge bg-dark border text-muted" style="font-size:0.75rem;">Real-time Enforcement</span>
        </div>
        <div class="d-flex align-items-center gap-2">
            <input type="text" id="matrixSearch" class="form-control form-control-sm" placeholder="Filter permissions..." style="width:190px;">
        </div>
    </div>
    <div class="card-body p-0">
        <form method="POST" action="roles.php" id="matrixForm">
            <?= csrfField() ?>
            <input type="hidden" name="action" value="update_matrix">

            <div class="p-3 border-bottom d-flex align-items-center justify-content-between flex-wrap gap-2" style="background:rgba(255,255,255,0.01);">
                <div class="text-muted" style="font-size:0.83rem;">
                    <i class="fa-solid fa-circle-info text-cyan me-1"></i>
                    Check or uncheck boxes below to grant/revoke privileges. Changes apply globally upon saving.
                    <span class="text-warning-emphasis ms-1"><i class="fa-solid fa-lock fa-xs"></i> Locked admin keys protect against accidental lockout.</span>
                </div>
                <div class="d-flex gap-2">
                    <button type="reset" class="btn btn-outline-secondary btn-sm">
                        <i class="fa-solid fa-rotate-left me-1"></i>Reset
                    </button>
                    <button type="submit" class="btn btn-cyber btn-sm px-3">
                        <i class="fa-solid fa-floppy-disk me-1"></i>Save Matrix Changes
                    </button>
                </div>
            </div>

            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0" id="matrixTable">
                    <thead>
                        <tr>
                            <th style="min-width:260px;">Permission / Action</th>
                            <th style="min-width:110px;">Module</th>
                            <?php foreach ($roles as $role): ?>
                            <th class="text-center" style="min-width:140px;">
                                <div class="d-flex flex-column align-items-center gap-1">
                                    <span class="role-badge <?= roleBadgeClass($role['slug']) ?>"><?= e($role['name']) ?></span>
                                    <div class="btn-group btn-group-sm mt-1" style="transform:scale(0.85);">
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2 role-select-all" data-role="<?= $role['id'] ?>" title="Select All">All</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2 role-deselect-all" data-role="<?= $role['id'] ?>" title="Deselect All">None</button>
                                    </div>
                                </div>
                            </th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($grouped as $module => $perms): ?>
                        <tr class="module-header-row" data-module="<?= strtolower(e($module)) ?>" style="background:rgba(255,255,255,0.025);">
                            <td colspan="2" class="py-2 px-3">
                                <span class="fw-bold text-cyan" style="font-size:0.8rem;text-transform:uppercase;letter-spacing:0.07em;">
                                    <i class="fa-solid fa-shield-halved me-1 text-muted"></i><?= e($module) ?>
                                </span>
                                <span class="badge bg-secondary-subtle text-muted ms-2" style="font-size:0.7rem;"><?= count($perms) ?> rules</span>
                            </td>
                            <?php foreach ($roles as $role): ?>
                            <td class="text-center py-1">
                                <button type="button" class="btn btn-link btn-sm text-muted p-0 module-toggle-btn"
                                        style="font-size:0.7rem;text-decoration:none;"
                                        data-module="<?= e($module) ?>"
                                        data-role="<?= $role['id'] ?>"
                                        title="Toggle this whole module for <?= e($role['name']) ?>">
                                    Toggle All
                                </button>
                            </td>
                            <?php endforeach; ?>
                        </tr>

                        <?php foreach ($perms as $perm): ?>
                        <tr class="perm-row" data-perm="<?= strtolower(e($perm['name'] . ' ' . $perm['slug'] . ' ' . $module)) ?>">
                            <td>
                                <div class="fw-semibold text-white" style="font-size:0.875rem;"><?= e($perm['name']) ?></div>
                                <div class="mono text-cyan" style="font-size:0.75rem;opacity:0.85;"><?= e($perm['slug']) ?></div>
                                <?php if (!empty($perm['description'])): ?>
                                    <div class="text-muted" style="font-size:0.75rem;line-height:1.3;margin-top:2px;"><?= e($perm['description']) ?></div>
                                <?php endif; ?>
                            </td>
                            <td>
                                <span class="badge bg-dark border text-light" style="font-size:0.72rem;"><?= e($perm['module']) ?></span>
                            </td>

                            <?php foreach ($roles as $role): ?>
                            <?php
                                $rId = (int)$role['id'];
                                $pId = (int)$perm['id'];
                                $isGranted = !empty($rolePermMap[$rId][$pId]);
                                $isLockedAdmin = ($role['slug'] === 'admin' && in_array($perm['slug'], ['roles.manage', 'settings.manage'], true));
                            ?>
                            <td class="text-center">
                                <div class="d-inline-flex align-items-center justify-content-center">
                                    <?php if ($isLockedAdmin): ?>
                                        <!-- Hidden input ensures value is always submitted even though disabled -->
                                        <input type="hidden" name="matrix[<?= $rId ?>][]" value="<?= $pId ?>">
                                        <input class="form-check-input" type="checkbox" checked disabled
                                               title="Protected system integrity key (always granted to Super Admin)"
                                               style="opacity:0.9;cursor:not-allowed;background-color:var(--accent-cyan);border-color:var(--accent-cyan);">
                                        <i class="fa-solid fa-lock text-cyan ms-1" style="font-size:0.7rem;" title="Locked"></i>
                                    <?php else: ?>
                                        <input class="form-check-input perm-checkbox role-<?= $rId ?> module-<?= preg_replace('/[^a-zA-Z0-9]/', '-', $module) ?>-<?= $rId ?>"
                                               type="checkbox"
                                               name="matrix[<?= $rId ?>][]"
                                               value="<?= $pId ?>"
                                               <?= $isGranted ? 'checked' : '' ?>
                                               data-role-slug="<?= e($role['slug']) ?>"
                                               data-perm-slug="<?= e($perm['slug']) ?>"
                                               style="cursor:pointer;width:1.2rem;height:1.2rem;">
                                    <?php endif; ?>
                                </div>
                            </td>
                            <?php endforeach; ?>
                        </tr>
                        <?php endforeach; ?>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="p-3 border-top d-flex justify-content-between align-items-center flex-wrap gap-2">
                <span class="text-muted" style="font-size:0.8rem;">
                    Server enforces strict zero-trust checks on <code>hasPermission()</code>.
                </span>
                <button type="submit" class="btn btn-cyber btn-sm px-4">
                    <i class="fa-solid fa-floppy-disk me-1"></i>Save Matrix Changes
                </button>
            </div>
        </form>
    </div>
</div>

<!-- ================= ROLE CARDS & CATALOG ================= -->
<div class="d-flex align-items-center justify-content-between mb-3">
    <h2 class="h5 text-white mb-0">
        <i class="fa-solid fa-id-badge me-2 text-cyan"></i>Role Registry & Statistics
    </h2>
    <span class="text-muted" style="font-size:0.82rem;">Manage role definitions, view user assignments & scope</span>
</div>

<div class="row g-3 mb-4">
    <?php foreach ($roles as $role): ?>
    <?php
        $isSystemRole = in_array($role['slug'], ['admin', 'editor', 'viewer'], true);
        $percent = $totalPermissions > 0 ? round(($role['perm_count'] / $totalPermissions) * 100) : 0;
    ?>
    <div class="col-md-6 col-lg-4">
        <div class="card h-100">
            <div class="card-body d-flex flex-column">
                <div class="d-flex align-items-start justify-content-between mb-2">
                    <div>
                        <span class="role-badge <?= roleBadgeClass($role['slug']) ?> fs-6"><?= e($role['name']) ?></span>
                        <div class="mono text-muted mt-1" style="font-size:0.75rem;">slug: <?= e($role['slug']) ?></div>
                    </div>
                    <?php if ($isSystemRole): ?>
                        <span class="badge bg-dark border text-muted" style="font-size:0.7rem;">
                            <i class="fa-solid fa-shield me-1"></i>System
                        </span>
                    <?php else: ?>
                        <span class="badge bg-purple-subtle text-purple border" style="font-size:0.7rem;">
                            <i class="fa-solid fa-sparkles me-1"></i>Custom
                        </span>
                    <?php endif; ?>
                </div>

                <p class="text-muted mb-3 flex-grow-1" style="font-size:0.84rem;min-height:38px;">
                    <?= e($role['description'] ?: 'No custom description provided.') ?>
                </p>

                <div class="p-2 rounded mb-3" style="background:rgba(255,255,255,0.02);border:1px solid var(--border-color);">
                    <div class="d-flex justify-content-between mb-1" style="font-size:0.78rem;">
                        <span class="text-muted">Assigned Users:</span>
                        <span class="fw-bold text-white"><?= $role['user_count'] ?> account(s)</span>
                    </div>
                    <div class="d-flex justify-content-between mb-1" style="font-size:0.78rem;">
                        <span class="text-muted">Permission Scope:</span>
                        <span class="fw-bold text-cyan"><?= $role['perm_count'] ?> / <?= $totalPermissions ?> (<?= $percent ?>%)</span>
                    </div>
                    <div class="progress" style="height:5px;background:rgba(255,255,255,0.08);">
                        <div class="progress-bar" style="width:<?= $percent ?>%;background:var(--accent-cyan);"></div>
                    </div>
                </div>

                <div class="d-flex align-items-center justify-content-end gap-2 pt-2 border-top">
                    <button type="button" class="btn btn-outline-secondary btn-sm"
                            data-bs-toggle="modal"
                            data-bs-target="#editRoleModal"
                            data-role-id="<?= $role['id'] ?>"
                            data-role-name="<?= e($role['name']) ?>"
                            data-role-desc="<?= e($role['description']) ?>"
                            data-is-system="<?= $isSystemRole ? '1' : '0' ?>">
                        <i class="fa-solid fa-pen-to-square me-1"></i>Edit
                    </button>
                    <?php if (!$isSystemRole): ?>
                        <button type="button" class="btn btn-outline-danger btn-sm"
                                data-bs-toggle="modal"
                                data-bs-target="#deleteRoleModal"
                                data-role-id="<?= $role['id'] ?>"
                                data-role-name="<?= e($role['name']) ?>"
                                data-user-count="<?= $role['user_count'] ?>">
                            <i class="fa-solid fa-trash me-1"></i>Delete
                        </button>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    <?php endforeach; ?>
</div>

<!-- ================= LIVE RBAC POLICY SIMULATOR ================= -->
<div class="card" id="simulatorSection">
    <div class="card-header d-flex align-items-center justify-content-between flex-wrap gap-2">
        <span class="card-title mb-0">
            <i class="fa-solid fa-flask-vial me-2 text-cyan"></i>Interactive RBAC Policy Simulator & Evaluator
        </span>
        <span class="badge bg-dark border text-muted" style="font-size:0.72rem;">Zero-Trust Sandbox</span>
    </div>
    <div class="card-body">
        <p class="text-muted mb-4" style="font-size:0.85rem;">
            Test access control decisions without switching user accounts. Select a target role and permission rule to evaluate whether the server middleware would grant <code>HTTP 200</code> access or trigger <code>HTTP 403 Forbidden</code> with security audit logging.
        </p>

        <div class="row g-3 align-items-end mb-4">
            <div class="col-md-4">
                <label class="form-label" style="font-size:0.8rem;text-transform:uppercase;letter-spacing:0.05em;">1. Test Role Subject</label>
                <select id="simRoleSelect" class="form-select">
                    <?php foreach ($roles as $r): ?>
                        <option value="<?= e($r['slug']) ?>" data-name="<?= e($r['name']) ?>">
                            <?= e($r['name']) ?> (<?= e($r['slug']) ?>)
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-5">
                <label class="form-label" style="font-size:0.8rem;text-transform:uppercase;letter-spacing:0.05em;">2. Action / Privilege Check</label>
                <select id="simPermSelect" class="form-select">
                    <?php foreach ($grouped as $mod => $pList): ?>
                        <optgroup label="<?= e($mod) ?>">
                            <?php foreach ($pList as $p): ?>
                                <option value="<?= e($p['slug']) ?>" data-name="<?= e($p['name']) ?>" data-mod="<?= e($mod) ?>">
                                    <?= e($p['slug']) ?> — <?= e($p['name']) ?>
                                </option>
                            <?php endforeach; ?>
                        </optgroup>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-3">
                <button type="button" id="btnRunSim" class="btn btn-cyber w-100">
                    <i class="fa-solid fa-play me-1"></i>Simulate Policy Check
                </button>
            </div>
        </div>

        <!-- Simulation Result Box -->
        <div id="simResultBox" class="p-3 rounded d-none" style="border:1px solid var(--border-glow);background:rgba(8,13,30,0.85);">
            <div class="d-flex align-items-center gap-3">
                <div id="simIcon" style="font-size:2rem;"></div>
                <div class="flex-grow-1">
                    <div class="d-flex align-items-center gap-2 mb-1">
                        <span id="simVerdictBadge" class="badge fs-6 px-3 py-1"></span>
                        <span id="simHttpCode" class="badge bg-dark border text-muted"></span>
                    </div>
                    <div id="simExplanation" class="text-white fw-semibold" style="font-size:0.9rem;"></div>
                    <div id="simDetails" class="text-muted mt-1" style="font-size:0.8rem;"></div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ================= CREATE CUSTOM ROLE MODAL ================= -->
<div class="modal fade" id="createRoleModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content" style="background:var(--bg-secondary);border:1px solid var(--border-glow);">
            <div class="modal-header" style="border-color:var(--border-color);">
                <h5 class="modal-title text-white"><i class="fa-solid fa-plus-circle me-2 text-cyan"></i>Create Custom Role</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="roles.php">
                <?= csrfField() ?>
                <input type="hidden" name="action" value="create_role">

                <div class="modal-body">
                    <div class="row g-3 mb-3">
                        <div class="col-md-6">
                            <label class="form-label">Role Display Name <span class="text-danger">*</span></label>
                            <input type="text" name="name" id="newRoleName" class="form-control" placeholder="e.g. Compliance Auditor" required>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Role Slug (identifier) <span class="text-danger">*</span></label>
                            <input type="text" name="slug" id="newRoleSlug" class="form-control mono" placeholder="e.g. auditor" required>
                            <small class="text-muted" style="font-size:0.75rem;">Lowercase letters, numbers, and hyphens only.</small>
                        </div>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Description / Purpose</label>
                        <textarea name="description" class="form-control" rows="2" placeholder="Describe the responsibilities and scope of this role..."></textarea>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Start From Template Preset (Optional)</label>
                        <select name="preset" id="newRolePreset" class="form-select">
                            <option value="">— Custom Selection Below —</option>
                            <option value="viewer">Clone Viewer Permissions (Read-only)</option>
                            <option value="editor">Clone Editor Permissions (Create + Read + Update resources)</option>
                            <option value="all">Grant All Privileges (Full Access)</option>
                        </select>
                    </div>

                    <div class="border rounded p-3" style="background:rgba(0,0,0,0.2);border-color:var(--border-color)!important;">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <label class="form-label mb-0 fw-bold text-white">Assign Initial Permissions</label>
                            <div class="btn-group btn-group-sm">
                                <button type="button" id="modalSelectAll" class="btn btn-outline-secondary btn-sm py-0">Select All</button>
                                <button type="button" id="modalDeselectAll" class="btn btn-outline-secondary btn-sm py-0">Deselect All</button>
                            </div>
                        </div>

                        <div class="row g-2" style="max-height:240px;overflow-y:auto;">
                            <?php foreach ($permissions as $p): ?>
                            <div class="col-md-6">
                                <div class="form-check">
                                    <input class="form-check-input modal-perm-check" type="checkbox" name="permissions[]" value="<?= $p['id'] ?>" id="np_<?= $p['id'] ?>">
                                    <label class="form-check-label" for="np_<?= $p['id'] ?>" style="font-size:0.83rem;">
                                        <span class="text-white fw-semibold"><?= e($p['name']) ?></span>
                                        <span class="mono text-muted d-block" style="font-size:0.72rem;"><?= e($p['slug']) ?></span>
                                    </label>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>

                <div class="modal-footer" style="border-color:var(--border-color);">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-cyber"><i class="fa-solid fa-check me-1"></i>Create Role</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- ================= EDIT ROLE MODAL ================= -->
<div class="modal fade" id="editRoleModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content" style="background:var(--bg-secondary);border:1px solid var(--border-glow);">
            <div class="modal-header" style="border-color:var(--border-color);">
                <h5 class="modal-title text-white"><i class="fa-solid fa-pen-to-square me-2 text-cyan"></i>Edit Role</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="roles.php">
                <?= csrfField() ?>
                <input type="hidden" name="action" value="update_role">
                <input type="hidden" name="role_id" id="editRoleId">

                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Role Name</label>
                        <input type="text" name="name" id="editRoleName" class="form-control" required>
                        <small id="systemRoleNotice" class="text-muted d-none" style="font-size:0.75rem;">
                            System role names are read-only to preserve application identity.
                        </small>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Description</label>
                        <textarea name="description" id="editRoleDesc" class="form-control" rows="3"></textarea>
                    </div>
                </div>

                <div class="modal-footer" style="border-color:var(--border-color);">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-cyber">Save Changes</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- ================= DELETE ROLE MODAL ================= -->
<div class="modal fade" id="deleteRoleModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content" style="background:var(--bg-secondary);border:1px solid var(--accent-red);">
            <div class="modal-header" style="border-color:var(--border-color);">
                <h5 class="modal-title text-danger"><i class="fa-solid fa-triangle-exclamation me-2"></i>Delete Custom Role</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="roles.php">
                <?= csrfField() ?>
                <input type="hidden" name="action" value="delete_role">
                <input type="hidden" name="role_id" id="delRoleId">

                <div class="modal-body">
                    <p class="text-white mb-2">
                        Are you sure you want to permanently delete custom role <strong id="delRoleName" class="text-danger"></strong>?
                    </p>
                    <div id="delUserWarning" class="alert alert-danger py-2 d-none" style="font-size:0.84rem;">
                        <i class="fa-solid fa-triangle-exclamation me-1"></i>
                        <span id="delUserCountText"></span>
                    </div>
                    <p class="text-muted mb-0" style="font-size:0.8rem;">
                        All role-to-permission mappings associated with this role will be removed immediately.
                    </p>
                </div>

                <div class="modal-footer" style="border-color:var(--border-color);">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" id="btnConfirmDelete" class="btn btn-danger"><i class="fa-solid fa-trash me-1"></i>Delete Role</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- ================= JAVASCRIPT LOGIC ================= -->
<script>
document.addEventListener('DOMContentLoaded', function () {
    // 1. Matrix Filter / Search
    const searchInput = document.getElementById('matrixSearch');
    const permRows = document.querySelectorAll('.perm-row');
    const moduleRows = document.querySelectorAll('.module-header-row');

    if (searchInput) {
        searchInput.addEventListener('input', function () {
            const query = this.value.toLowerCase().trim();
            permRows.forEach(row => {
                const text = row.getAttribute('data-perm') || '';
                row.style.display = text.includes(query) ? '' : 'none';
            });
            // Show module row if any child is visible
            moduleRows.forEach(mRow => {
                const module = mRow.getAttribute('data-module');
                const hasVisible = Array.from(permRows).some(r =>
                    r.getAttribute('data-perm').includes(module) && r.style.display !== 'none'
                );
                mRow.style.display = hasVisible ? '' : 'none';
            });
        });
    }

    // 2. Select All / Deselect All per Role Column
    document.querySelectorAll('.role-select-all').forEach(btn => {
        btn.addEventListener('click', function () {
            const roleId = this.dataset.role;
            document.querySelectorAll('.perm-checkbox.role-' + roleId + ':not(:disabled)').forEach(cb => cb.checked = true);
        });
    });
    document.querySelectorAll('.role-deselect-all').forEach(btn => {
        btn.addEventListener('click', function () {
            const roleId = this.dataset.role;
            document.querySelectorAll('.perm-checkbox.role-' + roleId + ':not(:disabled)').forEach(cb => cb.checked = false);
        });
    });

    // 3. Module toggle per Role
    document.querySelectorAll('.module-toggle-btn').forEach(btn => {
        btn.addEventListener('click', function () {
            const roleId = this.dataset.role;
            const moduleSlug = this.dataset.module.replace(/[^a-zA-Z0-9]/g, '-');
            const checkboxes = document.querySelectorAll('.module-' + moduleSlug + '-' + roleId + ':not(:disabled)');
            if (checkboxes.length > 0) {
                const allChecked = Array.from(checkboxes).every(cb => cb.checked);
                checkboxes.forEach(cb => cb.checked = !allChecked);
            }
        });
    });

    // 4. Auto-generate slug from name in Create Role modal
    const nameInput = document.getElementById('newRoleName');
    const slugInput = document.getElementById('newRoleSlug');
    if (nameInput && slugInput) {
        nameInput.addEventListener('input', function () {
            slugInput.value = this.value.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
        });
    }

    // 5. Modal Select All / Deselect All
    document.getElementById('modalSelectAll')?.addEventListener('click', () => {
        document.querySelectorAll('.modal-perm-check').forEach(cb => cb.checked = true);
    });
    document.getElementById('modalDeselectAll')?.addEventListener('click', () => {
        document.querySelectorAll('.modal-perm-check').forEach(cb => cb.checked = false);
    });

    // 6. Edit Role Modal Populator
    const editModal = document.getElementById('editRoleModal');
    if (editModal) {
        editModal.addEventListener('show.bs.modal', function (event) {
            const btn = event.relatedTarget;
            document.getElementById('editRoleId').value = btn.dataset.roleId;
            const nameEl = document.getElementById('editRoleName');
            nameEl.value = btn.dataset.roleName;
            document.getElementById('editRoleDesc').value = btn.dataset.roleDesc;

            const isSys = btn.dataset.isSystem === '1';
            const notice = document.getElementById('systemRoleNotice');
            if (isSys) {
                nameEl.readOnly = true;
                notice.classList.remove('d-none');
            } else {
                nameEl.readOnly = false;
                notice.classList.add('d-none');
            }
        });
    }

    // 7. Delete Role Modal Populator
    const deleteModal = document.getElementById('deleteRoleModal');
    if (deleteModal) {
        deleteModal.addEventListener('show.bs.modal', function (event) {
            const btn = event.relatedTarget;
            const roleId = btn.dataset.roleId;
            const roleName = btn.dataset.roleName;
            const userCount = parseInt(btn.dataset.userCount || '0', 10);

            document.getElementById('delRoleId').value = roleId;
            document.getElementById('delRoleName').textContent = roleName;

            const warnBox = document.getElementById('delUserWarning');
            const warnText = document.getElementById('delUserCountText');
            const confirmBtn = document.getElementById('btnConfirmDelete');

            if (userCount > 0) {
                warnBox.classList.remove('d-none');
                warnText.textContent = `Warning: ${userCount} user(s) currently assigned. You must reassign them before deletion.`;
                confirmBtn.disabled = true;
            } else {
                warnBox.classList.add('d-none');
                confirmBtn.disabled = false;
            }
        });
    }

    // 8. Policy Simulator Logic
    const btnRunSim = document.getElementById('btnRunSim');
    if (btnRunSim) {
        btnRunSim.addEventListener('click', function () {
            const roleSelect = document.getElementById('simRoleSelect');
            const permSelect = document.getElementById('simPermSelect');
            const roleSlug = roleSelect.value;
            const roleName = roleSelect.options[roleSelect.selectedIndex].getAttribute('data-name');
            const permSlug = permSelect.value;
            const permName = permSelect.options[permSelect.selectedIndex].getAttribute('data-name');
            const permMod  = permSelect.options[permSelect.selectedIndex].getAttribute('data-mod');

            // Look up directly in current DOM matrix checkboxes
            const cb = document.querySelector(`.perm-checkbox[data-role-slug="${roleSlug}"][data-perm-slug="${permSlug}"]`);
            let isAllowed = false;

            // Admin always has locked keys
            if (roleSlug === 'admin' && (permSlug === 'roles.manage' || permSlug === 'settings.manage')) {
                isAllowed = true;
            } else if (cb) {
                isAllowed = cb.checked;
            }

            const resultBox = document.getElementById('simResultBox');
            const iconEl = document.getElementById('simIcon');
            const badgeEl = document.getElementById('simVerdictBadge');
            const httpEl = document.getElementById('simHttpCode');
            const explEl = document.getElementById('simExplanation');
            const detEl = document.getElementById('simDetails');

            resultBox.classList.remove('d-none');

            if (isAllowed) {
                resultBox.style.borderColor = 'rgba(52, 211, 153, 0.4)';
                resultBox.style.boxShadow = '0 0 15px rgba(52, 211, 153, 0.15)';
                iconEl.innerHTML = '<i class="fa-solid fa-circle-check text-success"></i>';
                badgeEl.className = 'badge bg-success fs-6 px-3 py-1';
                badgeEl.textContent = 'ACCESS GRANTED';
                httpEl.className = 'badge bg-success-subtle text-success border';
                httpEl.textContent = 'HTTP 200 OK';
                explEl.textContent = `Role "${roleName}" has the "${permSlug}" permission granted.`;
                detEl.innerHTML = `Action <span class="mono text-cyan">${permSlug}</span> in module <strong>${permMod}</strong> is permitted. Server middleware allows execution.`;
            } else {
                resultBox.style.borderColor = 'rgba(248, 113, 113, 0.4)';
                resultBox.style.boxShadow = '0 0 15px rgba(248, 113, 113, 0.15)';
                iconEl.innerHTML = '<i class="fa-solid fa-circle-xmark text-danger"></i>';
                badgeEl.className = 'badge bg-danger fs-6 px-3 py-1';
                badgeEl.textContent = 'ACCESS DENIED';
                httpEl.className = 'badge bg-danger-subtle text-danger border';
                httpEl.textContent = 'HTTP 403 Forbidden';
                explEl.textContent = `Role "${roleName}" is missing "${permSlug}" in the policy matrix.`;
                detEl.innerHTML = `Server middleware will intercept the request, halt processing, and dispatch a security event <span class="mono text-warning">UNAUTHORIZED_ACCESS</span> to the audit logs.`;
            }
        });
    }
});
</script>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
