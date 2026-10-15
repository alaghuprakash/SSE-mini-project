<?php
/**
 * RBAC Permission Engine
 * Secure Role-Based Access Control (RBAC) Admin Panel
 *
 * All permission checks are performed server-side. Frontend hiding is
 * supplementary only — never the enforcement layer.
 */

if (!defined('APP_INIT')) {
    define('APP_INIT', true);
}

// -------------------------------------------------------
// Permission Cache (per-request)
// -------------------------------------------------------
$_permissionsCache = [];

/**
 * Load all permissions for a given role slug from the database.
 * Results are cached per-request in $_permissionsCache.
 */
function loadRolePermissions(string $roleSlug): array {
    global $_permissionsCache;
    if (isset($_permissionsCache[$roleSlug])) {
        return $_permissionsCache[$roleSlug];
    }
    try {
        require_once __DIR__ . '/../config/database.php';
        $db = getDB();
        $stmt = $db->prepare(
            "SELECT p.slug
             FROM permissions p
             JOIN role_permissions rp ON p.id = rp.permission_id
             JOIN roles r ON rp.role_id = r.id
             WHERE r.slug = ?"
        );
        $stmt->execute([$roleSlug]);
        $perms = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $_permissionsCache[$roleSlug] = $perms;
        return $perms;
    } catch (Throwable $e) {
        $_permissionsCache[$roleSlug] = [];
        return [];
    }
}

/**
 * Check if the currently logged-in user has a specific permission.
 *
 * @param string $permission  e.g. 'resources.create', 'users.delete'
 * @return bool
 */
function hasPermission(string $permission): bool {
    if (!isset($_SESSION['user_id'])) {
        return false;
    }
    $roleSlug = $_SESSION['user_role'] ?? '';
    if (empty($roleSlug)) {
        return false;
    }
    $perms = loadRolePermissions($roleSlug);
    return in_array($permission, $perms, true);
}

/**
 * Require a specific permission or abort with HTTP 403.
 *
 * @param string $permission  Permission slug to check
 */
function requirePermission(string $permission): void {
    require_once __DIR__ . '/auth.php';
    requireLogin();

    if (!hasPermission($permission)) {
        $user = getCurrentUser();
        $ip   = getClientIP();
        logSecurityEvent(
            $user['id'] ?? null,
            'UNAUTHORIZED_ACCESS',
            "Permission denied: '$permission' for role '{$_SESSION['user_role']}' on " . ($_SERVER['REQUEST_URI'] ?? ''),
            $ip,
            'DENIED'
        );
        http_response_code(403);
        include __DIR__ . '/../access-denied.php';
        exit;
    }
}

/**
 * Return all permissions for a role as an associative array keyed by slug.
 * Useful for building the permission matrix display.
 */
function getAllPermissions(): array {
    try {
        require_once __DIR__ . '/../config/database.php';
        $db = getDB();
        $stmt = $db->query("SELECT id, name, slug, module, description FROM permissions ORDER BY module, name");
        return $stmt->fetchAll();
    } catch (Throwable $e) {
        return [];
    }
}

/**
 * Check if a role has a specific permission (by role slug, not current user).
 */
function roleHasPermission(string $roleSlug, string $permissionSlug): bool {
    $perms = loadRolePermissions($roleSlug);
    return in_array($permissionSlug, $perms, true);
}

/**
 * Invalidate in-memory permissions cache.
 */
function clearPermissionsCache(?string $roleSlug = null): void {
    global $_permissionsCache;
    if ($roleSlug !== null) {
        unset($_permissionsCache[$roleSlug]);
    } else {
        $_permissionsCache = [];
    }
}

/**
 * Get assigned permission IDs for a given role ID.
 */
function getRolePermissionIds(int $roleId): array {
    try {
        require_once __DIR__ . '/../config/database.php';
        $db = getDB();
        $stmt = $db->prepare("SELECT permission_id FROM role_permissions WHERE role_id = ?");
        $stmt->execute([$roleId]);
        return array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    } catch (Throwable $e) {
        return [];
    }
}

/**
 * Synchronize/update permissions for a given role ID.
 *
 * @param int   $roleId
 * @param int[] $permissionIds
 * @return bool
 */
function syncRolePermissions(int $roleId, array $permissionIds): bool {
    try {
        require_once __DIR__ . '/../config/database.php';
        $db = getDB();

        // Check if role is admin and protect crucial permissions
        $stmt = $db->prepare("SELECT slug FROM roles WHERE id = ?");
        $stmt->execute([$roleId]);
        $slug = $stmt->fetchColumn();

        if ($slug === 'admin') {
            // Admin must always retain roles.manage and settings.manage
            $protectStmt = $db->query("SELECT id FROM permissions WHERE slug IN ('roles.manage', 'settings.manage')");
            $essentialIds = $protectStmt->fetchAll(PDO::FETCH_COLUMN);
            foreach ($essentialIds as $eid) {
                if (!in_array((int)$eid, $permissionIds, true)) {
                    $permissionIds[] = (int)$eid;
                }
            }
        }

        $db->beginTransaction();

        // Clear existing
        $del = $db->prepare("DELETE FROM role_permissions WHERE role_id = ?");
        $del->execute([$roleId]);

        // Insert new
        if (!empty($permissionIds)) {
            $ins = $db->prepare("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)");
            foreach (array_unique($permissionIds) as $pid) {
                $ins->execute([$roleId, (int)$pid]);
            }
        }

        $db->commit();
        clearPermissionsCache();
        return true;
    } catch (Throwable $e) {
        if (isset($db) && $db->inTransaction()) {
            $db->rollBack();
        }
        return false;
    }
}

/**
 * Create a new custom role.
 */
function createRole(string $name, string $slug, string $description, array $permissionIds = []): array {
    try {
        require_once __DIR__ . '/../config/database.php';
        $db = getDB();

        $name = trim($name);
        $slug = strtolower(trim(preg_replace('/[^a-zA-Z0-9_-]/', '-', $slug), '-'));

        if (empty($name) || strlen($name) < 2) {
            return ['success' => false, 'error' => 'Role name must be at least 2 characters.'];
        }
        if (empty($slug) || strlen($slug) < 2) {
            return ['success' => false, 'error' => 'Role slug is invalid.'];
        }

        // Check duplicate
        $chk = $db->prepare("SELECT id FROM roles WHERE slug = ? OR name = ?");
        $chk->execute([$slug, $name]);
        if ($chk->fetchColumn()) {
            return ['success' => false, 'error' => 'A role with this name or slug already exists.'];
        }

        $stmt = $db->prepare("INSERT INTO roles (name, slug, description, created_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)");
        $stmt->execute([$name, $slug, $description]);
        $newRoleId = (int)$db->lastInsertId();

        if (!empty($permissionIds)) {
            syncRolePermissions($newRoleId, $permissionIds);
        }

        return ['success' => true, 'role_id' => $newRoleId, 'slug' => $slug];
    } catch (Throwable $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Safely delete a custom role (prevents deleting default roles or roles with assigned users).
 */
function deleteRole(int $roleId): array {
    try {
        require_once __DIR__ . '/../config/database.php';
        $db = getDB();

        $stmt = $db->prepare("SELECT slug, name FROM roles WHERE id = ?");
        $stmt->execute([$roleId]);
        $role = $stmt->fetch();

        if (!$role) {
            return ['success' => false, 'error' => 'Role not found.'];
        }

        // Protected built-in roles
        if (in_array($role['slug'], ['admin', 'editor', 'viewer'], true)) {
            return ['success' => false, 'error' => "System role '{$role['name']}' is protected and cannot be deleted."];
        }

        // Check if any users are currently assigned to this role
        $uCheck = $db->prepare("SELECT COUNT(*) FROM users WHERE role_id = ?");
        $uCheck->execute([$roleId]);
        $assignedCount = (int)$uCheck->fetchColumn();

        if ($assignedCount > 0) {
            return ['success' => false, 'error' => "Cannot delete role '{$role['name']}': {$assignedCount} user(s) currently assigned. Please reassign them first."];
        }

        $db->prepare("DELETE FROM roles WHERE id = ?")->execute([$roleId]);
        clearPermissionsCache();

        return ['success' => true, 'name' => $role['name']];
    } catch (Throwable $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}
