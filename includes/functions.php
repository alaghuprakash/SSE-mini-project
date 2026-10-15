<?php
/**
 * General Helper Functions
 * Secure Role-Based Access Control (RBAC) Admin Panel
 */

if (!defined('APP_INIT')) {
    define('APP_INIT', true);
}

/**
 * Safely escape output for HTML context.
 */
function e(string $str): string {
    return htmlspecialchars($str, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/**
 * Return a Bootstrap badge class for a given role slug.
 */
function roleBadgeClass(string $roleSlug): string {
    return match ($roleSlug) {
        'admin'  => 'badge-admin',
        'editor' => 'badge-editor',
        'viewer' => 'badge-viewer',
        default  => 'badge-custom',
    };
}

/**
 * Return a readable label for event_type.
 */
function formatEventType(string $type): string {
    return match ($type) {
        'LOGIN_SUCCESS'        => 'Login Success',
        'LOGIN_FAILED'         => 'Login Failed',
        'LOGIN_DENIED'         => 'Login Denied',
        'LOGIN_BLOCKED'        => 'Rate Limited',
        'LOGOUT'               => 'Logout',
        'USER_CREATED'         => 'User Created',
        'USER_UPDATED'         => 'User Updated',
        'USER_DELETED'         => 'User Deleted',
        'ROLE_CHANGED'         => 'Role Changed',
        'RESOURCE_CREATED'     => 'Resource Created',
        'RESOURCE_UPDATED'     => 'Resource Updated',
        'RESOURCE_DELETED'     => 'Resource Deleted',
        'UNAUTHORIZED_ACCESS'  => 'Unauthorized Access',
        'CSRF_VALIDATION_FAILED' => 'CSRF Failed',
        'SYSTEM_INITIALIZATION'  => 'System Init',
        default => ucwords(strtolower(str_replace('_', ' ', $type))),
    };
}

/**
 * Return a Bootstrap badge class for an audit log status.
 */
function auditStatusBadge(string $status): string {
    return match (strtoupper($status)) {
        'SUCCESS' => 'bg-success',
        'DENIED'  => 'bg-danger',
        'FAILED'  => 'bg-warning text-dark',
        'WARNING' => 'bg-warning text-dark',
        default   => 'bg-secondary',
    };
}

/**
 * Paginate a query result.
 *
 * @param PDO    $db
 * @param string $countSql  Full SQL for COUNT
 * @param string $dataSql   Full SQL for data (should end without LIMIT/OFFSET)
 * @param array  $params
 * @param int    $page      Current page (1-based)
 * @param int    $perPage   Rows per page
 * @return array ['data'=>[], 'total'=>int, 'page'=>int, 'perPage'=>int, 'totalPages'=>int]
 */
function paginate(PDO $db, string $countSql, string $dataSql, array $params, int $page = 1, int $perPage = 15): array {
    $page    = max(1, $page);
    $perPage = max(5, min(100, $perPage));
    $offset  = ($page - 1) * $perPage;

    $cStmt = $db->prepare($countSql);
    $cStmt->execute($params);
    $total = (int)$cStmt->fetchColumn();

    $dStmt = $db->prepare($dataSql . " LIMIT $perPage OFFSET $offset");
    $dStmt->execute($params);
    $data = $dStmt->fetchAll();

    return [
        'data'       => $data,
        'total'      => $total,
        'page'       => $page,
        'perPage'    => $perPage,
        'totalPages' => max(1, (int)ceil($total / $perPage)),
    ];
}

/**
 * Render a Bootstrap pagination widget.
 */
function renderPagination(array $p, string $baseUrl): string {
    if ($p['totalPages'] <= 1) return '';
    $html = '<nav><ul class="pagination pagination-sm mb-0">';
    $prev = $p['page'] - 1;
    $next = $p['page'] + 1;
    $disabled = $p['page'] <= 1 ? 'disabled' : '';
    $html .= "<li class=\"page-item $disabled\"><a class=\"page-link\" href=\"{$baseUrl}&page=$prev\">«</a></li>";
    for ($i = 1; $i <= $p['totalPages']; $i++) {
        $active = $i === $p['page'] ? 'active' : '';
        $html .= "<li class=\"page-item $active\"><a class=\"page-link\" href=\"{$baseUrl}&page=$i\">$i</a></li>";
    }
    $disabled2 = $p['page'] >= $p['totalPages'] ? 'disabled' : '';
    $html .= "<li class=\"page-item $disabled2\"><a class=\"page-link\" href=\"{$baseUrl}&page=$next\">»</a></li>";
    $html .= '</ul></nav>';
    return $html;
}

/**
 * Flash message system — store a message for the next page load.
 */
function setFlash(string $type, string $message): void {
    if (session_status() === PHP_SESSION_NONE) session_start();
    $_SESSION['_flash'][$type][] = $message;
}

/**
 * Render and clear all flash messages.
 */
function renderFlash(): string {
    if (session_status() === PHP_SESSION_NONE) session_start();
    if (empty($_SESSION['_flash'])) return '';
    $map = ['success' => 'success', 'error' => 'danger', 'warning' => 'warning', 'info' => 'info'];
    $icons = ['success' => 'circle-check', 'error' => 'triangle-exclamation', 'warning' => 'exclamation', 'info' => 'info-circle'];
    $html = '';
    foreach ($_SESSION['_flash'] as $type => $messages) {
        $cls  = $map[$type] ?? 'info';
        $icon = $icons[$type] ?? 'info-circle';
        foreach ($messages as $msg) {
            $html .= "<div class=\"alert alert-{$cls} alert-dismissible fade show d-flex align-items-center\" role=\"alert\">
                <i class=\"fa-solid fa-{$icon} me-2\"></i>
                <div>" . e($msg) . "</div>
                <button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"alert\"></button>
            </div>";
        }
    }
    unset($_SESSION['_flash']);
    return $html;
}

/**
 * Redirect to a URL and exit.
 */
function redirect(string $url): void {
    header("Location: $url");
    exit;
}

/**
 * Validate and sanitize a positive integer from user input.
 */
function inputInt(string $key, array $source = []): ?int {
    $val = ($source ?: $_POST)[$key] ?? null;
    if ($val === null || $val === '') return null;
    $int = filter_var($val, FILTER_VALIDATE_INT);
    return ($int !== false && $int > 0) ? $int : null;
}

/**
 * Sanitize a text string from user input (trim + strip tags).
 */
function inputStr(string $key, array $source = []): string {
    $val = ($source ?: $_POST)[$key] ?? '';
    return trim(strip_tags((string)$val));
}

/**
 * Format a MySQL datetime string for display.
 */
function formatDate(string $date): string {
    if (empty($date) || $date === '0000-00-00 00:00:00') return '—';
    try {
        $dt = new DateTime($date);
        return $dt->format('d M Y, H:i');
    } catch (Throwable $e) {
        return $date;
    }
}

/**
 * Format bytes into a human-readable string.
 */
function formatBytes(int $bytes): string {
    if ($bytes < 1024) return "{$bytes} B";
    if ($bytes < 1048576) return round($bytes / 1024, 1) . ' KB';
    return round($bytes / 1048576, 1) . ' MB';
}
