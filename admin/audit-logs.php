<?php
/**
 * Audit Logs — Admin Only
 * View security events with filtering and pagination.
 */
define('APP_INIT', true);
$pageTitle = 'Audit Logs';
$activeNav = 'audit';

require_once __DIR__ . '/../includes/header.php';

requirePermission('audit_logs.view');

$db = getDB();

// Filters
$filterType   = inputStr('type', $_GET);
$filterStatus = inputStr('status', $_GET);
$filterUser   = inputStr('user', $_GET);
$page         = max(1, (int)($_GET['page'] ?? 1));

$where  = ['1=1'];
$params = [];

if ($filterType) {
    $where[]  = 'al.event_type = ?';
    $params[] = $filterType;
}
if ($filterStatus) {
    $where[]  = 'al.status = ?';
    $params[] = strtoupper($filterStatus);
}
if ($filterUser) {
    $where[]  = '(u.name LIKE ? OR u.email LIKE ?)';
    $params[] = "%$filterUser%";
    $params[] = "%$filterUser%";
}

$whereStr = implode(' AND ', $where);

$countSql = "SELECT COUNT(*) FROM audit_logs al LEFT JOIN users u ON al.user_id = u.id WHERE $whereStr";
$dataSql  = "SELECT al.*, u.name AS user_name, u.email AS user_email
             FROM audit_logs al
             LEFT JOIN users u ON al.user_id = u.id
             WHERE $whereStr ORDER BY al.created_at DESC";

$paged = paginate($db, $countSql, $dataSql, $params, $page, 20);
$logs  = $paged['data'];

// Distinct event types for filter dropdown
$eventTypes = $db->query("SELECT DISTINCT event_type FROM audit_logs ORDER BY event_type")->fetchAll(PDO::FETCH_COLUMN);
?>

<!-- Filters -->
<form method="GET" action="audit-logs.php" class="card p-3 mb-3">
    <div class="row g-2 align-items-end">
        <div class="col-md-3">
            <label class="form-label">Event Type</label>
            <select name="type" class="form-select form-select-sm">
                <option value="">All Events</option>
                <?php foreach ($eventTypes as $et): ?>
                    <option value="<?= e($et) ?>" <?= $filterType === $et ? 'selected' : '' ?>><?= e(formatEventType($et)) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-md-2">
            <label class="form-label">Status</label>
            <select name="status" class="form-select form-select-sm">
                <option value="">All</option>
                <option value="SUCCESS" <?= $filterStatus === 'SUCCESS' ? 'selected' : '' ?>>Success</option>
                <option value="FAILED" <?= $filterStatus === 'FAILED' ? 'selected' : '' ?>>Failed</option>
                <option value="DENIED" <?= $filterStatus === 'DENIED' ? 'selected' : '' ?>>Denied</option>
                <option value="WARNING" <?= $filterStatus === 'WARNING' ? 'selected' : '' ?>>Warning</option>
            </select>
        </div>
        <div class="col-md-3">
            <label class="form-label">User</label>
            <input type="text" name="user" class="form-control form-control-sm" placeholder="Name or email…" value="<?= e($filterUser) ?>">
        </div>
        <div class="col-md-4 d-flex gap-2">
            <button type="submit" class="btn btn-outline-cyber btn-sm"><i class="fa-solid fa-filter me-1"></i>Filter</button>
            <a href="audit-logs.php" class="btn btn-outline-secondary btn-sm">Clear</a>
        </div>
    </div>
</form>

<div class="mb-2 d-flex justify-content-between align-items-center">
    <small class="text-muted"><?= $paged['total'] ?> events found</small>
</div>

<!-- Logs Table -->
<div class="card">
    <div class="table-responsive">
        <table class="table table-hover mb-0">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Event</th>
                    <th>User</th>
                    <th>Description</th>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
            <?php if (empty($logs)): ?>
                <tr>
                    <td colspan="7" class="text-center text-muted py-5">
                        <i class="fa-solid fa-scroll fa-2x mb-2 d-block" style="opacity:0.3;"></i>
                        No log entries found.
                    </td>
                </tr>
            <?php else: foreach ($logs as $log): ?>
                <tr>
                    <td class="mono text-muted"><?= $log['id'] ?></td>
                    <td>
                        <span class="fw-medium" style="font-size:0.82rem;">
                            <?= e(formatEventType($log['event_type'])) ?>
                        </span>
                    </td>
                    <td style="font-size:0.8rem;">
                        <?php if ($log['user_name']): ?>
                            <div><?= e($log['user_name']) ?></div>
                            <div class="text-muted" style="font-size:0.73rem;"><?= e($log['user_email']) ?></div>
                        <?php else: ?>
                            <span class="text-muted">—</span>
                        <?php endif; ?>
                    </td>
                    <td style="font-size:0.8rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="<?= e($log['description']) ?>">
                        <?= e($log['description']) ?>
                    </td>
                    <td class="mono text-muted" style="font-size:0.78rem;"><?= e($log['ip_address']) ?></td>
                    <td>
                        <span class="badge <?= auditStatusBadge($log['status']) ?>"><?= e($log['status']) ?></span>
                    </td>
                    <td style="font-size:0.78rem;color:var(--text-muted);white-space:nowrap;">
                        <?= formatDate($log['created_at']) ?>
                    </td>
                </tr>
            <?php endforeach; endif; ?>
            </tbody>
        </table>
    </div>

    <?php if ($paged['totalPages'] > 1): ?>
    <div class="card-body pt-2 pb-3 d-flex justify-content-between align-items-center flex-wrap gap-2">
        <small class="text-muted">Page <?= $paged['page'] ?> of <?= $paged['totalPages'] ?></small>
        <?php
        $qs = http_build_query(['type'=>$filterType,'status'=>$filterStatus,'user'=>$filterUser]);
        echo renderPagination($paged, 'audit-logs.php?' . $qs);
        ?>
    </div>
    <?php endif; ?>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
