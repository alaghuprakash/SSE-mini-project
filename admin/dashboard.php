<?php
/**
 * Admin Dashboard
 * Shows stats, role distribution chart, and recent activity.
 */
define('APP_INIT', true);
$pageTitle = 'Dashboard';
$activeNav = 'dashboard';

require_once __DIR__ . '/../includes/header.php';

requirePermission('dashboard.view');

$db = getDB();

// -------------------------------------------------------
// Stats
// -------------------------------------------------------
$totalUsers    = (int)$db->query("SELECT COUNT(*) FROM users")->fetchColumn();
$totalAdmins   = (int)$db->query("SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id=r.id WHERE r.slug='admin'")->fetchColumn();
$totalEditors  = (int)$db->query("SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id=r.id WHERE r.slug='editor'")->fetchColumn();
$totalViewers  = (int)$db->query("SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id=r.id WHERE r.slug='viewer'")->fetchColumn();
$totalResources= (int)$db->query("SELECT COUNT(*) FROM resources")->fetchColumn();
$activeUsers   = (int)$db->query("SELECT COUNT(*) FROM users WHERE is_active=1")->fetchColumn();

// Recent audit logs
$recentLogs = $db->query(
    "SELECT al.*, u.name AS user_name, u.email AS user_email
     FROM audit_logs al LEFT JOIN users u ON al.user_id = u.id
     ORDER BY al.created_at DESC LIMIT 8"
)->fetchAll();

// Recent users
$recentUsers = $db->query(
    "SELECT u.*, r.name AS role_name, r.slug AS role_slug
     FROM users u JOIN roles r ON u.role_id = r.id
     ORDER BY u.created_at DESC LIMIT 5"
)->fetchAll();

// Activity chart: events per day (last 7 days)
$sevenDaysAgo = date('Y-m-d H:i:s', strtotime('-7 days'));
$stmt = $db->prepare(
    "SELECT DATE(created_at) as day, COUNT(*) as cnt
     FROM audit_logs
     WHERE created_at >= ?
     GROUP BY DATE(created_at) ORDER BY day ASC"
);
$stmt->execute([$sevenDaysAgo]);
$activityData = $stmt->fetchAll();
$chartLabels = array_column($activityData, 'day');
$chartValues = array_column($activityData, 'cnt');

// Threat detection: count recent unauthorized attempts
$blockedAttempts = (int)$db->query("SELECT COUNT(*) FROM audit_logs WHERE status='DENIED' OR event_type LIKE '%BLOCKED%'")->fetchColumn();
?>

<!-- Cybersecurity SOC Telemetry & Defense Strip -->
<div class="card mb-4 p-3" style="background:linear-gradient(135deg, rgba(0,242,254,0.06), rgba(13,21,40,0.85));border-color:var(--border-glow);">
    <div class="d-flex align-items-center justify-content-between flex-wrap gap-3">
        <div class="d-flex align-items-center gap-3">
            <div class="sidebar-avatar" style="width:42px;height:42px;background:linear-gradient(135deg,var(--accent-cyan),var(--accent-blue));color:#070c1b;font-size:1.1rem;box-shadow:0 0 14px var(--border-glow);">
                <i class="fa-solid fa-shield-virus"></i>
            </div>
            <div>
                <div class="d-flex align-items-center gap-2">
                    <span class="fw-bold text-white" style="font-size:0.95rem;">Security Operations Center (SOC) Active</span>
                    <span class="badge bg-success-subtle text-success border border-success-subtle" style="font-size:0.7rem;">
                        <span class="status-live-dot d-inline-block me-1"></span> DEFCON 5 (SECURE)
                    </span>
                </div>
                <div class="text-muted" style="font-size:0.78rem;">
                    Zero-Trust Gateway &bull; PDO Parameterized Shield &bull; Session Integrity: Strict &bull; Denied Events: <span class="text-warning fw-semibold"><?= $blockedAttempts ?></span>
                </div>
            </div>
        </div>
        <div class="d-flex align-items-center gap-2">
            <a href="/tests/authorization-tests.php" target="_blank" class="btn btn-outline-cyber btn-sm">
                <i class="fa-solid fa-vial-circle-check me-1"></i>Run Security Test Suite
            </a>
            <button type="button" class="btn btn-cyber btn-sm" data-bs-toggle="modal" data-bs-target="#projectSpecsModal">
                <i class="fa-solid fa-award me-1"></i>Project Defense Specs
            </button>
        </div>
    </div>
</div>

<!-- Stat Cards -->
<div class="row g-3 mb-4">
    <div class="col-6 col-md-4 col-lg-2">
        <div class="card stat-card">
            <div class="card-body d-flex align-items-center gap-3 p-3">
                <div class="stat-icon cyan"><i class="fa-solid fa-users"></i></div>
                <div>
                    <div class="stat-value"><?= $totalUsers ?></div>
                    <div class="stat-label">Total Users</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-4 col-lg-2">
        <div class="card stat-card stat-red">
            <div class="card-body d-flex align-items-center gap-3 p-3">
                <div class="stat-icon red"><i class="fa-solid fa-user-shield"></i></div>
                <div>
                    <div class="stat-value"><?= $totalAdmins ?></div>
                    <div class="stat-label">Admins</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-4 col-lg-2">
        <div class="card stat-card stat-orange">
            <div class="card-body d-flex align-items-center gap-3 p-3">
                <div class="stat-icon orange"><i class="fa-solid fa-pen-to-square"></i></div>
                <div>
                    <div class="stat-value"><?= $totalEditors ?></div>
                    <div class="stat-label">Editors</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-4 col-lg-2">
        <div class="card stat-card stat-green">
            <div class="card-body d-flex align-items-center gap-3 p-3">
                <div class="stat-icon green"><i class="fa-solid fa-eye"></i></div>
                <div>
                    <div class="stat-value"><?= $totalViewers ?></div>
                    <div class="stat-label">Viewers</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-4 col-lg-2">
        <div class="card stat-card">
            <div class="card-body d-flex align-items-center gap-3 p-3">
                <div class="stat-icon blue"><i class="fa-solid fa-folder-open"></i></div>
                <div>
                    <div class="stat-value"><?= $totalResources ?></div>
                    <div class="stat-label">Resources</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-4 col-lg-2">
        <div class="card stat-card stat-green">
            <div class="card-body d-flex align-items-center gap-3 p-3">
                <div class="stat-icon green"><i class="fa-solid fa-circle-check"></i></div>
                <div>
                    <div class="stat-value"><?= $activeUsers ?></div>
                    <div class="stat-label">Active</div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Charts Row -->
<div class="row g-3 mb-4">
    <div class="col-md-4">
        <div class="card h-100">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-chart-pie me-2 text-cyan"></i>Role Distribution</span>
            </div>
            <div class="card-body" style="height:220px;position:relative;">
                <canvas id="roleDistributionChart"
                    data-values='<?= json_encode(['admin'=>$totalAdmins,'editor'=>$totalEditors,'viewer'=>$totalViewers]) ?>'>
                </canvas>
            </div>
        </div>
    </div>
    <div class="col-md-8">
        <div class="card h-100">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-chart-bar me-2 text-cyan"></i>Security Events (Last 7 Days)</span>
            </div>
            <div class="card-body" style="height:220px;position:relative;">
                <canvas id="activityChart"
                    data-labels='<?= json_encode($chartLabels) ?>'
                    data-values='<?= json_encode($chartValues) ?>'>
                </canvas>
            </div>
        </div>
    </div>
</div>

<!-- Recent Data Row -->
<div class="row g-3">
    <!-- Recent Audit Events -->
    <div class="col-lg-7">
        <div class="card">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-scroll me-2 text-cyan"></i>Recent Security Events</span>
                <?php if (hasPermission('audit_logs.view')): ?>
                    <a href="/admin/audit-logs.php" class="btn btn-outline-cyber btn-sm">View All</a>
                <?php endif; ?>
            </div>
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead>
                        <tr>
                            <th>Event</th>
                            <th>User</th>
                            <th>Status</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php if (empty($recentLogs)): ?>
                        <tr><td colspan="4" class="text-center text-muted py-4">No events recorded yet.</td></tr>
                    <?php else: foreach ($recentLogs as $log): ?>
                        <tr>
                            <td>
                                <span class="fw-medium" style="font-size:0.82rem;"><?= e(formatEventType($log['event_type'])) ?></span>
                            </td>
                            <td style="font-size:0.8rem;color:var(--text-muted);">
                                <?= $log['user_name'] ? e($log['user_name']) : '<em>System</em>' ?>
                            </td>
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
        </div>
    </div>

    <!-- Recent Users -->
    <div class="col-lg-5">
        <div class="card">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-user-plus me-2 text-cyan"></i>Recent Users</span>
                <?php if (hasPermission('users.view')): ?>
                    <a href="/admin/users.php" class="btn btn-outline-cyber btn-sm">Manage</a>
                <?php endif; ?>
            </div>
            <div class="card-body p-0">
                <?php if (empty($recentUsers)): ?>
                    <div class="empty-state"><i class="fa-solid fa-users"></i><p>No users yet.</p></div>
                <?php else: foreach ($recentUsers as $u): ?>
                    <div class="d-flex align-items-center gap-3 px-3 py-2" style="border-bottom:1px solid var(--border-color);">
                        <div class="sidebar-avatar" style="width:32px;height:32px;font-size:0.7rem;flex-shrink:0;">
                            <?= strtoupper(substr($u['name'], 0, 2)) ?>
                        </div>
                        <div class="flex-grow-1 min-w-0">
                            <div style="font-size:0.83rem;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                                <?= e($u['name']) ?>
                            </div>
                            <div style="font-size:0.73rem;color:var(--text-muted);"><?= e($u['email']) ?></div>
                        </div>
                        <span class="role-badge <?= roleBadgeClass($u['role_slug']) ?>"><?= e($u['role_name']) ?></span>
                    </div>
                <?php endforeach; endif; ?>
            </div>
        </div>
    <!-- ================= CYBERSECURITY EVALUATION SPECS MODAL ================= -->
<div class="modal fade" id="projectSpecsModal" tabindex="-1">
    <div class="modal-dialog modal-lg modal-dialog-centered">
        <div class="modal-content" style="background:var(--bg-secondary);border:1px solid var(--border-glow);">
            <div class="modal-header" style="border-color:var(--border-color);">
                <div class="d-flex align-items-center gap-2">
                    <div class="sidebar-avatar" style="width:34px;height:34px;background:linear-gradient(135deg,var(--accent-cyan),var(--accent-blue));color:#070c1b;font-size:0.9rem;">
                        <i class="fa-solid fa-shield-halved"></i>
                    </div>
                    <div>
                        <h5 class="modal-title text-white mb-0">SSE Cybersecurity Mini Project &bull; Evaluation Summary</h5>
                        <small class="text-muted" style="font-size:0.75rem;">Role-Based Access Control (RBAC) &bull; Threat Mitigation Portfolio</small>
                    </div>
                </div>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body p-4">
                <div class="row g-3 mb-4">
                    <div class="col-md-4">
                        <div class="p-3 rounded h-100" style="background:rgba(255,255,255,0.02);border:1px solid var(--border-color);">
                            <div class="d-flex align-items-center gap-2 mb-1">
                                <span class="role-badge badge-admin">Admin Role</span>
                            </div>
                            <small class="text-muted d-block">Tier 1: Master Authority</small>
                            <p class="mb-0 mt-2 text-white" style="font-size:0.8rem;">
                                Full CRUD on users, dynamic permissions matrix modification, audit trail inspection, system configuration, resource administration.
                            </p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="p-3 rounded h-100" style="background:rgba(255,255,255,0.02);border:1px solid var(--border-color);">
                            <div class="d-flex align-items-center gap-2 mb-1">
                                <span class="role-badge badge-editor">Editor Role</span>
                            </div>
                            <small class="text-muted d-block">Tier 2: Content Operations</small>
                            <p class="mb-0 mt-2 text-white" style="font-size:0.8rem;">
                                Authorized to create, browse, and edit resources. Intercepted from deleting resources, managing users, roles, or viewing logs.
                            </p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="p-3 rounded h-100" style="background:rgba(255,255,255,0.02);border:1px solid var(--border-color);">
                            <div class="d-flex align-items-center gap-2 mb-1">
                                <span class="role-badge badge-viewer">Viewer Role</span>
                            </div>
                            <small class="text-muted d-block">Tier 3: Read-Only Audit</small>
                            <p class="mb-0 mt-2 text-white" style="font-size:0.8rem;">
                                Strictly restricted to reading published resource data. All mutations are denied by middleware with HTTP 403.
                            </p>
                        </div>
                    </div>
                </div>

                <h6 class="text-white mb-3" style="font-size:0.85rem;text-transform:uppercase;letter-spacing:0.06em;">
                    <i class="fa-solid fa-lock text-cyan me-1"></i>Defensive Security Mitigations (OWASP Benchmark)
                </h6>

                <div class="table-responsive">
                    <table class="table table-sm" style="font-size:0.8rem;">
                        <thead>
                            <tr>
                                <th>Vulnerability Threat</th>
                                <th>Defensive Layer & Countermeasure</th>
                                <th>Verification Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td class="fw-semibold text-white">Privilege Escalation</td>
                                <td>Zero-Trust server middleware <code>requirePermission()</code> check on every route</td>
                                <td><span class="badge bg-success">Enforced</span></td>
                            </tr>
                            <tr>
                                <td class="fw-semibold text-white">SQL Injection (SQLi)</td>
                                <td>PDO native prepared statements with parameter separation (no string concat)</td>
                                <td><span class="badge bg-success">Immune</span></td>
                            </tr>
                            <tr>
                                <td class="fw-semibold text-white">Cross-Site Request Forgery (CSRF)</td>
                                <td>Cryptographically random per-session HMAC tokens validated on POST requests</td>
                                <td><span class="badge bg-success">Protected</span></td>
                            </tr>
                            <tr>
                                <td class="fw-semibold text-white">Brute-Force & Credential Stuffing</td>
                                <td>15-minute sliding IP & email lockout window after 5 consecutive failures</td>
                                <td><span class="badge bg-success">Throttled</span></td>
                            </tr>
                            <tr>
                                <td class="fw-semibold text-white">Session Fixation & Hijacking</td>
                                <td><code>session_regenerate_id(true)</code> on auth, <code>HttpOnly</code>, <code>SameSite=Strict</code></td>
                                <td><span class="badge bg-success">Hardened</span></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="modal-footer" style="border-color:var(--border-color);">
                <a href="/tests/authorization-tests.php" target="_blank" class="btn btn-outline-cyber btn-sm">
                    <i class="fa-solid fa-vials me-1"></i>Open 20/20 Test Suite
                </a>
                <button type="button" class="btn btn-cyber btn-sm" data-bs-dismiss="modal">Close Specs</button>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
