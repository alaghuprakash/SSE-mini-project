<?php
/**
 * Authorization Test Suite
 * Secure RBAC Admin Panel — Security Test Cases
 *
 * Run via CLI:  php tests/authorization-tests.php
 * Or browser:  http://127.0.0.1:8000/tests/authorization-tests.php
 *
 * NOTE: Requires the database to be initialized via setup.php first.
 */

define('APP_INIT', true);
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/permissions.php';
require_once __DIR__ . '/../includes/functions.php';

$isCli = (php_sapi_name() === 'cli');

// -------------------------------------------------------
// Test Framework
// -------------------------------------------------------
$results = [];
$passed  = 0;
$failed  = 0;

function testCase(string $id, string $description, bool $condition, string $expected): void {
    global $results, $passed, $failed;
    $status = $condition ? 'PASS' : 'FAIL';
    $results[] = compact('id', 'description', 'status', 'expected');
    $condition ? $passed++ : $failed++;
}

function getUserForRole(PDO $db, string $slug): ?array {
    $stmt = $db->prepare(
        "SELECT u.* FROM users u JOIN roles r ON u.role_id = r.id WHERE r.slug = ? AND u.is_active = 1 LIMIT 1"
    );
    $stmt->execute([$slug]);
    return $stmt->fetch() ?: null;
}

function simulatePermission(array $userRow, string $permission): bool {
    // Inject user into session temporarily for loadRolePermissions
    $original = $_SESSION['user_role'] ?? null;
    $stmt = (getDB())->prepare("SELECT r.slug FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?");
    $stmt->execute([$userRow['id']]);
    $slug = $stmt->fetchColumn();
    $_SESSION['user_role'] = $slug;
    $_SESSION['user_id']   = $userRow['id'];
    $result = hasPermission($permission);
    // Restore
    if ($original !== null) $_SESSION['user_role'] = $original;
    return $result;
}

// -------------------------------------------------------
// Run Tests
// -------------------------------------------------------
try {
    $db    = getDB();
    startSecureSession();

    $admin  = getUserForRole($db, 'admin');
    $editor = getUserForRole($db, 'editor');
    $viewer = getUserForRole($db, 'viewer');

    // ---- PERMISSION TESTS ----
    testCase('T01', 'Admin can create resources',
        $admin && simulatePermission($admin, 'resources.create'),
        'PASS — resources.create granted to admin'
    );

    testCase('T02', 'Editor can create resources',
        $editor && simulatePermission($editor, 'resources.create'),
        'PASS — resources.create granted to editor'
    );

    testCase('T03', 'Viewer CANNOT create resources',
        $viewer && !simulatePermission($viewer, 'resources.create'),
        'PASS — resources.create NOT granted to viewer'
    );

    testCase('T04', 'Viewer CANNOT edit resources',
        $viewer && !simulatePermission($viewer, 'resources.update'),
        'PASS — resources.update NOT granted to viewer'
    );

    testCase('T05', 'Editor CANNOT manage roles',
        $editor && !simulatePermission($editor, 'roles.manage'),
        'PASS — roles.manage NOT granted to editor'
    );

    testCase('T06', 'Viewer CANNOT view audit logs',
        $viewer && !simulatePermission($viewer, 'audit_logs.view'),
        'PASS — audit_logs.view NOT granted to viewer'
    );

    testCase('T07', 'Admin CAN view audit logs',
        $admin && simulatePermission($admin, 'audit_logs.view'),
        'PASS — audit_logs.view granted to admin'
    );

    testCase('T08', 'Admin CAN delete resources',
        $admin && simulatePermission($admin, 'resources.delete'),
        'PASS — resources.delete granted to admin'
    );

    testCase('T09', 'Editor CANNOT delete resources',
        $editor && !simulatePermission($editor, 'resources.delete'),
        'PASS — resources.delete NOT granted to editor'
    );

    testCase('T10', 'Admin CAN manage settings',
        $admin && simulatePermission($admin, 'settings.manage'),
        'PASS — settings.manage granted to admin'
    );

    testCase('T11', 'Viewer CANNOT manage settings',
        $viewer && !simulatePermission($viewer, 'settings.manage'),
        'PASS — settings.manage NOT granted to viewer'
    );

    testCase('T12', 'Editor CAN view resources',
        $editor && simulatePermission($editor, 'resources.view'),
        'PASS — resources.view granted to editor'
    );

    testCase('T13', 'Admin CAN view users',
        $admin && simulatePermission($admin, 'users.view'),
        'PASS — users.view granted to admin'
    );

    testCase('T14', 'Viewer CANNOT view users',
        $viewer && !simulatePermission($viewer, 'users.view'),
        'PASS — users.view NOT granted to viewer'
    );

    testCase('T15', 'Editor CANNOT view users',
        $editor && !simulatePermission($editor, 'users.view'),
        'PASS — users.view NOT granted to editor'
    );

    // ---- SQL INJECTION TEST (via prepared statement) ----
    try {
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute(["' OR '1'='1"]);
        $rows = $stmt->fetchAll();
        testCase('T16', 'SQL injection payload returns no results (prepared statements)',
            count($rows) === 0,
            'PASS — Prepared statement blocked injection'
        );
    } catch (Throwable $e) {
        testCase('T16', 'SQL injection payload (prepared statements)', false, 'FAIL — Exception: '.$e->getMessage());
    }

    // ---- PASSWORD HASHING TEST ----
    if ($admin) {
        $isHashed = (substr($admin['password_hash'], 0, 4) === '$2y$') ||
                    (substr($admin['password_hash'], 0, 4) === '$2b$') ||
                    str_starts_with($admin['password_hash'], '$argon');
        testCase('T17', 'Passwords are stored as bcrypt/argon hashes (not plaintext)',
            $isHashed,
            'PASS — Password stored as secure hash'
        );
    }

    // ---- LAST ADMIN GUARD ----
    $adminCount = (int)$db->query("SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id=r.id WHERE r.slug='admin' AND u.is_active=1")->fetchColumn();
    testCase('T18', 'At least one active administrator exists',
        $adminCount >= 1,
        'PASS — Active admin account exists'
    );

    // ---- INACTIVE USER CHECK ----
    // Create a temporary inactive user and check login is blocked
    $testEmail = 'inactive_test_' . time() . '@rbac.test';
    $testHash  = password_hash('TestPass123!', PASSWORD_DEFAULT);
    $adminRole = $db->query("SELECT id FROM roles WHERE slug='viewer' LIMIT 1")->fetchColumn();
    $db->prepare("INSERT INTO users (name, email, password_hash, role_id, is_active) VALUES (?, ?, ?, ?, 0)")->execute(['Inactive Test', $testEmail, $testHash, $adminRole]);
    $loginResult = attemptLogin($testEmail, 'TestPass123!', '127.0.0.1');
    testCase('T19', 'Inactive user cannot log in',
        !$loginResult['success'],
        'PASS — Inactive account blocked'
    );
    $db->prepare("DELETE FROM users WHERE email=?")->execute([$testEmail]);

    // ---- RATE LIMITING ----
    $testIp = '10.0.0.99';
    $testMail = 'ratelimit@rbac.test';
    // Insert 5+ fake attempts
    for ($i = 0; $i < 6; $i++) {
        recordLoginAttempt($testIp, $testMail);
    }
    $attempts = getLoginAttempts($testIp, $testMail);
    testCase('T20', 'Rate limiting detects excessive login attempts',
        $attempts >= 5,
        'PASS — Rate limit threshold exceeded correctly'
    );
    // Clean up
    $db->prepare("DELETE FROM login_attempts WHERE ip_address=? OR email=?")->execute([$testIp, $testMail]);

} catch (Throwable $e) {
    $results[] = ['id'=>'ERR', 'description'=>'Test suite error', 'status'=>'FAIL', 'expected'=>$e->getMessage()];
    $failed++;
}

// -------------------------------------------------------
// Output
// -------------------------------------------------------
if ($isCli) {
    echo "\n";
    echo "========================================================\n";
    echo "  SECURE RBAC ADMIN PANEL — AUTHORIZATION TEST SUITE\n";
    echo "========================================================\n\n";
    foreach ($results as $r) {
        $icon = $r['status'] === 'PASS' ? '✓' : '✗';
        printf("[%s] %s — %s\n", $icon, $r['id'], $r['description']);
        if ($r['status'] === 'FAIL') {
            echo "     Expected: {$r['expected']}\n";
        }
    }
    echo "\n";
    echo "Results: $passed passed, $failed failed out of " . count($results) . " tests.\n";
    echo ($failed === 0 ? "All tests passed! ✓\n" : "Some tests FAILED. Review output above.\n");
    echo "\n";
    exit($failed > 0 ? 1 : 0);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorization Tests | RBAC Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <link href="/assets/css/style.css" rel="stylesheet">
</head>
<body style="padding:2rem 1rem;">
<div style="max-width:900px;margin:0 auto;">
    <div class="d-flex align-items-center gap-3 mb-4">
        <div class="sidebar-logo"><i class="fa-solid fa-vials"></i></div>
        <div>
            <h1 class="h5 text-white mb-0">Authorization Test Suite</h1>
            <p class="text-muted mb-0" style="font-size:0.82rem;">RBAC Admin Panel — Security Test Cases</p>
        </div>
        <div class="ms-auto">
            <?php if ($failed === 0): ?>
                <span class="badge bg-success px-3 py-2" style="font-size:0.85rem;">All <?= count($results) ?> Tests Passed ✓</span>
            <?php else: ?>
                <span class="badge bg-danger px-3 py-2" style="font-size:0.85rem;"><?= $failed ?> Failed</span>
            <?php endif; ?>
        </div>
    </div>

    <!-- Summary -->
    <div class="row g-3 mb-4">
        <div class="col-4"><div class="card text-center p-3"><div class="h4 text-white"><?= count($results) ?></div><div class="text-muted" style="font-size:0.8rem;">Total Tests</div></div></div>
        <div class="col-4"><div class="card text-center p-3"><div class="h4 text-success"><?= $passed ?></div><div class="text-muted" style="font-size:0.8rem;">Passed</div></div></div>
        <div class="col-4"><div class="card text-center p-3"><div class="h4 text-danger"><?= $failed ?></div><div class="text-muted" style="font-size:0.8rem;">Failed</div></div></div>
    </div>

    <!-- Results Table -->
    <div class="card">
        <div class="table-responsive">
            <table class="table mb-0">
                <thead>
                    <tr><th style="width:80px;">Test</th><th>Description</th><th>Expected</th><th style="width:90px;">Status</th></tr>
                </thead>
                <tbody>
                <?php foreach ($results as $r): ?>
                <tr>
                    <td class="mono text-muted"><?= e($r['id']) ?></td>
                    <td style="font-size:0.85rem;"><?= e($r['description']) ?></td>
                    <td style="font-size:0.78rem;color:var(--text-muted);"><?= e($r['expected']) ?></td>
                    <td>
                        <?php if ($r['status'] === 'PASS'): ?>
                            <span class="badge bg-success"><i class="fa-solid fa-check me-1"></i>PASS</span>
                        <?php else: ?>
                            <span class="badge bg-danger"><i class="fa-solid fa-xmark me-1"></i>FAIL</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="mt-3 text-center">
        <a href="/admin/dashboard.php" class="btn btn-outline-cyber btn-sm">Back to Dashboard</a>
    </div>
</div>
</body>
</html>
