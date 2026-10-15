<?php
/**
 * Setup and Initialization Wizard
 * Secure Role-Based Access Control (RBAC) Admin Panel
 *
 * Can be run from the Command Line (CLI):
 *   php setup.php
 * Or opened in the browser during first-time installation:
 *   http://127.0.0.1:8000/setup.php
 */

define('APP_INIT', true);
require_once __DIR__ . '/config/database.php';

$isCli = (php_sapi_name() === 'cli');
$success = null;
$error = null;
$info = null;

/**
 * Initializes the database tables and default seed records.
 */
function initializeDatabase(PDO $db, string $driver): void {
    if ($driver === 'sqlite') {
        $sql = file_get_contents(__DIR__ . '/database/schema.sqlite.sql');
        $db->exec($sql);
    } else {
        // MySQL / MariaDB
        $sql = file_get_contents(__DIR__ . '/database/rbac_admin_panel.sql');
        // Remove CREATE DATABASE and USE statements if executed in an existing connection
        $statements = array_filter(array_map('trim', explode(';', $sql)));
        foreach ($statements as $stmt) {
            if (!empty($stmt)) {
                $db->exec($stmt);
            }
        }
    }
}

/**
 * Checks if an administrator account already exists.
 */
function hasExistingAdmin(PDO $db): bool {
    try {
        $stmt = $db->prepare("
            SELECT COUNT(*) 
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE r.slug = 'admin' AND u.is_active = 1
        ");
        $stmt->execute();
        return (int)$stmt->fetchColumn() > 0;
    } catch (Throwable $e) {
        return false;
    }
}

/**
 * Creates a user safely with hashed password.
 */
function createUser(PDO $db, string $name, string $email, string $password, string $roleSlug): int {
    $stmt = $db->prepare("SELECT id FROM roles WHERE slug = ?");
    $stmt->execute([$roleSlug]);
    $roleId = $stmt->fetchColumn();

    if (!$roleId) {
        throw new Exception("Role '$roleSlug' does not exist.");
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $db->prepare("
        INSERT INTO users (name, email, password_hash, role_id, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    ");
    $stmt->execute([$name, $email, $hash, $roleId]);
    return (int)$db->lastInsertId();
}

/**
 * Logs a setup audit event.
 */
function logSetupEvent(PDO $db, string $event, string $desc): void {
    try {
        $stmt = $db->prepare("
            INSERT INTO audit_logs (user_id, event_type, description, ip_address, user_agent, status, created_at)
            VALUES (NULL, ?, ?, '127.0.0.1', 'System Installer', 'SUCCESS', CURRENT_TIMESTAMP)
        ");
        $stmt->execute([$event, $desc]);
    } catch (Throwable $e) {
        // Ignore during fresh bootstrap
    }
}

// -------------------------------------------------------------
// CLI Execution Handler
// -------------------------------------------------------------
if ($isCli) {
    echo "========================================================\n";
    echo "  SECURE RBAC ADMIN PANEL - SETUP & INITIALIZATION WIZARD\n";
    echo "========================================================\n\n";

    try {
        // Test connection or initialize SQLite fallback if needed
        $driver = strtolower(DB_DRIVER);
        echo "[*] Connecting to database (Driver: $driver)...\n";
        
        $db = null;
        try {
            $db = getDB();
        } catch (Throwable $e) {
            echo "[!] MySQL connection failed: " . $e->getMessage() . "\n";
            echo "[*] Falling back to high-performance local SQLite database...\n";
            putenv('DB_DRIVER=sqlite');
            $driver = 'sqlite';
            $db = getDB(true);
        }

        echo "[*] Initializing database schema and role permissions...\n";
        initializeDatabase($db, $driver);
        echo "[+] Schema and base permissions initialized successfully.\n";

        // Admin Account Setup
        $adminName = 'Super Administrator';
        $adminEmail = 'admin@example.com';
        $adminPassword = 'AdminPassword123!';

        // Check if custom args provided
        $options = getopt('', ['name:', 'email:', 'password:', 'seed-demo:']);
        if (isset($options['name'])) $adminName = $options['name'];
        if (isset($options['email'])) $adminEmail = $options['email'];
        if (isset($options['password'])) $adminPassword = $options['password'];

        $adminId = createUser($db, $adminName, $adminEmail, $adminPassword, 'admin');
        echo "[+] Initial Administrator account created:\n";
        echo "    Name:     $adminName\n";
        echo "    Email:    $adminEmail\n";
        echo "    Password: $adminPassword\n";

        // Seed demo accounts for Editor and Viewer to allow immediate multi-role testing
        $editorId = createUser($db, 'Content Editor', 'editor@example.com', 'EditorPassword123!', 'editor');
        $viewerId = createUser($db, 'Auditor Viewer', 'viewer@example.com', 'ViewerPassword123!', 'viewer');
        echo "[+] Demo accounts seeded:\n";
        echo "    Editor:   editor@example.com / EditorPassword123!\n";
        echo "    Viewer:   viewer@example.com / ViewerPassword123!\n";

        // Seed sample resources
        $stmt = $db->prepare("
            INSERT INTO resources (title, description, category, status, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ");
        $stmt->execute([
            'Network Security Policy Document',
            'Internal standard operating procedures for firewall rules, zero-trust perimeter enforcement, and VPN access.',
            'Cybersecurity',
            'Published',
            $adminId
        ]);
        $stmt->execute([
            'Vulnerability Assessment Report Q3',
            'Quarterly vulnerability scanner logs, automated penetration testing telemetry, and patching prioritization matrix.',
            'Audit',
            'Published',
            $editorId
        ]);
        echo "[+] Sample resources populated.\n";

        logSetupEvent($db, 'SYSTEM_INITIALIZATION', 'System initialized and administrator account created via CLI.');
        echo "\n[✓] Setup completed successfully!\n";
        echo "You can now run: php -S 127.0.0.1:8000\n";
        echo "And open:        http://127.0.0.1:8000\n\n";
        exit(0);

    } catch (Throwable $e) {
        echo "[!] Error during setup: " . $e->getMessage() . "\n";
        exit(1);
    }
}

// -------------------------------------------------------------
// Web Browser Execution Handler
// -------------------------------------------------------------
$dbStatus = checkDatabaseStatus();
$alreadySetup = false;

if ($dbStatus['connected'] && $dbStatus['initialized']) {
    try {
        $db = getDB();
        $alreadySetup = hasExistingAdmin($db);
    } catch (Throwable $e) {
        $alreadySetup = false;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'setup') {
        $adminName = trim($_POST['admin_name'] ?? '');
        $adminEmail = trim($_POST['admin_email'] ?? '');
        $adminPassword = $_POST['admin_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        $seedDemo = isset($_POST['seed_demo']);
        $driverChoice = $_POST['driver'] ?? 'mysql';

        if (empty($adminName) || empty($adminEmail) || empty($adminPassword)) {
            $error = 'All fields are required.';
        } elseif (!filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please enter a valid email address.';
        } elseif (strlen($adminPassword) < 8) {
            $error = 'Password must be at least 8 characters long.';
        } elseif ($adminPassword !== $confirmPassword) {
            $error = 'Passwords do not match.';
        } else {
            try {
                if ($driverChoice === 'sqlite') {
                    putenv('DB_DRIVER=sqlite');
                }
                $db = getDB(true);
                $driver = $db->getAttribute(PDO::ATTR_DRIVER_NAME);

                initializeDatabase($db, $driver);
                $adminId = createUser($db, $adminName, $adminEmail, $adminPassword, 'admin');

                if ($seedDemo) {
                    createUser($db, 'Content Editor', 'editor@example.com', 'EditorPassword123!', 'editor');
                    createUser($db, 'Auditor Viewer', 'viewer@example.com', 'ViewerPassword123!', 'viewer');
                    
                    // Sample resources
                    $stmt = $db->prepare("
                        INSERT INTO resources (title, description, category, status, created_by, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ");
                    $stmt->execute([
                        'Network Security Policy Document',
                        'Internal standard operating procedures for firewall rules, zero-trust perimeter enforcement, and VPN access.',
                        'Cybersecurity',
                        'Published',
                        $adminId
                    ]);
                }

                logSetupEvent($db, 'SYSTEM_INITIALIZATION', "System initialized and admin '$adminEmail' created via Web Wizard.");
                $success = "Setup completed successfully! Administrator account created.";
                $alreadySetup = true;
            } catch (Throwable $e) {
                $error = "Setup failed: " . $e->getMessage();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Setup | Secure RBAC Portal</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0a0f1d;
            --card-bg: rgba(16, 24, 48, 0.85);
            --accent-cyan: #00f2fe;
            --accent-blue: #4facfe;
            --text-main: #e2e8f0;
            --text-muted: #94a3b8;
            --border-glow: rgba(0, 242, 254, 0.25);
        }
        body {
            background: radial-gradient(circle at 50% 20%, #111e38 0%, #070b14 100%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            padding: 2rem 1rem;
        }
        .setup-card {
            background: var(--card-bg);
            border: 1px solid var(--border-glow);
            backdrop-filter: blur(16px);
            border-radius: 1rem;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6), 0 0 30px rgba(0, 242, 254, 0.1);
            max-width: 650px;
            width: 100%;
            overflow: hidden;
        }
        .setup-header {
            background: linear-gradient(135deg, rgba(0, 242, 254, 0.15), rgba(79, 172, 254, 0.05));
            border-bottom: 1px solid var(--border-glow);
            padding: 2rem;
            text-align: center;
        }
        .form-control, .form-select {
            background: rgba(10, 15, 29, 0.7);
            border: 1px solid rgba(148, 163, 184, 0.2);
            color: #fff;
            padding: 0.75rem 1rem;
        }
        .form-control:focus, .form-select:focus {
            background: rgba(10, 15, 29, 0.9);
            border-color: var(--accent-cyan);
            color: #fff;
            box-shadow: 0 0 10px rgba(0, 242, 254, 0.3);
        }
        .btn-cyber {
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            border: none;
            color: #070b14;
            font-weight: 600;
            padding: 0.85rem;
            border-radius: 0.5rem;
            transition: all 0.3s;
        }
        .btn-cyber:hover {
            opacity: 0.95;
            box-shadow: 0 0 20px rgba(0, 242, 254, 0.4);
            color: #000;
        }
        .badge-status {
            font-size: 0.85rem;
            padding: 0.4rem 0.8rem;
            border-radius: 2rem;
        }
    </style>
</head>
<body>

<div class="setup-card">
    <div class="setup-header">
        <div class="mb-3">
            <i class="fa-solid fa-shield-halved fa-3x" style="color: var(--accent-cyan);"></i>
        </div>
        <h2 class="h4 text-white fw-bold mb-1">CyberSec RBAC Portal Setup</h2>
        <p class="text-muted small mb-0">Role-Based Access Control Initial Configuration & Admin Setup</p>
    </div>

    <div class="p-4 p-md-5">
        <?php if ($success): ?>
            <div class="alert alert-success d-flex align-items-center mb-4" role="alert">
                <i class="fa-solid fa-circle-check me-2 fs-5"></i>
                <div><?= htmlspecialchars($success) ?></div>
            </div>
            <div class="text-center mt-4">
                <a href="auth/login.php" class="btn btn-cyber px-4 py-2">
                    <i class="fa-solid fa-right-to-bracket me-2"></i>Proceed to Login
                </a>
            </div>
        <?php elseif ($alreadySetup): ?>
            <div class="alert alert-info d-flex align-items-center mb-4">
                <i class="fa-solid fa-shield-cat me-2 fs-5"></i>
                <div>
                    <strong>System Already Initialized!</strong>
                    <div class="small mt-1">An active administrator account is already configured. Setup is locked to protect system integrity.</div>
                </div>
            </div>
            <div class="text-center mt-4">
                <a href="auth/login.php" class="btn btn-cyber px-4 py-2">
                    <i class="fa-solid fa-right-to-bracket me-2"></i>Go to Login Portal
                </a>
            </div>
        <?php else: ?>
            <?php if ($error): ?>
                <div class="alert alert-danger d-flex align-items-center mb-4" role="alert">
                    <i class="fa-solid fa-triangle-exclamation me-2 fs-5"></i>
                    <div><?= htmlspecialchars($error) ?></div>
                </div>
            <?php endif; ?>

            <div class="mb-4 p-3 rounded" style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08);">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <div class="fw-semibold text-white">Database Environment</div>
                        <div class="small text-muted">Configured Driver: <?= htmlspecialchars(DB_DRIVER) ?></div>
                    </div>
                    <div>
                        <?php if ($dbStatus['connected']): ?>
                            <span class="badge bg-success badge-status"><i class="fa-solid fa-check me-1"></i>Connected (<?= htmlspecialchars($dbStatus['driver']) ?>)</span>
                        <?php else: ?>
                            <span class="badge bg-warning text-dark badge-status"><i class="fa-solid fa-info me-1"></i>Will auto-fallback to SQLite</span>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <form method="POST" action="setup.php">
                <input type="hidden" name="action" value="setup">

                <h5 class="text-white mb-3"><i class="fa-solid fa-user-shield me-2 text-info"></i>Create Primary Administrator</h5>

                <div class="mb-3">
                    <label class="form-label text-light small">Full Name</label>
                    <input type="text" name="admin_name" class="form-control" placeholder="e.g. Alex Morgan" required value="Security Administrator">
                </div>

                <div class="mb-3">
                    <label class="form-label text-light small">Administrator Email</label>
                    <input type="email" name="admin_email" class="form-control" placeholder="admin@example.com" required value="admin@example.com">
                </div>

                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-light small">Admin Password</label>
                        <input type="password" name="admin_password" class="form-control" placeholder="Min. 8 characters" required>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label text-light small">Confirm Password</label>
                        <input type="password" name="confirm_password" class="form-control" placeholder="Re-enter password" required>
                    </div>
                </div>

                <div class="mb-4">
                    <label class="form-label text-light small">Database Driver</label>
                    <select name="driver" class="form-select">
                        <option value="mysql" <?= DB_DRIVER === 'mysql' ? 'selected' : '' ?>>MySQL / MariaDB (XAMPP / Homebrew)</option>
                        <option value="sqlite">SQLite (Standalone Zero-Dependency)</option>
                    </select>
                    <div class="form-text text-muted small">Choose MySQL if running XAMPP/MySQL service; choose SQLite for instant local execution.</div>
                </div>

                <div class="form-check mb-4">
                    <input class="form-check-input" type="checkbox" name="seed_demo" id="seedDemo" checked>
                    <label class="form-check-label text-light small" for="seedDemo">
                        Seed sample <strong>Editor</strong> and <strong>Viewer</strong> accounts and demonstration resources for quick testing.
                    </label>
                </div>

                <button type="submit" class="btn btn-cyber w-100">
                    <i class="fa-solid fa-key me-2"></i>Initialize Database & Create Admin
                </button>
            </form>
        <?php endif; ?>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
