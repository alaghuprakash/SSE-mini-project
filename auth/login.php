<?php
/**
 * Login Page — Interactive Cybersecurity Edition
 * Secure Role-Based Access Control (RBAC) Admin Panel
 */
define('APP_INIT', true);
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/functions.php';

startSecureSession();

// Already logged in? Redirect to dashboard
if (isAuthenticated()) {
    redirect('/admin/dashboard.php');
}

$error    = '';
$redirect = filter_var($_GET['redirect'] ?? '', FILTER_SANITIZE_URL);
$reason   = $_GET['reason'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify();

    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $ip       = getClientIP();

    if (empty($email) || empty($password)) {
        $error = 'Please enter your email and password.';
    } else {
        $result = attemptLogin($email, $password, $ip);
        if ($result['success']) {
            // Safe redirect — only allow relative paths
            if ($redirect && strpos($redirect, '/') === 0 && strpos($redirect, '//') !== 0) {
                redirect($redirect);
            }
            redirect('/admin/dashboard.php');
        } else {
            $error = $result['error'];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero-Trust Authentication | CyberSec RBAC Portal</title>
    <meta name="description" content="Secure Role-Based Access Control Admin Panel with Dynamic Multi-Theme Interface">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="/assets/css/style.css" rel="stylesheet">
    <script>
        (function() {
            try {
                const t = localStorage.getItem('rbac_theme') || 'cyber';
                document.documentElement.setAttribute('data-theme', t);
            } catch(e) {}
        })();
    </script>
</head>
<body class="login-page">

<!-- Interactive Glowing Cyber Particle Canvas Background -->
<canvas id="cyberCanvas"></canvas>

<!-- Main Login Glassmorphism Card -->
<div class="login-card fade-in-up">

    <!-- Card Header with Animated Holographic Radar -->
    <div class="login-header position-relative">

        <!-- Top Controls: Theme Switcher & System Specs Modal Trigger -->
        <div class="position-absolute top-0 end-0 m-3 d-flex align-items-center gap-2">
            <!-- Architecture Specs Trigger -->
            <button type="button" class="btn btn-outline-secondary btn-sm py-1 px-2"
                    data-bs-toggle="modal" data-bs-target="#secArchModal"
                    title="Cybersecurity Architecture Specs">
                <i class="fa-solid fa-microchip text-cyan"></i>
            </button>

            <!-- Floating Theme Selector -->
            <div class="dropdown">
                <button class="btn btn-outline-secondary btn-sm dropdown-toggle py-1 px-2"
                        type="button" id="loginThemeDropdown" data-bs-toggle="dropdown" aria-expanded="false"
                        title="Change Theme">
                    <i class="fa-solid fa-palette text-cyan"></i>
                </button>
                <ul class="dropdown-menu dropdown-menu-end shadow" aria-labelledby="loginThemeDropdown"
                    style="background:var(--card-bg);border:1px solid var(--border-color);min-width:180px;">
                    <li><h6 class="dropdown-header text-muted" style="font-size:0.68rem;text-transform:uppercase;">Select Theme</h6></li>
                    <li><button type="button" class="dropdown-item d-flex align-items-center gap-2 theme-choice" data-theme="cyber"><span class="theme-dot" style="background:#00f2fe;box-shadow:0 0 6px #00f2fe;"></span> Midnight Cyber</button></li>
                    <li><button type="button" class="dropdown-item d-flex align-items-center gap-2 theme-choice" data-theme="emerald"><span class="theme-dot" style="background:#10b981;box-shadow:0 0 6px #10b981;"></span> Emerald SOC</button></li>
                    <li><button type="button" class="dropdown-item d-flex align-items-center gap-2 theme-choice" data-theme="violet"><span class="theme-dot" style="background:#c084fc;box-shadow:0 0 6px #c084fc;"></span> Neon Synthwave</button></li>
                    <li><hr class="dropdown-divider my-1" style="border-color:var(--border-color);"></li>
                    <li><button type="button" class="dropdown-item d-flex align-items-center gap-2 theme-choice" data-theme="light"><span class="theme-dot" style="background:#2563eb;box-shadow:0 0 6px #2563eb;"></span> Nordic Light</button></li>
                </ul>
            </div>
        </div>

        <!-- Radar Pulse & Rotating Holographic Shield -->
        <div class="login-icon-container">
            <div class="radar-pulse-ring"></div>
            <div class="radar-scanner"></div>
            <div class="login-icon glow-pulse">
                <i class="fa-solid fa-shield-halved"></i>
            </div>
        </div>

        <h1 class="h5 text-white fw-bold mb-1">CyberSec RBAC Portal</h1>
        <p class="text-muted small mb-0">Role-Based Access Control &bull; SSE Security Project</p>
    </div>

    <!-- Card Body -->
    <div class="p-4">

        <?php if ($reason === 'timeout'): ?>
            <div class="alert alert-warning d-flex align-items-center mb-3">
                <i class="fa-solid fa-clock me-2"></i>
                <div>Your session expired due to inactivity. Please log in again.</div>
            </div>
        <?php elseif ($reason === 'deactivated'): ?>
            <div class="alert alert-danger d-flex align-items-center mb-3">
                <i class="fa-solid fa-ban me-2"></i>
                <div>Your account has been deactivated by an administrator.</div>
            </div>
        <?php elseif ($reason === 'logout'): ?>
            <div class="alert alert-success d-flex align-items-center mb-3">
                <i class="fa-solid fa-circle-check me-2"></i>
                <div>You have been safely logged out. Session destroyed.</div>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="alert alert-danger d-flex align-items-center mb-3" role="alert">
                <i class="fa-solid fa-triangle-exclamation me-2"></i>
                <div><?= e($error) ?></div>
            </div>
        <?php endif; ?>

        <!-- 1-Click Interactive Evaluation Role Switcher -->
        <div class="mb-3 p-2 rounded" style="background:rgba(255,255,255,0.02);border:1px solid var(--border-color);">
            <div class="d-flex justify-content-between align-items-center mb-1">
                <span class="section-title mb-0" style="font-size:0.68rem;">
                    <i class="fa-solid fa-wand-magic-sparkles me-1 text-cyan"></i>1-Click Role Fill (Demo Mode)
                </span>
                <span class="badge bg-dark border text-muted" style="font-size:0.62rem;">Instant Evaluation</span>
            </div>
            <div class="d-flex flex-wrap gap-1 mt-1">
                <button type="button" class="role-pill-btn role-autofill"
                        data-email="admin@example.com" data-pwd="AdminPassword123!" data-role="Admin"
                        data-tier="Tier 1 &mdash; Full System Control (Roles, Audit Logs, Users, Resources)">
                    <span class="role-dot role-dot-admin"></span> Super Admin
                </button>
                <button type="button" class="role-pill-btn role-autofill"
                        data-email="editor@example.com" data-pwd="EditorPassword123!" data-role="Editor"
                        data-tier="Tier 2 &mdash; Resource Operations (Create, Browse, Update)">
                    <span class="role-dot role-dot-editor"></span> Editor
                </button>
                <button type="button" class="role-pill-btn role-autofill"
                        data-email="viewer@example.com" data-pwd="ViewerPassword123!" data-role="Viewer"
                        data-tier="Tier 3 &mdash; Read-Only Audit & Inspection">
                    <span class="role-dot role-dot-viewer"></span> Viewer
                </button>
            </div>
            <div id="clearancePreview" class="text-cyan mt-2 d-none" style="font-size:0.75rem;line-height:1.3;">
                <i class="fa-solid fa-fingerprint fa-xs me-1"></i><span id="clearanceText"></span>
            </div>
        </div>

        <!-- Login Form -->
        <form method="POST" action="login.php" novalidate autocomplete="on" id="loginForm">
            <?= csrfField() ?>
            <?php if ($redirect): ?>
                <input type="hidden" name="redirect" value="<?= e($redirect) ?>">
            <?php endif; ?>

            <div class="mb-3">
                <label for="email" class="form-label">Email Address</label>
                <div class="input-group">
                    <span class="input-group-text" style="background:rgba(7,12,27,0.8);border-color:var(--border-color);color:var(--text-muted);">
                        <i class="fa-solid fa-envelope fa-sm"></i>
                    </span>
                    <input
                        type="email"
                        id="email"
                        name="email"
                        class="form-control"
                        placeholder="admin@example.com"
                        value="<?= e($_POST['email'] ?? '') ?>"
                        autocomplete="username"
                        required
                    >
                </div>
            </div>

            <div class="mb-4">
                <label for="password_field" class="form-label">Password</label>
                <div class="input-group">
                    <span class="input-group-text" style="background:rgba(7,12,27,0.8);border-color:var(--border-color);color:var(--text-muted);">
                        <i class="fa-solid fa-lock fa-sm"></i>
                    </span>
                    <input
                        type="password"
                        id="password_field"
                        name="password"
                        class="form-control"
                        placeholder="Your password"
                        autocomplete="current-password"
                        required
                    >
                    <button
                        type="button"
                        class="input-group-text"
                        onclick="togglePasswordVisibility()"
                        title="Show/hide password"
                        style="background:rgba(7,12,27,0.8);border-color:var(--border-color);color:var(--text-muted);cursor:pointer;"
                    >
                        <i id="pwdEyeIcon" class="fa-solid fa-eye fa-sm"></i>
                    </button>
                </div>
            </div>

            <button type="submit" class="btn btn-cyber w-100 py-2" id="loginBtn">
                <i class="fa-solid fa-right-to-bracket me-2"></i>Authenticate & Enter Portal
            </button>
        </form>

        <!-- Security Defense Protocols Status Ticker -->
        <div class="security-status-ticker mt-3">
            <span class="status-live-dot"></span>
            <span><strong>Zero-Trust Shield Active</strong> &bull; PDO Prepared &bull; CSRF Salted</span>
        </div>

    </div>
</div>

<!-- ================= CYBERSECURITY ARCHITECTURE MODAL ================= -->
<div class="modal fade" id="secArchModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content" style="background:var(--bg-secondary);border:1px solid var(--border-glow);">
            <div class="modal-header" style="border-color:var(--border-color);">
                <h5 class="modal-title text-white">
                    <i class="fa-solid fa-microchip me-2 text-cyan"></i>Security Architecture Specs
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" style="font-size:0.85rem;">
                <p class="text-muted mb-3">
                    Engineered for college evaluation benchmarks with multi-layered defensive security controls:
                </p>

                <div class="d-flex align-items-start gap-2 mb-2">
                    <i class="fa-solid fa-shield text-cyan mt-1"></i>
                    <div>
                        <strong class="text-white">Role-Based Access Control (RBAC):</strong>
                        <div class="text-muted">Strict server-side policy enforcement with zero trust on client input.</div>
                    </div>
                </div>

                <div class="d-flex align-items-start gap-2 mb-2">
                    <i class="fa-solid fa-database text-cyan mt-1"></i>
                    <div>
                        <strong class="text-white">Injection Resistance:</strong>
                        <div class="text-muted">100% parameter-bound queries via PHP PDO (SQLi protection).</div>
                    </div>
                </div>

                <div class="d-flex align-items-start gap-2 mb-2">
                    <i class="fa-solid fa-key text-cyan mt-1"></i>
                    <div>
                        <strong class="text-white">Password Hashing:</strong>
                        <div class="text-muted">Bcrypt adaptive hashing with auto-generated salts.</div>
                    </div>
                </div>

                <div class="d-flex align-items-start gap-2 mb-2">
                    <i class="fa-solid fa-stopwatch text-cyan mt-1"></i>
                    <div>
                        <strong class="text-white">Brute-Force Throttling:</strong>
                        <div class="text-muted">Automatic 15-minute IP/Email lockout after 5 consecutive failed attempts.</div>
                    </div>
                </div>

                <div class="d-flex align-items-start gap-2">
                    <i class="fa-solid fa-scroll text-cyan mt-1"></i>
                    <div>
                        <strong class="text-white">Immutable Security Audit Logs:</strong>
                        <div class="text-muted">Real-time telemetry recording IP, User Agent, Timestamp, and Outcome.</div>
                    </div>
                </div>
            </div>
            <div class="modal-footer" style="border-color:var(--border-color);">
                <button type="button" class="btn btn-cyber btn-sm" data-bs-dismiss="modal">Close Specs</button>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="/assets/js/app.js"></script>

<script>
// Password show/hide toggle
function togglePasswordVisibility() {
    const f = document.getElementById('password_field');
    const i = document.getElementById('pwdEyeIcon');
    if (f.type === 'password') {
        f.type = 'text';
        i.classList.replace('fa-eye', 'fa-eye-slash');
    } else {
        f.type = 'password';
        i.classList.replace('fa-eye-slash', 'fa-eye');
    }
}

// 1-Click Role Quick Fill with glowing highlight
document.querySelectorAll('.role-autofill').forEach(btn => {
    btn.addEventListener('click', function() {
        document.querySelectorAll('.role-autofill').forEach(b => b.classList.remove('active'));
        this.classList.add('active');

        const emailInput = document.getElementById('email');
        const pwdInput   = document.getElementById('password_field');

        emailInput.value = this.dataset.email;
        pwdInput.value   = this.dataset.pwd;

        emailInput.classList.add('input-highlight');
        pwdInput.classList.add('input-highlight');
        setTimeout(() => {
            emailInput.classList.remove('input-highlight');
            pwdInput.classList.remove('input-highlight');
        }, 600);

        const previewBox = document.getElementById('clearancePreview');
        const previewTxt = document.getElementById('clearanceText');
        previewBox.classList.remove('d-none');
        previewTxt.innerHTML = '<strong>' + this.dataset.role + ':</strong> ' + this.dataset.tier;
    });
});

// Form submission spinner
document.getElementById('loginForm')?.addEventListener('submit', () => {
    const btn = document.getElementById('loginBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i>Verifying Credentials…';
});
</script>
</body>
</html>
