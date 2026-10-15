<?php
/**
 * Global HTML Header / Sidebar Navigation
 * Secure Role-Based Access Control (RBAC) Admin Panel
 *
 * Included at the top of every protected page.
 * $pageTitle must be set before including this file.
 */
if (!defined('APP_INIT')) { define('APP_INIT', true); }
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/permissions.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/csrf.php';

requireLogin();
$user = getCurrentUser();
if (!$user) { redirect('/auth/login.php'); }

$pageTitle = $pageTitle ?? 'Dashboard';
$activeNav = $activeNav ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= e($pageTitle) ?> | CyberSec RBAC Portal</title>
    <meta name="description" content="Secure Role-Based Access Control Admin Panel">
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
<body>

<!-- Global Animated Cyber Particle Matrix Background -->
<canvas id="cyberCanvas"></canvas>

<!-- ===== SIDEBAR ===== -->
<nav id="sidebar" class="sidebar">
    <div class="sidebar-header">
        <div class="sidebar-logo">
            <i class="fa-solid fa-shield-halved"></i>
        </div>
        <div class="sidebar-brand">
            <span class="brand-name">CyberSec</span>
            <span class="brand-sub">RBAC Portal</span>
        </div>
        <button id="sidebarToggle" class="sidebar-toggle d-lg-none">
            <i class="fa-solid fa-xmark"></i>
        </button>
    </div>

    <div class="sidebar-user">
        <div class="sidebar-avatar">
            <?= strtoupper(substr($user['name'], 0, 2)) ?>
        </div>
        <div class="sidebar-userinfo">
            <div class="sidebar-username"><?= e($user['name']) ?></div>
            <div class="sidebar-role">
                <span class="role-dot role-dot-<?= e($user['role_slug']) ?>"></span>
                <?= e($user['role_name']) ?>
            </div>
        </div>
    </div>

    <ul class="sidebar-nav">
        <li class="nav-section-label">Main</li>

        <li class="sidebar-nav-item">
            <a href="/admin/dashboard.php" class="sidebar-nav-link <?= $activeNav === 'dashboard' ? 'active' : '' ?>">
                <i class="fa-solid fa-gauge-high nav-icon"></i>
                <span>Dashboard</span>
            </a>
        </li>

        <?php if (hasPermission('resources.view')): ?>
        <li class="sidebar-nav-item">
            <a href="/resources/index.php" class="sidebar-nav-link <?= $activeNav === 'resources' ? 'active' : '' ?>">
                <i class="fa-solid fa-folder-open nav-icon"></i>
                <span>Resources</span>
            </a>
        </li>
        <?php endif; ?>

        <?php if (hasPermission('users.view')): ?>
        <li class="nav-section-label">Administration</li>
        <li class="sidebar-nav-item">
            <a href="/admin/users.php" class="sidebar-nav-link <?= $activeNav === 'users' ? 'active' : '' ?>">
                <i class="fa-solid fa-users-gear nav-icon"></i>
                <span>User Management</span>
            </a>
        </li>
        <?php endif; ?>

        <?php if (hasPermission('roles.manage')): ?>
        <li class="sidebar-nav-item">
            <a href="/admin/roles.php" class="sidebar-nav-link <?= $activeNav === 'roles' ? 'active' : '' ?>">
                <i class="fa-solid fa-key nav-icon"></i>
                <span>Roles & Permissions</span>
            </a>
        </li>
        <?php endif; ?>

        <?php if (hasPermission('audit_logs.view')): ?>
        <li class="sidebar-nav-item">
            <a href="/admin/audit-logs.php" class="sidebar-nav-link <?= $activeNav === 'audit' ? 'active' : '' ?>">
                <i class="fa-solid fa-scroll nav-icon"></i>
                <span>Audit Logs</span>
            </a>
        </li>
        <?php endif; ?>

        <?php if (hasPermission('settings.manage')): ?>
        <li class="sidebar-nav-item">
            <a href="/admin/settings.php" class="sidebar-nav-link <?= $activeNav === 'settings' ? 'active' : '' ?>">
                <i class="fa-solid fa-sliders nav-icon"></i>
                <span>Settings</span>
            </a>
        </li>
        <?php endif; ?>

        <li class="nav-section-label">Account</li>
        <li class="sidebar-nav-item">
            <a href="/profile.php" class="sidebar-nav-link <?= $activeNav === 'profile' ? 'active' : '' ?>">
                <i class="fa-solid fa-circle-user nav-icon"></i>
                <span>My Profile</span>
            </a>
        </li>
        <li class="sidebar-nav-item">
            <a href="/auth/logout.php" class="sidebar-nav-link text-danger-soft"
               onclick="return confirm('Are you sure you want to log out?')">
                <i class="fa-solid fa-right-from-bracket nav-icon"></i>
                <span>Logout</span>
            </a>
        </li>
    </ul>
</nav>

<!-- ===== SIDEBAR OVERLAY (mobile) ===== -->
<div id="sidebarOverlay" class="sidebar-overlay d-lg-none"></div>

<!-- ===== MAIN CONTENT WRAPPER ===== -->
<div class="main-wrapper">

    <!-- Top Navigation Bar -->
    <header class="topbar">
        <button id="menuToggle" class="menu-toggle d-lg-none">
            <i class="fa-solid fa-bars"></i>
        </button>
        <div class="topbar-title">
            <h1 class="page-heading"><?= e($pageTitle) ?></h1>
        </div>
        <div class="topbar-right">
            <!-- Theme Switcher Dropdown -->
            <div class="dropdown">
                <button class="btn btn-outline-secondary btn-sm dropdown-toggle py-1 px-2" type="button" id="themeDropdown" data-bs-toggle="dropdown" aria-expanded="false" title="Change Visual Theme">
                    <i class="fa-solid fa-palette text-cyan me-1"></i>
                    <span class="d-none d-md-inline" id="currentThemeLabel">Theme</span>
                </button>
                <ul class="dropdown-menu dropdown-menu-end shadow" aria-labelledby="themeDropdown" style="background:var(--card-bg);border:1px solid var(--border-color);min-width:185px;">
                    <li><h6 class="dropdown-header text-muted" style="font-size:0.68rem;text-transform:uppercase;letter-spacing:0.05em;">Visual Theme</h6></li>
                    <li>
                        <button type="button" class="dropdown-item d-flex align-items-center justify-content-between theme-choice" data-theme="cyber">
                            <span class="d-flex align-items-center gap-2">
                                <span class="theme-dot" style="background:#00f2fe;box-shadow:0 0 6px #00f2fe;"></span>
                                Midnight Cyber
                            </span>
                            <i class="fa-solid fa-check text-cyan theme-check d-none"></i>
                        </button>
                    </li>
                    <li>
                        <button type="button" class="dropdown-item d-flex align-items-center justify-content-between theme-choice" data-theme="emerald">
                            <span class="d-flex align-items-center gap-2">
                                <span class="theme-dot" style="background:#10b981;box-shadow:0 0 6px #10b981;"></span>
                                Emerald SOC
                            </span>
                            <i class="fa-solid fa-check text-cyan theme-check d-none"></i>
                        </button>
                    </li>
                    <li>
                        <button type="button" class="dropdown-item d-flex align-items-center justify-content-between theme-choice" data-theme="violet">
                            <span class="d-flex align-items-center gap-2">
                                <span class="theme-dot" style="background:#c084fc;box-shadow:0 0 6px #c084fc;"></span>
                                Neon Synthwave
                            </span>
                            <i class="fa-solid fa-check text-cyan theme-check d-none"></i>
                        </button>
                    </li>
                    <li><hr class="dropdown-divider my-1" style="border-color:var(--border-color);"></li>
                    <li>
                        <button type="button" class="dropdown-item d-flex align-items-center justify-content-between theme-choice" data-theme="light">
                            <span class="d-flex align-items-center gap-2">
                                <span class="theme-dot" style="background:#2563eb;box-shadow:0 0 6px #2563eb;"></span>
                                Nordic Light
                            </span>
                            <i class="fa-solid fa-check text-cyan theme-check d-none"></i>
                        </button>
                    </li>
                </ul>
            </div>

            <span class="role-badge <?= e(roleBadgeClass($user['role_slug'])) ?>">
                <i class="fa-solid fa-circle-dot me-1"></i><?= e($user['role_name']) ?>
            </span>
            <div class="topbar-user">
                <a href="/profile.php" class="topbar-avatar" title="My Profile">
                    <?= strtoupper(substr($user['name'], 0, 2)) ?>
                </a>
            </div>
        </div>
    </header>

    <!-- Page Content Container -->
    <main class="content-area">
        <?= renderFlash() ?>
