-- ========================================================
-- Secure Role-Based Access Control (RBAC) Admin Panel
-- SQLite Schema (For local automated testing and zero-config mode)
-- ========================================================

PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS `login_attempts`;
DROP TABLE IF EXISTS `audit_logs`;
DROP TABLE IF EXISTS `resources`;
DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `role_permissions`;
DROP TABLE IF EXISTS `permissions`;
DROP TABLE IF EXISTS `roles`;
DROP TABLE IF EXISTS `system_settings`;

CREATE TABLE `roles` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `name` TEXT NOT NULL UNIQUE,
  `slug` TEXT NOT NULL UNIQUE,
  `description` TEXT,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE `permissions` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `name` TEXT NOT NULL,
  `slug` TEXT NOT NULL UNIQUE,
  `module` TEXT NOT NULL,
  `description` TEXT,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE `role_permissions` (
  `role_id` INTEGER NOT NULL,
  `permission_id` INTEGER NOT NULL,
  PRIMARY KEY (`role_id`, `permission_id`),
  FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE `users` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `name` TEXT NOT NULL,
  `email` TEXT NOT NULL UNIQUE,
  `password_hash` TEXT NOT NULL,
  `role_id` INTEGER NOT NULL,
  `is_active` INTEGER NOT NULL DEFAULT 1,
  `last_login_at` DATETIME DEFAULT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE `resources` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `title` TEXT NOT NULL,
  `description` TEXT NOT NULL,
  `category` TEXT DEFAULT 'General',
  `status` TEXT DEFAULT 'Published',
  `created_by` INTEGER NOT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE `audit_logs` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `user_id` INTEGER DEFAULT NULL,
  `event_type` TEXT NOT NULL,
  `description` TEXT NOT NULL,
  `ip_address` TEXT NOT NULL,
  `user_agent` TEXT,
  `status` TEXT DEFAULT 'SUCCESS',
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE `login_attempts` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `ip_address` TEXT NOT NULL,
  `email` TEXT NOT NULL,
  `attempted_at` DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE `system_settings` (
  `key_name` TEXT PRIMARY KEY,
  `key_value` TEXT NOT NULL,
  `description` TEXT,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Seed Roles
INSERT INTO `roles` (`id`, `name`, `slug`, `description`) VALUES
(1, 'Administrator', 'admin', 'Full system access and security administration privileges'),
(2, 'Editor', 'editor', 'Can view, create and modify resources; no user or administrative controls'),
(3, 'Viewer', 'viewer', 'Read-only access to view authorized resources and dashboard');

-- Seed Permissions
INSERT INTO `permissions` (`id`, `name`, `slug`, `module`, `description`) VALUES
(1, 'View Dashboard', 'dashboard.view', 'Dashboard', 'Access and view metrics and activity dashboard'),
(2, 'View Resources', 'resources.view', 'Resources', 'Browse and view resource records'),
(3, 'Create Resources', 'resources.create', 'Resources', 'Create new resource records'),
(4, 'Update Resources', 'resources.update', 'Resources', 'Edit existing resource records'),
(5, 'Delete Resources', 'resources.delete', 'Resources', 'Delete resource records permanently'),
(6, 'View Users', 'users.view', 'User Management', 'Browse user accounts list and user profiles'),
(7, 'Create Users', 'users.create', 'User Management', 'Create new user accounts and assign roles'),
(8, 'Update Users', 'users.update', 'User Management', 'Edit user profiles, change roles, toggle active status'),
(9, 'Delete Users', 'users.delete', 'User Management', 'Delete user accounts'),
(10, 'Manage Roles', 'roles.manage', 'RBAC', 'Inspect role definitions and permission mappings'),
(11, 'View Audit Logs', 'audit_logs.view', 'Security', 'Inspect security audit logs and event history'),
(12, 'Manage Settings', 'settings.manage', 'System', 'Modify system settings, registration, and security policies');

-- Seed Role Permissions
INSERT INTO `role_permissions` (`role_id`, `permission_id`) VALUES
(1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 7), (1, 8), (1, 9), (1, 10), (1, 11), (1, 12),
(2, 1), (2, 2), (2, 3), (2, 4),
(3, 1), (3, 2);

-- Seed Settings
INSERT INTO `system_settings` (`key_name`, `key_value`, `description`) VALUES
('app_name', 'CyberSec RBAC Portal', 'Application display title'),
('public_registration', '0', 'Allow self-registration (0=Disabled, 1=Enabled)'),
('max_login_attempts', '5', 'Max failed login attempts before lockout'),
('lockout_duration_minutes', '15', 'Lockout duration in minutes for rate limiting'),
('session_timeout_minutes', '30', 'Session inactivity expiration in minutes');
