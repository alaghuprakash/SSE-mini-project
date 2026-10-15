-- ========================================================
-- Secure Role-Based Access Control (RBAC) Admin Panel
-- Database Schema: rbac_admin_panel
-- Designed for MySQL / MariaDB (XAMPP / Homebrew / Production)
-- ========================================================

CREATE DATABASE IF NOT EXISTS `rbac_admin_panel` 
  CHARACTER SET utf8mb4 
  COLLATE utf8mb4_unicode_ci;

USE `rbac_admin_panel`;

-- Disable foreign key checks during initialization
SET FOREIGN_KEY_CHECKS = 0;

-- --------------------------------------------------------
-- 1. Table structure for table `roles`
-- --------------------------------------------------------
DROP TABLE IF EXISTS `roles`;
CREATE TABLE `roles` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(50) NOT NULL UNIQUE,
  `slug` VARCHAR(50) NOT NULL UNIQUE,
  `description` VARCHAR(255) DEFAULT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- 2. Table structure for table `permissions`
-- --------------------------------------------------------
DROP TABLE IF EXISTS `permissions`;
CREATE TABLE `permissions` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(100) NOT NULL,
  `slug` VARCHAR(100) NOT NULL UNIQUE,
  `module` VARCHAR(50) NOT NULL,
  `description` VARCHAR(255) DEFAULT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- 3. Table structure for table `role_permissions`
-- --------------------------------------------------------
DROP TABLE IF EXISTS `role_permissions`;
CREATE TABLE `role_permissions` (
  `role_id` INT UNSIGNED NOT NULL,
  `permission_id` INT UNSIGNED NOT NULL,
  PRIMARY KEY (`role_id`, `permission_id`),
  CONSTRAINT `fk_rp_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_rp_permission` FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- 4. Table structure for table `users`
-- --------------------------------------------------------
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(100) NOT NULL,
  `email` VARCHAR(191) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `role_id` INT UNSIGNED NOT NULL,
  `is_active` TINYINT(1) NOT NULL DEFAULT 1,
  `last_login_at` DATETIME DEFAULT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT `fk_users_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
  INDEX `idx_users_role` (`role_id`),
  INDEX `idx_users_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- 5. Table structure for table `resources`
-- --------------------------------------------------------
DROP TABLE IF EXISTS `resources`;
CREATE TABLE `resources` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `title` VARCHAR(200) NOT NULL,
  `description` TEXT NOT NULL,
  `category` VARCHAR(50) DEFAULT 'General',
  `status` VARCHAR(20) DEFAULT 'Published',
  `created_by` INT UNSIGNED NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT `fk_resources_creator` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  INDEX `idx_resources_creator` (`created_by`),
  INDEX `idx_resources_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- 6. Table structure for table `audit_logs`
-- --------------------------------------------------------
DROP TABLE IF EXISTS `audit_logs`;
CREATE TABLE `audit_logs` (
  `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT UNSIGNED DEFAULT NULL,
  `event_type` VARCHAR(80) NOT NULL,
  `description` TEXT NOT NULL,
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(255) DEFAULT NULL,
  `status` ENUM('SUCCESS', 'WARNING', 'DENIED', 'FAILED') DEFAULT 'SUCCESS',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  INDEX `idx_audit_user` (`user_id`),
  INDEX `idx_audit_event` (`event_type`),
  INDEX `idx_audit_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- 7. Table structure for table `login_attempts`
-- --------------------------------------------------------
DROP TABLE IF EXISTS `login_attempts`;
CREATE TABLE `login_attempts` (
  `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `ip_address` VARCHAR(45) NOT NULL,
  `email` VARCHAR(191) NOT NULL,
  `attempted_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_attempts_ip_time` (`ip_address`, `attempted_at`),
  INDEX `idx_attempts_email_time` (`email`, `attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- 8. Table structure for table `system_settings`
-- --------------------------------------------------------
DROP TABLE IF EXISTS `system_settings`;
CREATE TABLE `system_settings` (
  `key_name` VARCHAR(50) PRIMARY KEY,
  `key_value` TEXT NOT NULL,
  `description` VARCHAR(255) DEFAULT NULL,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;

-- ========================================================
-- SEED DATA: Roles, Permissions, and Initial Mappings
-- ========================================================

-- Insert Base Roles
INSERT INTO `roles` (`id`, `name`, `slug`, `description`) VALUES
(1, 'Administrator', 'admin', 'Full system access and security administration privileges'),
(2, 'Editor', 'editor', 'Can view, create and modify resources; no user or administrative controls'),
(3, 'Viewer', 'viewer', 'Read-only access to view authorized resources and dashboard');

-- Insert System Permissions
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

-- Assign Permissions to Administrator (All permissions 1 to 12)
INSERT INTO `role_permissions` (`role_id`, `permission_id`) VALUES
(1, 1),  -- dashboard.view
(1, 2),  -- resources.view
(1, 3),  -- resources.create
(1, 4),  -- resources.update
(1, 5),  -- resources.delete
(1, 6),  -- users.view
(1, 7),  -- users.create
(1, 8),  -- users.update
(1, 9),  -- users.delete
(1, 10), -- roles.manage
(1, 11), -- audit_logs.view
(1, 12); -- settings.manage

-- Assign Permissions to Editor (dashboard.view, resources.view, resources.create, resources.update)
INSERT INTO `role_permissions` (`role_id`, `permission_id`) VALUES
(2, 1),  -- dashboard.view
(2, 2),  -- resources.view
(2, 3),  -- resources.create
(2, 4);  -- resources.update

-- Assign Permissions to Viewer (dashboard.view, resources.view)
INSERT INTO `role_permissions` (`role_id`, `permission_id`) VALUES
(3, 1),  -- dashboard.view
(3, 2);  -- resources.view

-- Seed Default System Settings
INSERT INTO `system_settings` (`key_name`, `key_value`, `description`) VALUES
('app_name', 'CyberSec RBAC Portal', 'Application display title'),
('public_registration', '0', 'Allow self-registration (0=Disabled, 1=Enabled)'),
('max_login_attempts', '5', 'Max failed login attempts before lockout'),
('lockout_duration_minutes', '15', 'Lockout duration in minutes for rate limiting'),
('session_timeout_minutes', '30', 'Session inactivity expiration in minutes');
