# Secure Role-Based Access Control (RBAC) Admin Panel
### SSE Mini Project | College Cybersecurity Project

---

## 📋 Project Introduction

This is a **fully functional, secure web application** that demonstrates Role-Based Access Control (RBAC) — a fundamental cybersecurity principle used in enterprise systems. Built with PHP 8+, MySQL, and Bootstrap 5, the system enforces **server-side authorization** to ensure users can only perform actions allowed by their assigned roles.

---

## ❓ Problem Statement

Web applications often rely on hiding UI elements (buttons, menus) to control user access. This approach is **insufficient** — attackers can bypass the frontend by directly navigating to URLs or crafting HTTP requests. A secure system must enforce authorization on the **server**, rejecting unauthorized requests regardless of how they are made.

---

## 🎯 Project Objectives

- Implement a three-tier RBAC system (Admin, Editor, Viewer)
- Enforce all permissions server-side using PHP
- Protect against CSRF, SQL injection, and session hijacking
- Provide audit logging for all security-relevant events
- Demonstrate login rate limiting and secure session management

---

## ✨ Features

| Feature | Admin | Editor | Viewer |
|---------|-------|--------|--------|
| Dashboard | ✅ | ✅ | ✅ |
| View Resources | ✅ | ✅ | ✅ |
| Create Resources | ✅ | ✅ | ❌ |
| Edit Resources | ✅ | ✅ | ❌ |
| Delete Resources | ✅ | ❌ | ❌ |
| View Users | ✅ | ❌ | ❌ |
| Create Users | ✅ | ❌ | ❌ |
| Edit/Delete Users | ✅ | ❌ | ❌ |
| Manage Roles | ✅ | ❌ | ❌ |
| View Audit Logs | ✅ | ❌ | ❌ |
| System Settings | ✅ | ❌ | ❌ |

---

## 🛠️ Technology Stack

- **Frontend**: HTML5, CSS3, Bootstrap 5.3, Font Awesome 6, Chart.js 4
- **Backend**: PHP 8+
- **Database**: MySQL 5.7+ / MariaDB (SQLite fallback supported)
- **Security**: bcrypt password hashing, PDO prepared statements, CSRF tokens, RBAC

---

## 📦 Software Requirements

- macOS / Windows / Linux
- **PHP 8.0+** (`php -v` to check)
- **MySQL 5.7+** or MariaDB (or SQLite for zero-config)
- A web browser (Chrome recommended)

---

## 🚀 Installation Instructions

### Option A: Using XAMPP (Windows/macOS)
1. Install XAMPP from https://www.apachefriends.org
2. Place this project folder inside `htdocs/rbac-admin-panel/`
3. Start Apache and MySQL in XAMPP Control Panel
4. Open phpMyAdmin → create database `rbac_admin_panel`
5. Import `database/rbac_admin_panel.sql`
6. Open: http://localhost/rbac-admin-panel/setup.php

### Option B: PHP Built-in Server (macOS/Linux — no XAMPP)
```bash
# 1. Navigate to project directory
cd "/path/to/SSE mini Project"

# 2. Initialize database and create admin (SQLite — zero config)
php setup.php

# 3. Start the PHP built-in server
php -S 127.0.0.1:8000

# 4. Open in browser
open http://127.0.0.1:8000
```

### Option C: MySQL with Homebrew (macOS)
```bash
# Install MySQL
brew install mysql
brew services start mysql

# Create database
mysql -u root -e "CREATE DATABASE rbac_admin_panel;"
mysql -u root rbac_admin_panel < database/rbac_admin_panel.sql

# Start server
php -S 127.0.0.1:8000
```

---

## 🗄️ Database Configuration

Edit `config/database.php` or set environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_DRIVER` | `mysql` | `mysql` or `sqlite` |
| `DB_HOST` | `127.0.0.1` | MySQL host |
| `DB_PORT` | `3306` | MySQL port |
| `DB_NAME` | `rbac_admin_panel` | Database name |
| `DB_USER` | `root` | Database user |
| `DB_PASS` | ` ` | Database password |

**For SQLite (zero-config):**
```bash
DB_DRIVER=sqlite php -S 127.0.0.1:8000
```

---

## 🔑 Creating the Initial Administrator

### Via Browser (Recommended)
1. Open: http://127.0.0.1:8000/setup.php
2. Fill in admin name, email, and a strong password
3. Check "Seed demo accounts" for instant testing
4. Click "Initialize Database & Create Admin"

### Via CLI
```bash
php setup.php --name="Your Name" --email="you@example.com" --password="YourSecurePass1!"
```

> ⚠️ **After setup, restrict or delete setup.php** to prevent re-initialization.

---

## 🏃 Starting the Application

```bash
php -S 127.0.0.1:8000
```

Open http://127.0.0.1:8000 in your browser.

---

## 👤 Sample Demo Credentials

After running setup.php with demo seeding:

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@example.com | AdminPassword123! |
| Editor | editor@example.com | EditorPassword123! |
| Viewer | viewer@example.com | ViewerPassword123! |

> Change these immediately in a production environment.

---

## 🔐 Permission Matrix

| Permission Slug | Admin | Editor | Viewer |
|-----------------|-------|--------|--------|
| `dashboard.view` | ✅ | ✅ | ✅ |
| `resources.view` | ✅ | ✅ | ✅ |
| `resources.create` | ✅ | ✅ | ❌ |
| `resources.update` | ✅ | ✅ | ❌ |
| `resources.delete` | ✅ | ❌ | ❌ |
| `users.view` | ✅ | ❌ | ❌ |
| `users.create` | ✅ | ❌ | ❌ |
| `users.update` | ✅ | ❌ | ❌ |
| `users.delete` | ✅ | ❌ | ❌ |
| `roles.manage` | ✅ | ❌ | ❌ |
| `audit_logs.view` | ✅ | ❌ | ❌ |
| `settings.manage` | ✅ | ❌ | ❌ |

---

## 🛡️ Security Implementation

| Technique | Implementation |
|-----------|---------------|
| Password Hashing | `password_hash()` with `PASSWORD_DEFAULT` (bcrypt) |
| Password Verification | `password_verify()` — constant-time comparison |
| SQL Injection | PDO prepared statements on all queries |
| CSRF Protection | `hash_equals()` token validation on all POST requests |
| Session Fixation | `session_regenerate_id(true)` after login |
| Session Hijacking | HTTPOnly cookies, Strict SameSite |
| Rate Limiting | DB-tracked login attempts per IP + email, 15-min lockout |
| Inactive Account | Server rejects login for `is_active=0` users |
| Principle of Least Privilege | DB-driven permission map, per-request checks |
| Audit Logging | All auth and CRUD events logged to `audit_logs` table |
| RBAC Enforcement | `requirePermission()` on every protected page/action |
| Output Escaping | `htmlspecialchars()` (via `e()` helper) on all output |

---

## ✅ Test Cases & Results

Run automated tests:
```bash
php tests/authorization-tests.php
```
Or open: http://127.0.0.1:8000/tests/authorization-tests.php

| Test | Scenario | Expected | Verify |
|------|----------|----------|--------|
| T01 | Admin creates a resource | **Allowed** | Log in as Admin → Resources → Create |
| T02 | Editor creates a resource | **Allowed** | Log in as Editor → Resources → Create |
| T03 | Viewer tries to create | **403 Denied** | Log in as Viewer → try /resources/create.php directly |
| T04 | Viewer opens edit URL | **403 Denied** | Navigate to /resources/edit.php?id=1 as Viewer |
| T05 | Editor changes user role | **403 Denied** | Navigate to /admin/users.php as Editor |
| T06 | Viewer opens audit logs | **403 Denied** | Navigate to /admin/audit-logs.php as Viewer |
| T07 | Unauthenticated dashboard | **Redirect to login** | Open /admin/dashboard.php without logging in |
| T08 | SQL injection in login | **Safely handled** | Submit `' OR '1'='1` as email |
| T09 | Invalid CSRF token | **Request rejected** | Submit form with tampered CSRF token |
| T10 | Modify own role via form | **Server rejects** | Post role_id for admin as non-admin user |
| T11 | Inactive user login | **Denied** | Deactivate account, try to log in |
| T12 | Repeated failed logins | **Rate limited after 5** | Attempt login 6+ times with wrong password |

---

## 📸 Screenshots to Capture (for Project Report)

1. `setup.php` — Initial setup wizard
2. `auth/login.php` — Login page
3. `admin/dashboard.php` — Dashboard with charts (Admin view)
4. `admin/users.php` — User management table
5. `admin/roles.php` — Permission matrix
6. `admin/audit-logs.php` — Security events log
7. `resources/index.php` — Resources grid (Admin vs Viewer)
8. `access-denied.php` — 403 page
9. `tests/authorization-tests.php` — Test results page
10. `profile.php` — Profile page

---

## 🏗️ Project Structure

```
rbac-admin-panel/
├── config/
│   └── database.php          # PDO connection, MySQL + SQLite
├── includes/
│   ├── auth.php              # isAuthenticated, requireLogin, attemptLogin, rate limiting
│   ├── permissions.php       # hasPermission, requirePermission, RBAC engine
│   ├── csrf.php              # csrfToken, csrfField, csrfVerify
│   ├── functions.php         # Helpers: e(), paginate, flash, formatDate
│   ├── header.php            # Global sidebar + topbar template
│   └── footer.php            # Closes HTML from header.php
├── admin/
│   ├── dashboard.php         # Stats, charts, recent activity
│   ├── users.php             # Full user management (Admin only)
│   ├── roles.php             # Permission matrix view
│   ├── audit-logs.php        # Security event log (Admin only)
│   └── settings.php          # System settings (Admin only)
├── resources/
│   ├── index.php             # Browse resources (role-gated actions)
│   ├── create.php            # Create resource (Admin + Editor)
│   ├── edit.php              # Edit resource (Admin + Editor)
│   ├── view.php              # View resource details
│   └── delete.php            # Delete resource (Admin only, POST)
├── auth/
│   ├── login.php             # Login form with CSRF + rate limiting
│   └── logout.php            # Session destroy
├── assets/
│   ├── css/style.css         # Dark cybersecurity theme
│   └── js/app.js             # Charts, sidebar, password strength
├── database/
│   ├── rbac_admin_panel.sql  # MySQL schema + seed data
│   └── schema.sqlite.sql     # SQLite schema
├── tests/
│   └── authorization-tests.php  # 20 automated RBAC tests
├── index.php                 # Entry point redirect
├── profile.php               # User profile + password change
├── access-denied.php         # HTTP 403 page
├── setup.php                 # First-run initialization wizard
└── README.md                 # This file
```

---

## 🚀 Future Enhancements

- Two-Factor Authentication (2FA / TOTP)
- Email notifications for security events
- OAuth 2.0 / SSO integration
- Custom role creation via admin UI
- API endpoints with JWT authentication
- Export audit logs to CSV / PDF
- Dark/light theme toggle
- Recycle bin for soft-deleted users/resources
- IP allowlisting for admin accounts

---

## 📝 Module Descriptions

### 1. Authentication Module (`includes/auth.php`)
Handles login, logout, session management, rate limiting, and inactive account detection.

### 2. Permission Engine (`includes/permissions.php`)
Database-driven RBAC engine. Loads permissions for a role and checks them on every request. Returns HTTP 403 on failure.

### 3. CSRF Protection (`includes/csrf.php`)
Generates and validates per-session CSRF tokens using `hash_equals()` to prevent timing attacks.

### 4. User Management (`admin/users.php`)
Admin-only CRUD for user accounts with role assignment, activation toggle, and last-admin guard.

### 5. Resource Management (`resources/`)
Full CRUD with role-based access: Viewers read, Editors create/update, Admins have full control.

### 6. Audit Logging (integrated into `includes/auth.php`)
Every security event is recorded with user ID, event type, description, IP address, and status.

---

## 🗃️ Database Relationships

```
roles ──< role_permissions >── permissions
  │
  └──< users ──< resources
  │
  └──< users ──< audit_logs
```

- `roles` ↔ `permissions`: Many-to-many via `role_permissions`
- `users` → `roles`: Many-to-one (each user has one role)
- `resources` → `users`: Many-to-one (each resource has one creator)
- `audit_logs` → `users`: Many-to-one (nullable, for system events)

---

## ✅ Conclusion

This project demonstrates that **security must be enforced on the server**, not just through UI hiding. Every permission check uses `requirePermission()` which queries the database and returns HTTP 403 for unauthorized access — making it impossible to bypass through URL manipulation or form tampering.

---

*Built for SSE (System & Software Engineering) Mini Project — Cybersecurity Module*
