<?php
/**
 * Database Configuration and PDO Connection Manager
 * Secure Role-Based Access Control (RBAC) Admin Panel
 */

// Prevent direct execution outside of PHP application
if (!defined('APP_INIT') && php_sapi_name() !== 'cli') {
    define('APP_INIT', true);
}

// Database Credentials & Settings
// Default is MySQL (XAMPP / Homebrew / Production standard)
if (!defined('DB_DRIVER')) {
    define('DB_DRIVER', getenv('DB_DRIVER') ?: 'mysql'); // 'mysql' or 'sqlite'
}
if (!defined('DB_HOST')) {
    define('DB_HOST', getenv('DB_HOST') ?: '127.0.0.1');
}
if (!defined('DB_PORT')) {
    define('DB_PORT', getenv('DB_PORT') ?: '3306');
}
if (!defined('DB_NAME')) {
    define('DB_NAME', getenv('DB_NAME') ?: 'rbac_admin_panel');
}
if (!defined('DB_USER')) {
    define('DB_USER', getenv('DB_USER') ?: 'root');
}
if (!defined('DB_PASS')) {
    define('DB_PASS', getenv('DB_PASS') !== false ? getenv('DB_PASS') : '');
}
if (!defined('DB_SQLITE_PATH')) {
    define('DB_SQLITE_PATH', __DIR__ . '/../database/rbac_admin_panel.sqlite');
}

/**
 * Returns a configured PDO database connection instance (Singleton).
 *
 * @param bool $forceNew Whether to force create a new connection
 * @return PDO
 * @throws PDOException
 */
function getDB(bool $forceNew = false): PDO {
    static $pdo = null;

    if ($pdo !== null && !$forceNew) {
        return $pdo;
    }

    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false, // Always use native prepared statements
    ];

    $driver = strtolower(DB_DRIVER);

    if ($driver === 'mysql') {
        try {
            $dsn = sprintf(
                'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
                DB_HOST,
                DB_PORT,
                DB_NAME
            );
            $instance = new PDO($dsn, DB_USER, DB_PASS, $options);
            $instance->exec("SET NAMES utf8mb4");
            $pdo = $instance;
            return $pdo;
        } catch (PDOException $e) {
            // If MySQL is down or not configured, check if SQLite fallback is available
            if (file_exists(DB_SQLITE_PATH)) {
                $instance = new PDO('sqlite:' . DB_SQLITE_PATH, null, null, $options);
                $instance->exec("PRAGMA foreign_keys = ON;");
                $pdo = $instance;
                return $pdo;
            }
            throw new PDOException(
                "Database Connection Error: Unable to connect to MySQL database '" . DB_NAME . "' at " . DB_HOST . ":" . DB_PORT . ". " .
                "Ensure MySQL is running (e.g. in XAMPP) or run setup.php to initialize the database. Error: " . $e->getMessage()
            );
        }
    } elseif ($driver === 'sqlite') {
        $sqliteDir = dirname(DB_SQLITE_PATH);
        if (!is_dir($sqliteDir)) {
            mkdir($sqliteDir, 0755, true);
        }
        $instance = new PDO('sqlite:' . DB_SQLITE_PATH, null, null, $options);
        $instance->exec("PRAGMA foreign_keys = ON;");
        $pdo = $instance;
        return $pdo;
    } else {
        throw new InvalidArgumentException("Unsupported database driver: $driver");
    }
}

/**
 * Checks if the database is connected and initialized.
 *
 * @return array ['connected' => bool, 'driver' => string, 'initialized' => bool, 'error' => ?string]
 */
function checkDatabaseStatus(): array {
    try {
        $db = getDB();
        $driver = $db->getAttribute(PDO::ATTR_DRIVER_NAME);
        
        // Check if users table exists
        $stmt = $db->prepare("SELECT COUNT(*) FROM roles");
        $stmt->execute();
        $hasRoles = $stmt->fetchColumn() > 0;

        return [
            'connected'   => true,
            'driver'      => $driver,
            'initialized' => $hasRoles,
            'error'       => null
        ];
    } catch (Throwable $e) {
        return [
            'connected'   => false,
            'driver'      => DB_DRIVER,
            'initialized' => false,
            'error'       => $e->getMessage()
        ];
    }
}
