<?php
/**
 * Resource — Delete (POST only)
 * Admin only
 */
define('APP_INIT', true);
require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../includes/csrf.php';

// Only POST allowed
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('/resources/index.php');
}

requirePermission('resources.delete');
csrfVerify();

$db  = getDB();
$ip  = getClientIP();
$id  = inputInt('resource_id');

if (!$id) { setFlash('error', 'Invalid resource ID.'); redirect('/resources/index.php'); }

$stmt = $db->prepare("SELECT title FROM resources WHERE id=?");
$stmt->execute([$id]);
$res = $stmt->fetch();

if (!$res) { setFlash('error', 'Resource not found.'); redirect('/resources/index.php'); }

$db->prepare("DELETE FROM resources WHERE id=?")->execute([$id]);
logSecurityEvent($user['id'], 'RESOURCE_DELETED', "'{$user['email']}' deleted resource '{$res['title']}' (ID $id).", $ip, 'WARNING');
setFlash('success', "Resource \"{$res['title']}\" deleted.");
redirect('/resources/index.php');
