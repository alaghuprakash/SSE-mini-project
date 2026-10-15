<?php
/**
 * Resource — Create
 * Admin & Editor only
 */
define('APP_INIT', true);
$pageTitle = 'Create Resource';
$activeNav = 'resources';

require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../includes/csrf.php';

requirePermission('resources.create');

$db = getDB();
$ip = getClientIP();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify();

    $title       = inputStr('title');
    $description = trim(strip_tags($_POST['description'] ?? ''));
    $category    = inputStr('category');
    $status      = in_array($_POST['status'] ?? '', ['Published', 'Draft', 'Archived']) ? $_POST['status'] : 'Published';

    $errors = [];
    if (strlen($title) < 3)       $errors[] = 'Title must be at least 3 characters.';
    if (strlen($description) < 10) $errors[] = 'Description must be at least 10 characters.';
    if (strlen($title) > 200)     $errors[] = 'Title must not exceed 200 characters.';

    if (empty($errors)) {
        $stmt = $db->prepare(
            "INSERT INTO resources (title, description, category, status, created_by, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        );
        $stmt->execute([$title, $description, $category ?: 'General', $status, $user['id']]);
        $newId = $db->lastInsertId();
        logSecurityEvent($user['id'], 'RESOURCE_CREATED', "'{$user['email']}' created resource '$title' (ID $newId).", $ip);
        setFlash('success', "Resource \"$title\" created successfully.");
        redirect('/resources/index.php');
    }
}
$categories = ['Cybersecurity', 'Network', 'Policy', 'Audit', 'General', 'Confidential', 'Technical'];
?>

<div class="row justify-content-center">
    <div class="col-lg-8">
        <div class="card">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-file-circle-plus me-2 text-cyan"></i>Create New Resource</span>
                <a href="/resources/index.php" class="btn btn-outline-secondary btn-sm">
                    <i class="fa-solid fa-arrow-left me-1"></i>Back
                </a>
            </div>
            <div class="card-body">
                <?php if (!empty($errors)): ?>
                    <div class="alert alert-danger mb-3">
                        <ul class="mb-0 ps-3">
                            <?php foreach ($errors as $e): ?><li><?= e($e) ?></li><?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
                <form method="POST" action="create.php">
                    <?= csrfField() ?>
                    <div class="mb-3">
                        <label class="form-label">Resource Title <span class="text-danger">*</span></label>
                        <input type="text" name="title" class="form-control"
                            value="<?= e($_POST['title'] ?? '') ?>"
                            placeholder="e.g. Network Security Policy" maxlength="200" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Description <span class="text-danger">*</span></label>
                        <textarea name="description" class="form-control" rows="5"
                            placeholder="Describe the resource contents, purpose, and access requirements…" required><?= e($_POST['description'] ?? '') ?></textarea>
                    </div>
                    <div class="row g-3 mb-4">
                        <div class="col-md-6">
                            <label class="form-label">Category</label>
                            <select name="category" class="form-select">
                                <?php foreach ($categories as $cat): ?>
                                    <option value="<?= e($cat) ?>" <?= ($_POST['category'] ?? 'General') === $cat ? 'selected' : '' ?>><?= e($cat) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Status</label>
                            <select name="status" class="form-select">
                                <option value="Published" <?= ($_POST['status'] ?? 'Published') === 'Published' ? 'selected' : '' ?>>Published</option>
                                <option value="Draft" <?= ($_POST['status'] ?? '') === 'Draft' ? 'selected' : '' ?>>Draft</option>
                                <option value="Archived" <?= ($_POST['status'] ?? '') === 'Archived' ? 'selected' : '' ?>>Archived</option>
                            </select>
                        </div>
                    </div>
                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-cyber">
                            <i class="fa-solid fa-floppy-disk me-2"></i>Create Resource
                        </button>
                        <a href="/resources/index.php" class="btn btn-outline-secondary">Cancel</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
