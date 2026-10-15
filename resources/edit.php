<?php
/**
 * Resource — Edit
 * Admin & Editor only
 */
define('APP_INIT', true);
$pageTitle = 'Edit Resource';
$activeNav = 'resources';

require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../includes/csrf.php';

requirePermission('resources.update');

$db  = getDB();
$ip  = getClientIP();
$id  = inputInt('id', $_GET);

if (!$id) { setFlash('error', 'Invalid resource ID.'); redirect('/resources/index.php'); }

$resource = $db->prepare("SELECT * FROM resources WHERE id=?");
$resource->execute([$id]);
$resource = $resource->fetch();
if (!$resource) { setFlash('error', 'Resource not found.'); redirect('/resources/index.php'); }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify();

    $title       = inputStr('title');
    $description = trim(strip_tags($_POST['description'] ?? ''));
    $category    = inputStr('category');
    $status      = in_array($_POST['status'] ?? '', ['Published', 'Draft', 'Archived']) ? $_POST['status'] : 'Published';

    $errors = [];
    if (strlen($title) < 3)        $errors[] = 'Title must be at least 3 characters.';
    if (strlen($description) < 10) $errors[] = 'Description must be at least 10 characters.';

    if (empty($errors)) {
        $stmt = $db->prepare(
            "UPDATE resources SET title=?, description=?, category=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?"
        );
        $stmt->execute([$title, $description, $category ?: 'General', $status, $id]);
        logSecurityEvent($user['id'], 'RESOURCE_UPDATED', "'{$user['email']}' updated resource '$title' (ID $id).", $ip);
        setFlash('success', 'Resource updated successfully.');
        redirect('/resources/index.php');
    }
    // Repopulate
    $resource['title']       = $title;
    $resource['description'] = $description;
    $resource['category']    = $category;
    $resource['status']      = $status;
}

$categories = ['Cybersecurity', 'Network', 'Policy', 'Audit', 'General', 'Confidential', 'Technical'];
?>

<div class="row justify-content-center">
    <div class="col-lg-8">
        <div class="card">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-pen-to-square me-2 text-cyan"></i>Edit Resource</span>
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
                <form method="POST" action="edit.php?id=<?= $id ?>">
                    <?= csrfField() ?>
                    <div class="mb-3">
                        <label class="form-label">Resource Title <span class="text-danger">*</span></label>
                        <input type="text" name="title" class="form-control"
                            value="<?= e($resource['title']) ?>" maxlength="200" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Description <span class="text-danger">*</span></label>
                        <textarea name="description" class="form-control" rows="5" required><?= e($resource['description']) ?></textarea>
                    </div>
                    <div class="row g-3 mb-4">
                        <div class="col-md-6">
                            <label class="form-label">Category</label>
                            <select name="category" class="form-select">
                                <?php foreach ($categories as $cat): ?>
                                    <option value="<?= e($cat) ?>" <?= $resource['category'] === $cat ? 'selected' : '' ?>><?= e($cat) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Status</label>
                            <select name="status" class="form-select">
                                <option value="Published" <?= $resource['status'] === 'Published' ? 'selected' : '' ?>>Published</option>
                                <option value="Draft"     <?= $resource['status'] === 'Draft'     ? 'selected' : '' ?>>Draft</option>
                                <option value="Archived"  <?= $resource['status'] === 'Archived'  ? 'selected' : '' ?>>Archived</option>
                            </select>
                        </div>
                    </div>
                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-cyber">
                            <i class="fa-solid fa-floppy-disk me-2"></i>Save Changes
                        </button>
                        <a href="/resources/view.php?id=<?= $id ?>" class="btn btn-outline-secondary">Cancel</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
