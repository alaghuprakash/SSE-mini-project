<?php
/**
 * Resource — View (Read-only detail page)
 */
define('APP_INIT', true);
$pageTitle = 'View Resource';
$activeNav = 'resources';

require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../includes/csrf.php';

requirePermission('resources.view');

$db = getDB();
$id = inputInt('id', $_GET);

if (!$id) { setFlash('error', 'Invalid resource.'); redirect('/resources/index.php'); }

$stmt = $db->prepare(
    "SELECT r.*, u.name AS creator_name, u.email AS creator_email
     FROM resources r LEFT JOIN users u ON r.created_by = u.id
     WHERE r.id = ?"
);
$stmt->execute([$id]);
$res = $stmt->fetch();

if (!$res) { setFlash('error', 'Resource not found.'); redirect('/resources/index.php'); }
$pageTitle = e($res['title']);
?>

<div class="row justify-content-center">
    <div class="col-lg-9">
        <div class="card">
            <div class="card-header">
                <span class="card-title"><i class="fa-solid fa-file-lines me-2 text-cyan"></i>Resource Details</span>
                <div class="d-flex gap-2">
                    <?php if (hasPermission('resources.update')): ?>
                    <a href="/resources/edit.php?id=<?= $res['id'] ?>" class="btn btn-outline-cyber btn-sm">
                        <i class="fa-solid fa-pen me-1"></i>Edit
                    </a>
                    <?php endif; ?>
                    <?php if (hasPermission('resources.delete')): ?>
                    <form method="POST" action="/resources/delete.php" class="d-inline">
                        <?= csrfField() ?>
                        <input type="hidden" name="resource_id" value="<?= $res['id'] ?>">
                        <button type="submit" class="btn btn-sm btn-outline-secondary text-danger"
                            data-confirm="Permanently delete '<?= e($res['title']) ?>'?">
                            <i class="fa-solid fa-trash me-1"></i>Delete
                        </button>
                    </form>
                    <?php endif; ?>
                    <a href="/resources/index.php" class="btn btn-outline-secondary btn-sm">
                        <i class="fa-solid fa-arrow-left me-1"></i>Back
                    </a>
                </div>
            </div>
            <div class="card-body">
                <!-- Metadata row -->
                <div class="d-flex flex-wrap gap-2 mb-4">
                    <span class="badge" style="background:rgba(79,172,254,0.15);color:#93c5fd;border:1px solid rgba(79,172,254,0.3);">
                        <i class="fa-solid fa-tag me-1"></i><?= e($res['category'] ?? 'General') ?>
                    </span>
                    <span class="badge <?= $res['status'] === 'Published' ? 'bg-success' : 'bg-secondary' ?> bg-opacity-25">
                        <?= e($res['status']) ?>
                    </span>
                    <span class="text-muted" style="font-size:0.8rem;">
                        <i class="fa-solid fa-hashtag me-1"></i>ID: <?= $res['id'] ?>
                    </span>
                </div>

                <h2 class="h5 text-white mb-3"><?= e($res['title']) ?></h2>

                <div class="p-3 rounded mb-4" style="background:rgba(255,255,255,0.02);border:1px solid var(--border-color);white-space:pre-wrap;font-size:0.875rem;line-height:1.8;color:var(--text-secondary);">
                    <?= e($res['description']) ?>
                </div>

                <dl class="row" style="font-size:0.82rem;">
                    <dt class="col-sm-3 text-muted">Created By</dt>
                    <dd class="col-sm-9"><?= e($res['creator_name'] ?? 'Unknown') ?> <span class="text-muted">&lt;<?= e($res['creator_email'] ?? '') ?>&gt;</span></dd>

                    <dt class="col-sm-3 text-muted">Created At</dt>
                    <dd class="col-sm-9"><?= formatDate($res['created_at']) ?></dd>

                    <dt class="col-sm-3 text-muted">Last Updated</dt>
                    <dd class="col-sm-9"><?= formatDate($res['updated_at']) ?></dd>
                </dl>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
