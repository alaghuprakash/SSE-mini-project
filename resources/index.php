<?php
/**
 * Resources — List / Browse
 * Admin: full CRUD | Editor: create, read, update | Viewer: read only
 */
define('APP_INIT', true);
$pageTitle = 'Resources';
$activeNav = 'resources';

require_once __DIR__ . '/../includes/header.php';

requirePermission('resources.view');

$db = getDB();

// Filters
$search   = inputStr('q', $_GET);
$category = inputStr('cat', $_GET);
$page     = max(1, (int)($_GET['page'] ?? 1));

$where  = ['1=1'];
$params = [];
if ($search) {
    $where[]  = '(r.title LIKE ? OR r.description LIKE ?)';
    $params[] = "%$search%";
    $params[] = "%$search%";
}
if ($category) {
    $where[]  = 'r.category = ?';
    $params[] = $category;
}
$whereStr = implode(' AND ', $where);

$countSql = "SELECT COUNT(*) FROM resources r WHERE $whereStr";
$dataSql  = "SELECT r.*, u.name AS creator_name
             FROM resources r LEFT JOIN users u ON r.created_by = u.id
             WHERE $whereStr ORDER BY r.created_at DESC";

$paged     = paginate($db, $countSql, $dataSql, $params, $page, 10);
$resources = $paged['data'];
$categories= $db->query("SELECT DISTINCT category FROM resources WHERE category IS NOT NULL ORDER BY category")->fetchAll(PDO::FETCH_COLUMN);
?>

<div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
    <p class="text-muted mb-0" style="font-size:0.85rem;"><?= $paged['total'] ?> resource<?= $paged['total'] !== 1 ? 's' : '' ?></p>
    <?php if (hasPermission('resources.create')): ?>
    <a href="/resources/create.php" class="btn btn-cyber btn-sm">
        <i class="fa-solid fa-plus me-1"></i>New Resource
    </a>
    <?php endif; ?>
</div>

<!-- Filters -->
<form method="GET" action="index.php" data-autosearch class="mb-3">
    <div class="d-flex flex-wrap gap-2">
        <div class="input-group" style="max-width:320px;">
            <span class="input-group-text" style="background:rgba(7,12,27,0.8);border-color:var(--border-color);color:var(--text-muted);">
                <i class="fa-solid fa-magnifying-glass fa-sm"></i>
            </span>
            <input type="search" name="q" class="form-control" placeholder="Search resources…" value="<?= e($search) ?>">
        </div>
        <?php if ($categories): ?>
        <select name="cat" class="form-select" style="max-width:180px;">
            <option value="">All Categories</option>
            <?php foreach ($categories as $cat): ?>
                <option value="<?= e($cat) ?>" <?= $category === $cat ? 'selected' : '' ?>><?= e($cat) ?></option>
            <?php endforeach; ?>
        </select>
        <?php endif; ?>
        <button type="submit" class="btn btn-outline-cyber btn-sm">Filter</button>
        <?php if ($search || $category): ?>
            <a href="index.php" class="btn btn-outline-secondary btn-sm">Clear</a>
        <?php endif; ?>
    </div>
</form>

<!-- Resource Cards -->
<?php if (empty($resources)): ?>
<div class="card">
    <div class="empty-state py-5">
        <i class="fa-solid fa-folder-open d-block mb-3" style="font-size:2.5rem;opacity:0.3;"></i>
        <p>No resources found<?= $search ? " for \"$search\"" : '' ?>.</p>
        <?php if (hasPermission('resources.create')): ?>
            <a href="/resources/create.php" class="btn btn-outline-cyber btn-sm mt-2">Create First Resource</a>
        <?php endif; ?>
    </div>
</div>
<?php else: ?>
<div class="row g-3 mb-3">
<?php foreach ($resources as $res): ?>
    <div class="col-md-6 col-xl-4">
        <div class="card h-100 stat-card" style="cursor:pointer;" onclick="window.location='/resources/view.php?id=<?= $res['id'] ?>'">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <span class="badge" style="background:rgba(79,172,254,0.15);color:#93c5fd;border:1px solid rgba(79,172,254,0.3);font-size:0.7rem;">
                        <?= e($res['category'] ?? 'General') ?>
                    </span>
                    <span class="badge <?= $res['status'] === 'Published' ? 'bg-success' : 'bg-secondary' ?> bg-opacity-25" style="font-size:0.7rem;">
                        <?= e($res['status']) ?>
                    </span>
                </div>
                <h6 class="text-white mb-1" style="font-size:0.9rem;font-weight:600;"><?= e($res['title']) ?></h6>
                <p class="text-muted mb-3" style="font-size:0.8rem;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;">
                    <?= e($res['description']) ?>
                </p>
                <div class="d-flex align-items-center justify-content-between mt-auto">
                    <div style="font-size:0.73rem;color:var(--text-muted);">
                        <i class="fa-solid fa-user me-1"></i><?= e($res['creator_name'] ?? 'Unknown') ?>
                    </div>
                    <div class="d-flex gap-1">
                        <a href="/resources/view.php?id=<?= $res['id'] ?>" class="btn btn-outline-secondary btn-sm" title="View" onclick="event.stopPropagation()">
                            <i class="fa-solid fa-eye fa-sm"></i>
                        </a>
                        <?php if (hasPermission('resources.update')): ?>
                        <a href="/resources/edit.php?id=<?= $res['id'] ?>" class="btn btn-outline-secondary btn-sm" title="Edit" onclick="event.stopPropagation()">
                            <i class="fa-solid fa-pen fa-sm"></i>
                        </a>
                        <?php endif; ?>
                        <?php if (hasPermission('resources.delete')): ?>
                        <form method="POST" action="/resources/delete.php" class="d-inline" onclick="event.stopPropagation()">
                            <?= csrfField() ?>
                            <input type="hidden" name="resource_id" value="<?= $res['id'] ?>">
                            <button type="submit" class="btn btn-outline-secondary btn-sm text-danger"
                                data-confirm="Delete '<?= e($res['title']) ?>'? This is permanent.">
                                <i class="fa-solid fa-trash fa-sm"></i>
                            </button>
                        </form>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
<?php endforeach; ?>
</div>

<?php if ($paged['totalPages'] > 1): ?>
<div class="d-flex justify-content-between align-items-center">
    <small class="text-muted">Page <?= $paged['page'] ?> of <?= $paged['totalPages'] ?></small>
    <?= renderPagination($paged, 'index.php?q='.urlencode($search).'&cat='.urlencode($category)) ?>
</div>
<?php endif; ?>

<?php endif; ?>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
