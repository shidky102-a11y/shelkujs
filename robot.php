<?php
/**
 * koiplatform LP Deploy Robot
 *
 * Upload file ini ke ROOT website target, contoh:
 *   https://www.femave.com/robot.php
 *
 * Setelah generate LP di koiplatform, robot akan:
 * 1) buat folder dari path canonical (mis. /multimedia/)
 * 2) tulis index.php berisi HTML LP
 *
 * Keamanan: wajib token yang sama dengan pengaturan Template LP.
 */
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

const ROBOT_TOKEN = '2LfqaKvdsE4kPcrHQv1un17tSTat2GecbAJXMXUS';
const MAX_BYTES = 5242880; // 5MB

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Method not allowed']);
    exit;
}

$raw = file_get_contents('php://input') ?: '';
$data = json_decode($raw, true);
if (! is_array($data)) {
    $data = $_POST;
}

$token = (string) ($data['token'] ?? ($_SERVER['HTTP_X_ROBOT_TOKEN'] ?? ''));
if ($token === '' || ! hash_equals(ROBOT_TOKEN, $token)) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'error' => 'Invalid token']);
    exit;
}

$action = (string) ($data['action'] ?? 'deploy');
if ($action === 'ping') {
    echo json_encode(['ok' => true, 'message' => 'robot ready']);
    exit;
}

$path = (string) ($data['path'] ?? '');
$path = trim(str_replace('\\', '/', $path), '/');
$contentB64 = (string) ($data['content_base64'] ?? '');
$filename = (string) ($data['filename'] ?? 'index.php');

if ($path === '' || str_contains($path, '..') || preg_match('#^[a-zA-Z0-9._/-]+$#', $path) !== 1) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'Invalid path']);
    exit;
}

if ($filename === '' || str_contains($filename, '/') || str_contains($filename, '\\') || str_contains($filename, '..')) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'Invalid filename']);
    exit;
}

if ($contentB64 === '') {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'Missing content']);
    exit;
}

$content = base64_decode($contentB64, true);
if ($content === false) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'Invalid base64 content']);
    exit;
}

if (strlen($content) > MAX_BYTES) {
    http_response_code(413);
    echo json_encode(['ok' => false, 'error' => 'Content too large']);
    exit;
}

$root = realpath(__DIR__);
if ($root === false) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Cannot resolve root']);
    exit;
}

$targetDir = $root.DIRECTORY_SEPARATOR.str_replace('/', DIRECTORY_SEPARATOR, $path);
if (! is_dir($targetDir) && ! mkdir($targetDir, 0755, true) && ! is_dir($targetDir)) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Failed to create directory']);
    exit;
}

$realDir = realpath($targetDir);
if ($realDir === false || ! str_starts_with($realDir, $root)) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Path escape blocked']);
    exit;
}

$targetFile = $realDir.DIRECTORY_SEPARATOR.$filename;
if (file_put_contents($targetFile, $content) === false) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Failed to write file']);
    exit;
}

@chmod($targetFile, 0644);

echo json_encode([
    'ok' => true,
    'path' => $path.'/'.$filename,
    'bytes' => strlen($content),
]);
