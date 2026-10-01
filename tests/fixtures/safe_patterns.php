<?php

// 1. Safe SQL: Prepared statements
$userId = (int)$_GET['id'];
$pdo = new PDO('mysql:host=localhost;dbname=test', 'user', 'pass');
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $userId]);
$user = $stmt->fetch();

// 2. Safe XSS: Escaped output
$rawName = $_GET['name'];
$safeName = htmlspecialchars($rawName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
echo $safeName;

// 3. Safe RCE: Numeric or escaped args
$port = (int)$_GET['port'];
$safeArg = escapeshellarg($_POST['domain']);
system('nc -zv localhost ' . $port);

// 4. Safe Path Traversal: Basename sanitization
$requestedFile = basename($_GET['file']);
$fullPath = '/var/www/uploads/' . $requestedFile;
if (file_exists($fullPath)) {
    readfile($fullPath);
}

// 5. Safe Deserialization: JSON decode
$token = $_POST['token'];
$sessionData = json_decode($token, true);

// 6. Safe Deserialization: allowed_classes => false
$safeDeserialized = unserialize($token, ['allowed_classes' => false]);
