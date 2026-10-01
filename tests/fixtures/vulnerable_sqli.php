<?php

// Vulnerable SQL Injection Patterns
$userId = $_GET['id'];
$rawQuery = "SELECT * FROM users WHERE id = " . $userId;

// Raw mysql_query sink
mysql_query($rawQuery);

// Raw PDO query sink
$pdo = new PDO('mysql:host=localhost;dbname=test', 'user', 'pass');
$pdo->query("SELECT * FROM accounts WHERE user_id = " . $_GET['acc']);

// Double-quoted interpolation
$status = $_POST['status'];
$pdo->exec("UPDATE orders SET status = '$status'");
