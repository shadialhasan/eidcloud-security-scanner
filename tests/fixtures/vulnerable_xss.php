<?php

// Vulnerable XSS Patterns
$name = $_GET['name'];
echo "Hello, " . $name;

$bio = $_POST['bio'];
print $bio;

printf("User profile: %s", $_REQUEST['profile']);
