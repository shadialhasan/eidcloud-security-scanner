<?php

// Vulnerable Insecure Deserialization Patterns
$serializedData = $_COOKIE['session_token'];
$session = unserialize($serializedData);

$payload = $_POST['object_payload'];
$obj = unserialize($payload);
