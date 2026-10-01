<?php

// Vulnerable SSRF Patterns
$targetUrl = $_GET['webhook_url'];
$ch = curl_init($targetUrl);
curl_exec($ch);

$remoteEndpoint = $_POST['endpoint'];
$client = curl_init();
curl_setopt($client, CURLOPT_URL, $remoteEndpoint);

$feed = $_GET['rss_feed'];
$data = file_get_contents("http://" . $feed);
