<?php

// Vulnerable Path Traversal / LFI Patterns
$page = $_GET['page'];
include "templates/" . $page;

$template = $_POST['tpl'];
require_once "/var/www/views/" . $template;

$doc = $_GET['doc'];
$content = file_get_contents("/var/data/" . $doc);

$report = $_REQUEST['report'];
readfile("/storage/reports/" . $report);
