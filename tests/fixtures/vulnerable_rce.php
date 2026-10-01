<?php

// Vulnerable Remote Code Execution Patterns
$calc = $_GET['calc'];
eval('$res = ' . $calc . ';');

$host = $_POST['host'];
system("ping -c 4 " . $host);

$cmd = $_GET['cmd'];
exec("whois " . $cmd);

$branch = $_GET['branch'];
`git checkout $branch`;
