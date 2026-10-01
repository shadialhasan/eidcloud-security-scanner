<?php

declare(strict_types=1);

// Zero-dependency test runner for PHP 8.2+
// Requires no PHPUnit, Composer, or third-party packages.

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/SecurityScannerTest.php';

use EidCloud\SecurityScanner\Tests\SecurityScannerTest;

$testSuite = new SecurityScannerTest();
$methods = get_class_methods($testSuite);

$testMethods = array_filter($methods, fn(string $m) => str_starts_with($m, 'test'));

echo "\033[1;36m====================================================================\033[0m\n";
echo "\033[1;37m   EIDCLOUD SECURITY SCANNER - AUTOMATED ZERO-DEPENDENCY TEST SUITE \033[0m\n";
echo "\033[1;36m====================================================================\033[0m\n";
echo sprintf("PHP Version: %s | Total Tests: %d\n\n", PHP_VERSION, count($testMethods));

$passed = 0;
$failed = 0;
$startTime = microtime(true);

foreach ($testMethods as $method) {
    $testStart = microtime(true);
    try {
        $testSuite->$method();
        $elapsed = (microtime(true) - $testStart) * 1000;
        echo sprintf("  \033[1;32m[PASS]\033[0m %-42s \033[0;90m(%.2f ms)\033[0m\n", $method, $elapsed);
        $passed++;
    } catch (\Throwable $e) {
        $elapsed = (microtime(true) - $testStart) * 1000;
        echo sprintf("  \033[1;31m[FAIL]\033[0m %-42s \033[0;90m(%.2f ms)\033[0m\n", $method, $elapsed);
        echo sprintf("         \033[0;31mError: %s\033[0m\n", $e->getMessage());
        echo sprintf("         \033[0;90mFile: %s:%d\033[0m\n", $e->getFile(), $e->getLine());
        $failed++;
    }
}

$totalTime = (microtime(true) - $startTime) * 1000;

echo "\n\033[1;36m--------------------------------------------------------------------\033[0m\n";
if ($failed === 0) {
    echo sprintf("\033[1;32m   TEST SUITE RESULT: 100%% PASSED (%d/%d tests in %.2f ms)\033[0m\n", $passed, count($testMethods), $totalTime);
    echo "\033[1;36m====================================================================\033[0m\n\n";
    exit(0);
} else {
    echo sprintf("\033[1;31m   TEST SUITE RESULT: FAILED (%d failed, %d passed in %.2f ms)\033[0m\n", $failed, $passed, $totalTime);
    echo "\033[1;36m====================================================================\033[0m\n\n";
    exit(1);
}
