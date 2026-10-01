<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Tests;

use EidCloud\SecurityScanner\Analyzer\TaintAnalyzer;
use EidCloud\SecurityScanner\Model\Severity;
use EidCloud\SecurityScanner\Reporter\JsonReporter;
use EidCloud\SecurityScanner\Scanner;

class SecurityScannerTest
{
    private Scanner $scanner;
    private string $fixturesDir;

    public function __construct()
    {
        $this->scanner = new Scanner();
        $this->fixturesDir = dirname(__DIR__) . '/tests/fixtures';
    }

    public function testSqlInjectionDetection(): void
    {
        $result = $this->scanner->scanPath($this->fixturesDir . '/vulnerable_sqli.php');
        $findings = $result->getFindings();

        assert(count($findings) >= 3, 'Expected at least 3 SQLi findings');
        foreach ($findings as $f) {
            assert($f->getRuleId() === 'SEC-SQLI-001', 'Finding rule must be SEC-SQLI-001');
            assert($f->getSeverity() === Severity::CRITICAL, 'SQLi severity must be CRITICAL');
            assert(!empty($f->getTaintFlow()), 'Taint trace must be populated');
            assert($f->getDiffSuggestion() !== null, 'Diff suggestion must be generated');
        }
    }

    public function testXssDetection(): void
    {
        $result = $this->scanner->scanPath($this->fixturesDir . '/vulnerable_xss.php');
        $findings = $result->getFindings();

        assert(count($findings) >= 3, 'Expected at least 3 XSS findings');
        foreach ($findings as $f) {
            assert($f->getRuleId() === 'SEC-XSS-002', 'Finding rule must be SEC-XSS-002');
            assert($f->getSeverity() === Severity::HIGH, 'XSS severity must be HIGH');
            assert(str_contains($f->getRemediation(), 'htmlspecialchars'), 'Remediation must mention htmlspecialchars');
        }
    }

    public function testRceDetection(): void
    {
        $result = $this->scanner->scanPath($this->fixturesDir . '/vulnerable_rce.php');
        $findings = $result->getFindings();

        assert(count($findings) >= 4, 'Expected at least 4 RCE findings (eval, system, exec, backticks)');
        foreach ($findings as $f) {
            assert($f->getRuleId() === 'SEC-RCE-003', 'Finding rule must be SEC-RCE-003');
            assert($f->getSeverity() === Severity::CRITICAL, 'RCE severity must be CRITICAL');
        }
    }

    public function testPathTraversalDetection(): void
    {
        $result = $this->scanner->scanPath($this->fixturesDir . '/vulnerable_path_traversal.php');
        $findings = $result->getFindings();

        assert(count($findings) >= 4, 'Expected at least 4 Path Traversal findings');
        foreach ($findings as $f) {
            assert($f->getRuleId() === 'SEC-PATH-004', 'Finding rule must be SEC-PATH-004');
            assert($f->getSeverity() === Severity::HIGH, 'Path traversal severity must be HIGH');
            assert(str_contains($f->getRemediation(), 'basename'), 'Remediation must recommend basename');
        }
    }

    public function testInsecureDeserializationDetection(): void
    {
        $result = $this->scanner->scanPath($this->fixturesDir . '/vulnerable_deserialization.php');
        $findings = $result->getFindings();

        assert(count($findings) >= 2, 'Expected at least 2 Deserialization findings');
        foreach ($findings as $f) {
            assert($f->getRuleId() === 'SEC-DESER-005', 'Finding rule must be SEC-DESER-005');
            assert($f->getSeverity() === Severity::CRITICAL, 'Deserialization severity must be CRITICAL');
        }
    }

    public function testSsrfDetection(): void
    {
        $result = $this->scanner->scanPath($this->fixturesDir . '/vulnerable_ssrf.php');
        $findings = $result->getFindings();

        assert(count($findings) >= 3, 'Expected at least 3 SSRF findings');
        foreach ($findings as $f) {
            assert($f->getRuleId() === 'SEC-SSRF-006', 'Finding rule must be SEC-SSRF-006');
            assert($f->getSeverity() === Severity::HIGH, 'SSRF severity must be HIGH');
        }
    }

    public function testSafePatternsAvoidFalsePositives(): void
    {
        $result = $this->scanner->scanPath($this->fixturesDir . '/safe_patterns.php');
        $findings = $result->getFindings();

        assert(count($findings) === 0, 'Safe patterns file must produce 0 findings (found: ' . count($findings) . ')');
    }

    public function testMultiHopTaintPropagation(): void
    {
        $code = <<<'PHP'
<?php
$a = $_GET['input'];
$b = $a;
$c = $b;
echo $c;
PHP;
        $findings = $this->scanner->scanCode($code, 'multihop.php');
        assert(count($findings) === 1, 'Multi-hop variable must be flagged as tainted');
        assert($findings[0]->getRuleId() === 'SEC-XSS-002');
        assert(count($findings[0]->getTaintFlow()) >= 3, 'Taint flow must trace the hop chain');
    }

    public function testNumericCastClearsTaint(): void
    {
        $code = <<<'PHP'
<?php
$raw = $_GET['id'];
$clean = (int)$raw;
$pdo->query("SELECT * FROM users WHERE id = " . $clean);
PHP;
        $findings = $this->scanner->scanCode($code, 'cast.php');
        assert(count($findings) === 0, 'Numeric cast must clear taint and prevent false positive');
    }

    public function testHtmlSpecialCharsClearsXss(): void
    {
        $code = <<<'PHP'
<?php
$raw = $_GET['user'];
$safe = htmlspecialchars($raw, ENT_QUOTES, 'UTF-8');
echo $safe;
PHP;
        $findings = $this->scanner->scanCode($code, 'safe_xss.php');
        assert(count($findings) === 0, 'htmlspecialchars must neutralize XSS finding');
    }

    public function testSeverityThresholds(): void
    {
        assert(Severity::CRITICAL->meetsOrExceeds(Severity::HIGH) === true);
        assert(Severity::HIGH->meetsOrExceeds(Severity::CRITICAL) === false);
        assert(Severity::HIGH->meetsOrExceeds(Severity::HIGH) === true);
        assert(Severity::MEDIUM->meetsOrExceeds(Severity::LOW) === true);
        assert(Severity::LOW->meetsOrExceeds(Severity::MEDIUM) === false);
    }

    public function testJsonReporterContract(): void
    {
        $result = $this->scanner->scanPath($this->fixturesDir . '/vulnerable_sqli.php');
        $reporter = new JsonReporter();
        $json = $reporter->render($result);

        $decoded = json_decode($json, true);
        assert(is_array($decoded), 'JSON report must be valid JSON');
        assert(isset($decoded['summary']['files_scanned']));
        assert(isset($decoded['summary']['counts_by_severity']['CRITICAL']));
        assert(isset($decoded['findings'][0]['rule_id']));
        assert(isset($decoded['findings'][0]['diff_suggestion']));
    }

    public function testCliExecution(): void
    {
        $cliPath = dirname(__DIR__) . '/bin/eidcloud-sec';
        $cmd = escapeshellcmd(PHP_BINARY) . ' ' . escapeshellarg($cliPath) . ' --help';
        $output = shell_exec($cmd);
        assert(str_contains((string)$output, 'EidCloud Static Security Scanner'), 'CLI --help output must match banner');
    }
}
