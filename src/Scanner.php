<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner;

use EidCloud\SecurityScanner\Analyzer\TaintAnalyzer;
use EidCloud\SecurityScanner\Model\Finding;
use EidCloud\SecurityScanner\Model\ScanResult;
use EidCloud\SecurityScanner\Model\Severity;
use EidCloud\SecurityScanner\Rules\InsecureDeserializationRule;
use EidCloud\SecurityScanner\Rules\PathTraversalRule;
use EidCloud\SecurityScanner\Rules\RceRule;
use EidCloud\SecurityScanner\Rules\RuleInterface;
use EidCloud\SecurityScanner\Rules\SqlInjectionRule;
use EidCloud\SecurityScanner\Rules\SsrfRule;
use EidCloud\SecurityScanner\Rules\XssRule;

class Scanner
{
    /** @var RuleInterface[] */
    private array $rules = [];

    private TaintAnalyzer $taintAnalyzer;

    public function __construct(?array $rules = null, ?TaintAnalyzer $taintAnalyzer = null)
    {
        $this->taintAnalyzer = $taintAnalyzer ?? new TaintAnalyzer();

        if ($rules !== null) {
            $this->rules = $rules;
        } else {
            $this->registerDefaultRules();
        }
    }

    private function registerDefaultRules(): void
    {
        $this->rules = [
            new SqlInjectionRule(),
            new XssRule(),
            new RceRule(),
            new PathTraversalRule(),
            new InsecureDeserializationRule(),
            new SsrfRule(),
        ];
    }

    public function registerRule(RuleInterface $rule): void
    {
        $this->rules[] = $rule;
    }

    /**
     * @return RuleInterface[]
     */
    public function getRules(): array
    {
        return $this->rules;
    }

    /**
     * Scans a target path (file or directory).
     * @param string[] $excludeDirs
     */
    public function scanPath(string $targetPath, array $excludeDirs = ['vendor', '.git', 'tests/fixtures/ignored']): ScanResult
    {
        $start = microtime(true);
        $result = new ScanResult();

        if (!file_exists($targetPath)) {
            throw new \InvalidArgumentException("Target path does not exist: {$targetPath}");
        }

        $files = is_dir($targetPath)
            ? $this->collectPhpFiles($targetPath, $excludeDirs)
            : [$targetPath];

        $totalLines = 0;
        foreach ($files as $file) {
            $code = (string)file_get_contents($file);
            $totalLines += substr_count($code, "\n") + 1;
            $findings = $this->scanCode($code, $file);
            foreach ($findings as $f) {
                $result->addFinding($f);
            }
        }

        $result->setScannedFilesCount(count($files));
        $result->setScannedLinesCount($totalLines);
        $result->setDuration(microtime(true) - $start);

        return $result;
    }

    /**
     * Scans raw PHP code and returns detected findings.
     * @return Finding[]
     */
    public function scanCode(string $code, string $virtualFilePath = 'inline.php'): array
    {
        // First, run taint analysis pass
        $this->taintAnalyzer->analyze($code);
        $tokens = $this->taintAnalyzer->getTokens();

        $findings = [];
        foreach ($this->rules as $rule) {
            $ruleFindings = $rule->inspect($virtualFilePath, $code, $tokens, $this->taintAnalyzer);
            foreach ($ruleFindings as $rf) {
                $findings[] = $rf;
            }
        }

        return $findings;
    }

    /**
     * @param string[] $excludeDirs
     * @return string[]
     */
    private function collectPhpFiles(string $dir, array $excludeDirs): array
    {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }

            if (strtolower($file->getExtension()) !== 'php') {
                continue;
            }

            $filePath = str_replace('\\', '/', $file->getPathname());

            // Check exclusion
            $skip = false;
            foreach ($excludeDirs as $ex) {
                if (str_contains($filePath, '/' . trim($ex, '/') . '/')) {
                    $skip = true;
                    break;
                }
            }

            if (!$skip) {
                $files[] = $file->getRealPath();
            }
        }

        return $files;
    }
}
