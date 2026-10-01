<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Rules;

use EidCloud\SecurityScanner\Analyzer\TaintAnalyzer;
use EidCloud\SecurityScanner\Model\Finding;
use EidCloud\SecurityScanner\Model\Severity;

interface RuleInterface
{
    public function getId(): string;

    public function getTitle(): string;

    public function getDescription(): string;

    public function getDefaultSeverity(): Severity;

    /**
     * @param \PhpToken[] $tokens
     * @return Finding[]
     */
    public function inspect(string $filePath, string $code, array $tokens, TaintAnalyzer $taintAnalyzer): array;
}
