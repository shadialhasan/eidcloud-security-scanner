<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Rules;

use EidCloud\SecurityScanner\Model\Severity;

abstract class AbstractRule implements RuleInterface
{
    abstract public function getId(): string;
    abstract public function getTitle(): string;
    abstract public function getDescription(): string;
    abstract public function getDefaultSeverity(): Severity;

    protected function extractLineSnippet(string $code, int $lineNumber, int $context = 1): string
    {
        $lines = explode("\n", str_replace(["\r\n", "\r"], "\n", $code));
        $total = count($lines);
        $start = max(1, $lineNumber - $context);
        $end = min($total, $lineNumber + $context);

        $out = [];
        for ($i = $start; $i <= $end; $i++) {
            $prefix = ($i === $lineNumber) ? ' > ' : '   ';
            $num = str_pad((string)$i, 4, ' ', STR_PAD_LEFT);
            $lineContent = $lines[$i - 1] ?? '';
            $out[] = "{$prefix}{$num} | {$lineContent}";
        }

        return implode("\n", $out);
    }

    protected function getLineContent(string $code, int $lineNumber): string
    {
        $lines = explode("\n", str_replace(["\r\n", "\r"], "\n", $code));
        return $lines[$lineNumber - 1] ?? '';
    }

    protected function generateUnifiedDiff(string $filePath, int $line, string $originalCode, string $fixedCode): string
    {
        $originalLines = explode("\n", trim($originalCode));
        $fixedLines = explode("\n", trim($fixedCode));

        $diff = [
            "--- a/{$filePath} (line {$line})",
            "+++ b/{$filePath}",
            "@@ -{$line}," . count($originalLines) . " +{$line}," . count($fixedLines) . " @@",
        ];

        foreach ($originalLines as $l) {
            $diff[] = "- " . $l;
        }
        foreach ($fixedLines as $l) {
            $diff[] = "+ " . $l;
        }

        return implode("\n", $diff);
    }

    /**
     * Finds tokens representing function arguments inside ( ... )
     * @param \PhpToken[] $tokens
     * @return \PhpToken[]
     */
    protected function extractCallArguments(array $tokens, int $funcTokenIndex): array
    {
        $count = count($tokens);
        $parenStart = -1;

        for ($i = $funcTokenIndex + 1; $i < $count; $i++) {
            if ($tokens[$i]->text === '(') {
                $parenStart = $i;
                break;
            }
            if (!$tokens[$i]->isIgnorable()) {
                // Not a direct function call
                return [];
            }
        }

        if ($parenStart === -1) {
            return [];
        }

        $argTokens = [];
        $depth = 1;
        for ($i = $parenStart + 1; $i < $count; $i++) {
            $t = $tokens[$i];
            if ($t->text === '(') {
                $depth++;
            } elseif ($t->text === ')') {
                $depth--;
                if ($depth === 0) {
                    break;
                }
            }
            $argTokens[] = $t;
        }

        return $argTokens;
    }
}
