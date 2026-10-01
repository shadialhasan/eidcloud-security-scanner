<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Rules;

use EidCloud\SecurityScanner\Analyzer\TaintAnalyzer;
use EidCloud\SecurityScanner\Model\Finding;
use EidCloud\SecurityScanner\Model\Severity;

class XssRule extends AbstractRule
{
    public function getId(): string
    {
        return 'SEC-XSS-002';
    }

    public function getTitle(): string
    {
        return 'Cross-Site Scripting (XSS: OWASP A03:2021 - Injection)';
    }

    public function getDescription(): string
    {
        return 'Unsanitized user-controlled input echoed or printed directly to HTTP output stream without HTML escaping.';
    }

    public function getDefaultSeverity(): Severity
    {
        return Severity::HIGH;
    }

    public function inspect(string $filePath, string $code, array $tokens, TaintAnalyzer $taintAnalyzer): array
    {
        $findings = [];
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];

            // T_ECHO, T_PRINT, or echo short tag (<?=)
            $isEcho = ($token->id === T_ECHO || $token->id === T_PRINT || (defined('T_OPEN_TAG_WITH_ECHO') && $token->id === T_OPEN_TAG_WITH_ECHO));
            $isPrintf = ($token->id === T_STRING && in_array(strtolower($token->text), ['printf', 'vprintf'], true));

            if ($isEcho || $isPrintf) {
                // Collect expression until semicolon or close tag
                $exprTokens = [];
                $depth = 0;
                for ($j = $i + 1; $j < $count; $j++) {
                    $t = $tokens[$j];
                    if ($t->text === '(' || $t->text === '[' || $t->text === '{') {
                        $depth++;
                    } elseif ($t->text === ')' || $t->text === ']' || $t->text === '}') {
                        $depth--;
                    }

                    if ($depth <= 0 && ($t->text === ';' || $t->text === '?' || $t->id === T_CLOSE_TAG)) {
                        break;
                    }
                    $exprTokens[] = $t;
                }

                $taintCheck = $taintAnalyzer->checkExpressionTaint($exprTokens, 'xss');
                if ($taintCheck['isTainted']) {
                    $line = $token->line;
                    $lineStr = $this->getLineContent($code, $line);
                    $snippet = $this->extractLineSnippet($code, $line);

                    $rawVar = '$input';
                    foreach ($exprTokens as $et) {
                        if ($et->id === T_VARIABLE) {
                            $rawVar = $et->text;
                            break;
                        }
                    }

                    $flow = array_merge($taintCheck['taintFlow'], ["Sink: Output stream emission ({$token->text}) at line {$line}"]);

                    $diff = $this->generateUnifiedDiff(
                        $filePath,
                        $line,
                        $lineStr,
                        "echo htmlspecialchars({$rawVar}, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');"
                    );

                    $findings[] = new Finding(
                        $this->getId(),
                        $this->getTitle(),
                        $this->getDescription(),
                        $this->getDefaultSeverity(),
                        $filePath,
                        $line,
                        $snippet,
                        $flow,
                        'Wrap output variables with htmlspecialchars($var, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\') or use an auto-escaping template engine.',
                        $diff
                    );
                }
            }
        }

        return $findings;
    }
}
