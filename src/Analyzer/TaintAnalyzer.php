<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Analyzer;

class TaintAnalyzer
{
    /** @var array<string, array{tainted: bool, sources: string[], history: string[], sanitizedFor: string[]}> */
    private array $variables = [];

    /** @var \PhpToken[] */
    private array $tokens = [];

    private string $code = '';

    private const SOURCES = [
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_COOKIE',
        '$_SERVER',
        '$_FILES',
        'php://input',
    ];

    private const GLOBAL_SANITIZERS = [
        '(int)',
        'intval',
        'floatval',
        '(float)',
        'boolval',
        '(bool)',
        'filter_var($var, FILTER_VALIDATE_INT)',
    ];

    public function analyze(string $code): void
    {
        $this->code = $code;
        $this->variables = [];
        $this->tokens = \PhpToken::tokenize($code);

        $count = count($this->tokens);
        for ($i = 0; $i < $count; $i++) {
            $token = $this->tokens[$i];

            // Look for variable assignments: $var = ...;
            if ($token->id === T_VARIABLE) {
                $varName = $token->text;
                $nextSignificant = $this->findNextSignificantToken($i + 1);

                if ($nextSignificant !== null && $this->tokens[$nextSignificant]->text === '=') {
                    // Collect RHS until semicolon, comma or closing paren of statement
                    $rhsTokens = $this->collectRhsTokens($nextSignificant + 1);
                    $this->processAssignment($varName, $token->line, $rhsTokens);
                }
            }
        }
    }

    /**
     * @param \PhpToken[] $rhsTokens
     */
    private function processAssignment(string $varName, int $line, array $rhsTokens): void
    {
        $rhsText = '';
        foreach ($rhsTokens as $t) {
            $rhsText .= $t->text;
        }

        // Check for global sanitizers like (int), intval, floatval
        if (preg_match('/\(int\)|\(float\)|\(bool\)|intval\s*\(|floatval\s*\(|filter_var\s*\([^,]+,\s*FILTER_VALIDATE_INT\)/i', $rhsText)) {
            $this->variables[$varName] = [
                'tainted' => false,
                'sources' => [],
                'history' => ["Variable {$varName} sanitized via numeric cast at line {$line}"],
                'sanitizedFor' => ['all'],
            ];
            return;
        }

        // Check for specific sanitizers
        $sanitizedFor = [];
        if (preg_match('/htmlspecialchars\s*\(|htmlentities\s*\(|urlencode\s*\(/i', $rhsText)) {
            $sanitizedFor[] = 'xss';
        }
        if (preg_match('/escapeshellarg\s*\(|escapeshellcmd\s*\(/i', $rhsText)) {
            $sanitizedFor[] = 'rce';
        }
        if (preg_match('/basename\s*\(|realpath\s*\(/i', $rhsText)) {
            $sanitizedFor[] = 'path_traversal';
        }
        if (preg_match('/addslashes\s*\(|mysqli_real_escape_string\s*\(|PDO::quote\s*\(/i', $rhsText)) {
            $sanitizedFor[] = 'sqli';
        }

        // Check if RHS contains direct sources
        $foundSources = [];
        foreach (self::SOURCES as $source) {
            if (str_contains($rhsText, $source)) {
                $foundSources[] = "{$source} accessed at line {$line}";
            }
        }

        // Check if RHS references existing tainted variables
        $inheritedHistory = [];
        $parentSanitizations = [];
        $hasTaintedParent = false;

        foreach ($rhsTokens as $t) {
            if ($t->id === T_VARIABLE && $t->text !== $varName && isset($this->variables[$t->text])) {
                $parent = $this->variables[$t->text];
                if ($parent['tainted']) {
                    $hasTaintedParent = true;
                    foreach ($parent['sources'] as $src) {
                        if (!in_array($src, $foundSources, true)) {
                            $foundSources[] = $src;
                        }
                    }
                    $inheritedHistory = array_merge($inheritedHistory, $parent['history']);
                    if (!empty($parent['sanitizedFor'])) {
                        $parentSanitizations[] = $parent['sanitizedFor'];
                    }
                }
            }
        }

        // If all contributing parents share a sanitization category, inherit it
        if ($hasTaintedParent && !empty($parentSanitizations)) {
            $commonSanitizations = count($parentSanitizations) === 1
                ? $parentSanitizations[0]
                : array_intersect(...$parentSanitizations);

            foreach ($commonSanitizations as $cs) {
                if (!in_array($cs, $sanitizedFor, true)) {
                    $sanitizedFor[] = $cs;
                }
            }
        }

        if (!empty($foundSources)) {
            $history = $inheritedHistory;
            $history[] = "Source tainted input assigned to {$varName} at line {$line} [{$rhsText}]";
            $this->variables[$varName] = [
                'tainted' => true,
                'sources' => $foundSources,
                'history' => $history,
                'sanitizedFor' => $sanitizedFor,
            ];
        } else {
            // Overwritten with untainted value
            $this->variables[$varName] = [
                'tainted' => false,
                'sources' => [],
                'history' => [],
                'sanitizedFor' => $sanitizedFor,
            ];
        }
    }

    /**
     * Determine if a variable or direct superglobal in an expression is tainted for the given sink.
     */
    public function isTainted(string $varName, ?string $sinkCategory = null): bool
    {
        // Direct superglobals are always tainted unless specifically safe
        if ($this->isDirectSource($varName)) {
            return true;
        }

        if (!isset($this->variables[$varName])) {
            return false;
        }

        $info = $this->variables[$varName];
        if (!$info['tainted']) {
            return false;
        }

        if (in_array('all', $info['sanitizedFor'], true)) {
            return false;
        }

        if ($sinkCategory !== null && in_array($sinkCategory, $info['sanitizedFor'], true)) {
            return false;
        }

        return true;
    }

    public function isDirectSource(string $text): bool
    {
        foreach (self::SOURCES as $source) {
            if (str_starts_with(trim($text), $source)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return string[]
     */
    public function getTaintHistory(string $varName): array
    {
        if (isset($this->variables[$varName])) {
            return $this->variables[$varName]['history'];
        }

        if ($this->isDirectSource($varName)) {
            return ["Direct input source {$varName} provided by client"];
        }

        return [];
    }

    /**
     * Check if a series of tokens / expression is tainted for a specific sink category.
     * @param \PhpToken[] $tokens
     * @return array{isTainted: bool, taintFlow: string[]}
     */
    public function checkExpressionTaint(array $tokens, ?string $sinkCategory = null): array
    {
        $flow = [];
        $tainted = false;

        $exprText = '';
        foreach ($tokens as $t) {
            $exprText .= $t->text;
        }

        // Check for direct casting/sanitization in the call itself
        if (preg_match('/\(int\)|\(float\)|\(bool\)|intval\s*\(|floatval\s*\(/i', $exprText)) {
            return ['isTainted' => false, 'taintFlow' => []];
        }

        if ($sinkCategory === 'xss' && preg_match('/htmlspecialchars\s*\(|htmlentities\s*\(|urlencode\s*\(/i', $exprText)) {
            return ['isTainted' => false, 'taintFlow' => []];
        }
        if ($sinkCategory === 'rce' && preg_match('/escapeshellarg\s*\(|escapeshellcmd\s*\(/i', $exprText)) {
            return ['isTainted' => false, 'taintFlow' => []];
        }
        if ($sinkCategory === 'path_traversal' && preg_match('/basename\s*\(/i', $exprText)) {
            return ['isTainted' => false, 'taintFlow' => []];
        }

        foreach ($tokens as $token) {
            // Check direct superglobals
            if ($this->isDirectSource($token->text)) {
                $tainted = true;
                $flow[] = "Direct untrusted source '{$token->text}' passed to sink at line {$token->line}";
            }

            // Check variable
            if ($token->id === T_VARIABLE && $this->isTainted($token->text, $sinkCategory)) {
                $tainted = true;
                $varHistory = $this->getTaintHistory($token->text);
                foreach ($varHistory as $h) {
                    if (!in_array($h, $flow, true)) {
                        $flow[] = $h;
                    }
                }
                $flow[] = "Tainted variable '{$token->text}' forwarded to sink at line {$token->line}";
            }
        }

        return [
            'isTainted' => $tainted,
            'taintFlow' => array_unique($flow),
        ];
    }

    private function findNextSignificantToken(int $start): ?int
    {
        $count = count($this->tokens);
        for ($i = $start; $i < $count; $i++) {
            if (!$this->tokens[$i]->isIgnorable()) {
                return $i;
            }
        }
        return null;
    }

    /**
     * @return \PhpToken[]
     */
    private function collectRhsTokens(int $start): array
    {
        $rhs = [];
        $count = count($this->tokens);
        $depth = 0;

        for ($i = $start; $i < $count; $i++) {
            $t = $this->tokens[$i];
            if ($t->text === '(' || $t->text === '[' || $t->text === '{') {
                $depth++;
            } elseif ($t->text === ')' || $t->text === ']' || $t->text === '}') {
                $depth--;
            }

            if ($depth <= 0 && ($t->text === ';' || $t->text === '?' || $t->id === T_CLOSE_TAG)) {
                break;
            }

            $rhs[] = $t;
        }

        return $rhs;
    }

    /**
     * @return \PhpToken[]
     */
    public function getTokens(): array
    {
        return $this->tokens;
    }

    public function getCode(): string
    {
        return $this->code;
    }
}
