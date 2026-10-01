<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Rules;

use EidCloud\SecurityScanner\Analyzer\TaintAnalyzer;
use EidCloud\SecurityScanner\Model\Finding;
use EidCloud\SecurityScanner\Model\Severity;

class RceRule extends AbstractRule
{
    private const RCE_FUNCTIONS = [
        'system',
        'exec',
        'shell_exec',
        'passthru',
        'proc_open',
        'popen',
        'assert',
        'pcntl_exec',
    ];

    public function getId(): string
    {
        return 'SEC-RCE-003';
    }

    public function getTitle(): string
    {
        return 'Remote Code Execution (RCE: OWASP A03:2021 - Injection)';
    }

    public function getDescription(): string
    {
        return 'Arbitrary command or code execution sink invoked with untrusted or tainted input, allowing attackers to execute commands on the host server.';
    }

    public function getDefaultSeverity(): Severity
    {
        return Severity::CRITICAL;
    }

    public function inspect(string $filePath, string $code, array $tokens, TaintAnalyzer $taintAnalyzer): array
    {
        $findings = [];
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];

            // 1. eval() language construct
            if ($token->id === T_EVAL) {
                $args = $this->extractCallArguments($tokens, $i);
                $taintCheck = $taintAnalyzer->checkExpressionTaint($args, 'rce');
                if ($taintCheck['isTainted']) {
                    $line = $token->line;
                    $lineStr = $this->getLineContent($code, $line);
                    $snippet = $this->extractLineSnippet($code, $line);
                    $flow = array_merge($taintCheck['taintFlow'], ["Sink: eval() called with user data at line {$line}"]);

                    $diff = $this->generateUnifiedDiff(
                        $filePath,
                        $line,
                        $lineStr,
                        "// SECURE: Refactor to eliminate eval entirely; use safe parser or lookup maps"
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
                        'Never pass untrusted input into eval(). Replace dynamic code generation with static maps or domain-specific parsers.',
                        $diff
                    );
                }
            }

            // 2. Shell execution functions: system, exec, shell_exec, etc.
            if ($token->id === T_STRING && in_array(strtolower($token->text), self::RCE_FUNCTIONS, true)) {
                $prevIndex = $i - 1;
                while ($prevIndex >= 0 && $tokens[$prevIndex]->isIgnorable()) {
                    $prevIndex--;
                }
                if ($prevIndex >= 0 && ($tokens[$prevIndex]->id === T_OBJECT_OPERATOR || $tokens[$prevIndex]->id === T_FUNCTION)) {
                    continue;
                }

                $args = $this->extractCallArguments($tokens, $i);
                $taintCheck = $taintAnalyzer->checkExpressionTaint($args, 'rce');
                if ($taintCheck['isTainted']) {
                    $line = $token->line;
                    $lineStr = $this->getLineContent($code, $line);
                    $snippet = $this->extractLineSnippet($code, $line);
                    $flow = array_merge($taintCheck['taintFlow'], ["Sink: {$token->text}() executing shell command with tainted input at line {$line}"]);

                    $diff = $this->generateUnifiedDiff(
                        $filePath,
                        $line,
                        $lineStr,
                        "// SECURE: Whitelist allowed commands or escape arguments\n\$safeArg = escapeshellarg(\$arg);\n{$token->text}(\"command \" . \$safeArg);"
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
                        'Avoid passing dynamic input into shell commands. If unavoidable, sanitize parameters strictly with escapeshellarg() and validate against an explicit whitelist.',
                        $diff
                    );
                }
            }

            // 3. Backtick operator (execution operator)
            if ($token->text === '`') {
                // Find closing backtick
                $backtickTokens = [];
                for ($j = $i + 1; $j < $count; $j++) {
                    if ($tokens[$j]->text === '`') {
                        break;
                    }
                    $backtickTokens[] = $tokens[$j];
                }

                $taintCheck = $taintAnalyzer->checkExpressionTaint($backtickTokens, 'rce');
                if ($taintCheck['isTainted']) {
                    $line = $token->line;
                    $lineStr = $this->getLineContent($code, $line);
                    $snippet = $this->extractLineSnippet($code, $line);
                    $flow = array_merge($taintCheck['taintFlow'], ["Sink: Backtick execution operator at line {$line}"]);

                    $diff = $this->generateUnifiedDiff(
                        $filePath,
                        $line,
                        $lineStr,
                        "// SECURE: Discontinue backtick command invocation"
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
                        'Replace shell backtick operators with validated APIs and strict argument escaping.',
                        $diff
                    );
                }
            }
        }

        return $findings;
    }
}
