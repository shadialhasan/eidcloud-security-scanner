<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Rules;

use EidCloud\SecurityScanner\Analyzer\TaintAnalyzer;
use EidCloud\SecurityScanner\Model\Finding;
use EidCloud\SecurityScanner\Model\Severity;

class SqlInjectionRule extends AbstractRule
{
    private const SQL_SINKS = [
        'mysql_query',
        'mysqli_query',
        'pg_query',
        'pg_execute',
        'sqlite_query',
        'db_query',
    ];

    public function getId(): string
    {
        return 'SEC-SQLI-001';
    }

    public function getTitle(): string
    {
        return 'SQL Injection (OWASP A03:2021 - Injection)';
    }

    public function getDescription(): string
    {
        return 'Untrusted or concatenated user input supplied directly into SQL query execution functions or PDO query methods without parameter binding.';
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

            // 1. Procedural functions: mysql_query($query), mysqli_query($link, $query)
            if ($token->id === T_STRING && in_array(strtolower($token->text), self::SQL_SINKS, true)) {
                $prevIndex = $i - 1;
                while ($prevIndex >= 0 && $tokens[$prevIndex]->isIgnorable()) {
                    $prevIndex--;
                }
                // Ensure it's not a method declaration or method call like ->mysql_query
                if ($prevIndex >= 0 && ($tokens[$prevIndex]->id === T_OBJECT_OPERATOR || $tokens[$prevIndex]->id === T_FUNCTION)) {
                    continue;
                }

                $args = $this->extractCallArguments($tokens, $i);
                $taintCheck = $taintAnalyzer->checkExpressionTaint($args, 'sqli');
                if ($taintCheck['isTainted']) {
                    $line = $token->line;
                    $lineStr = $this->getLineContent($code, $line);
                    $snippet = $this->extractLineSnippet($code, $line);
                    $flow = array_merge($taintCheck['taintFlow'], ["Sink: {$token->text}() called with unparameterized query at line {$line}"]);

                    $diff = $this->generateUnifiedDiff(
                        $filePath,
                        $line,
                        $lineStr,
                        "// SECURE: Use PDO Prepared Statements\n\$stmt = \$pdo->prepare('SELECT ... WHERE id = :id');\n\$stmt->execute(['id' => \$safeId]);"
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
                        'Replace direct string queries with PDO prepared statements and bound parameters (:param).',
                        $diff
                    );
                }
            }

            // 2. Object methods: $db->query(...), $pdo->query(...), $pdo->exec(...)
            if ($token->id === T_OBJECT_OPERATOR || (defined('T_NULLSAFE_OBJECT_OPERATOR') && $token->id === T_NULLSAFE_OBJECT_OPERATOR)) {
                $next = $i + 1;
                while ($next < $count && $tokens[$next]->isIgnorable()) {
                    $next++;
                }

                if ($next < $count && $tokens[$next]->id === T_STRING) {
                    $methodName = strtolower($tokens[$next]->text);
                    if (in_array($methodName, ['query', 'exec', 'rawquery', 'raw'], true)) {
                        $args = $this->extractCallArguments($tokens, $next);
                        $taintCheck = $taintAnalyzer->checkExpressionTaint($args, 'sqli');
                        if ($taintCheck['isTainted']) {
                            $line = $token->line;
                            $lineStr = $this->getLineContent($code, $line);
                            $snippet = $this->extractLineSnippet($code, $line);
                            $flow = array_merge($taintCheck['taintFlow'], ["Sink: ->{$methodName}() invoked with tainted query argument at line {$line}"]);

                            $diff = $this->generateUnifiedDiff(
                                $filePath,
                                $line,
                                $lineStr,
                                "\$stmt = \$pdo->prepare('SELECT ... WHERE col = :val');\n\$stmt->execute(['val' => \$val]);\n\$result = \$stmt->fetchAll();"
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
                                'Use $pdo->prepare() and bind parameters with execute() instead of passing unescaped variables directly into query()/exec().',
                                $diff
                            );
                        }
                    }
                }
            }
        }

        return $findings;
    }
}
