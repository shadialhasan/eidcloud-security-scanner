<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Rules;

use EidCloud\SecurityScanner\Analyzer\TaintAnalyzer;
use EidCloud\SecurityScanner\Model\Finding;
use EidCloud\SecurityScanner\Model\Severity;

class PathTraversalRule extends AbstractRule
{
    private const FILE_FUNCTIONS = [
        'file_get_contents',
        'file_put_contents',
        'readfile',
        'fopen',
        'file',
        'unlink',
        'copy',
        'rename',
    ];

    public function getId(): string
    {
        return 'SEC-PATH-004';
    }

    public function getTitle(): string
    {
        return 'Path Traversal & Arbitrary File Access (OWASP A01:2021 - Broken Access Control)';
    }

    public function getDescription(): string
    {
        return 'User-controlled input concatenated into file system operations or dynamic inclusions without basename/path normalization, permitting directory traversal.';
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

            // 1. File inclusion statements: include, require, include_once, require_once
            $isInclude = ($token->id === T_INCLUDE || $token->id === T_REQUIRE || $token->id === T_INCLUDE_ONCE || $token->id === T_REQUIRE_ONCE);
            if ($isInclude) {
                // Collect expression up to semicolon
                $exprTokens = [];
                for ($j = $i + 1; $j < $count; $j++) {
                    $t = $tokens[$j];
                    if ($t->text === ';' || $t->id === T_CLOSE_TAG) {
                        break;
                    }
                    $exprTokens[] = $t;
                }

                $taintCheck = $taintAnalyzer->checkExpressionTaint($exprTokens, 'path_traversal');
                if ($taintCheck['isTainted']) {
                    $line = $token->line;
                    $lineStr = $this->getLineContent($code, $line);
                    $snippet = $this->extractLineSnippet($code, $line);
                    $flow = array_merge($taintCheck['taintFlow'], ["Sink: Dynamic {$token->text} statement at line {$line}"]);

                    $diff = $this->generateUnifiedDiff(
                        $filePath,
                        $line,
                        $lineStr,
                        "// SECURE: Whitelist allowed templates/views\n\$allowed = ['home' => 'views/home.php', 'about' => 'views/about.php'];\nif (isset(\$allowed[\$page])) { {$token->text} \$allowed[\$page]; }"
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
                        'Never dynamically include files using untrusted paths. Use basename() or an explicit whitelist lookup array to map parameters to valid static file paths.',
                        $diff
                    );
                }
            }

            // 2. File system functions: file_get_contents, fopen, etc.
            if ($token->id === T_STRING && in_array(strtolower($token->text), self::FILE_FUNCTIONS, true)) {
                $prevIndex = $i - 1;
                while ($prevIndex >= 0 && $tokens[$prevIndex]->isIgnorable()) {
                    $prevIndex--;
                }
                if ($prevIndex >= 0 && ($tokens[$prevIndex]->id === T_OBJECT_OPERATOR || $tokens[$prevIndex]->id === T_FUNCTION)) {
                    continue;
                }

                $args = $this->extractCallArguments($tokens, $i);
                $argsText = '';
                foreach ($args as $a) {
                    $argsText .= $a->text;
                }
                // Skip remote URLs; handled by SSRF rule
                if (preg_match('/http:\/\/|https:\/\/|ftp:\/\//i', $argsText)) {
                    continue;
                }

                $taintCheck = $taintAnalyzer->checkExpressionTaint($args, 'path_traversal');
                if ($taintCheck['isTainted']) {
                    $line = $token->line;
                    $lineStr = $this->getLineContent($code, $line);
                    $snippet = $this->extractLineSnippet($code, $line);
                    $flow = array_merge($taintCheck['taintFlow'], ["Sink: {$token->text}() reading or modifying filesystem path at line {$line}"]);

                    $diff = $this->generateUnifiedDiff(
                        $filePath,
                        $line,
                        $lineStr,
                        "// SECURE: Sanitize filename with basename and verify realpath\n\$safeFilename = basename(\$userFilename);\n\$targetPath = realpath(\$baseDir . '/' . \$safeFilename);\nif (\$targetPath && str_starts_with(\$targetPath, \$baseDir)) { {$token->text}(\$targetPath); }"
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
                        'Sanitize filenames with basename(), canonicalize with realpath(), and verify the resulting path resides within the intended directory base path.',
                        $diff
                    );
                }
            }
        }

        return $findings;
    }
}
