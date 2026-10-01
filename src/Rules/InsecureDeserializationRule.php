<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Rules;

use EidCloud\SecurityScanner\Analyzer\TaintAnalyzer;
use EidCloud\SecurityScanner\Model\Finding;
use EidCloud\SecurityScanner\Model\Severity;

class InsecureDeserializationRule extends AbstractRule
{
    public function getId(): string
    {
        return 'SEC-DESER-005';
    }

    public function getTitle(): string
    {
        return 'Insecure Deserialization (OWASP A08:2021 - Software and Data Integrity Failures)';
    }

    public function getDescription(): string
    {
        return 'Untrusted data passed into PHP unserialize() without restricting allowed_classes, enabling property-oriented programming (POP) gadget chains and remote code execution.';
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

            if ($token->id === T_STRING && strtolower($token->text) === 'unserialize') {
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

                // If allowed_classes => false is explicitly set, it prevents gadget execution
                $hasAllowedClassesFalse = (bool)preg_match('/[\'"]allowed_classes[\'"]\s*=>\s*false/i', $argsText);
                if ($hasAllowedClassesFalse) {
                    continue;
                }

                $taintCheck = $taintAnalyzer->checkExpressionTaint($args, 'deserialization');
                // Even without direct taint in this line, calling unserialize without allowed_classes => false is dangerous if dealing with non-constant strings
                if ($taintCheck['isTainted'] || preg_match('/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*/', $argsText)) {
                    $line = $token->line;
                    $lineStr = $this->getLineContent($code, $line);
                    $snippet = $this->extractLineSnippet($code, $line);
                    $flow = !empty($taintCheck['taintFlow'])
                        ? array_merge($taintCheck['taintFlow'], ["Sink: unserialize() invoked with untrusted payload at line {$line}"])
                        : ["Sink: unserialize() called without ['allowed_classes' => false] on dynamic data at line {$line}"];

                    $diff = $this->generateUnifiedDiff(
                        $filePath,
                        $line,
                        $lineStr,
                        "// SECURE: Use JSON or disable class instantiation\n\$data = json_decode(\$payload, true);\n// OR: unserialize(\$payload, ['allowed_classes' => false]);"
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
                        'Replace native PHP serialization with JSON (json_encode/json_decode). If unserialize() is required, always specify [\'allowed_classes\' => false].',
                        $diff
                    );
                }
            }
        }

        return $findings;
    }
}
