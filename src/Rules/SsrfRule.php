<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Rules;

use EidCloud\SecurityScanner\Analyzer\TaintAnalyzer;
use EidCloud\SecurityScanner\Model\Finding;
use EidCloud\SecurityScanner\Model\Severity;

class SsrfRule extends AbstractRule
{
    private const HTTP_SINKS = [
        'curl_init',
        'file_get_contents',
        'fopen',
        'readfile',
        'get_headers',
    ];

    public function getId(): string
    {
        return 'SEC-SSRF-006';
    }

    public function getTitle(): string
    {
        return 'Server-Side Request Forgery (SSRF: OWASP A10:2021 - SSRF)';
    }

    public function getDescription(): string
    {
        return 'Outbound network requests (cURL, file_get_contents) initiated using untrusted URLs, allowing attackers to access internal cloud metadata services, databases, and internal intranet resources.';
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

            // 1. curl_init($url) or curl_setopt($ch, CURLOPT_URL, $url)
            if ($token->id === T_STRING) {
                $func = strtolower($token->text);

                if ($func === 'curl_init') {
                    $args = $this->extractCallArguments($tokens, $i);
                    if (!empty($args)) {
                        $taintCheck = $taintAnalyzer->checkExpressionTaint($args, 'ssrf');
                        if ($taintCheck['isTainted']) {
                            $line = $token->line;
                            $lineStr = $this->getLineContent($code, $line);
                            $snippet = $this->extractLineSnippet($code, $line);
                            $flow = array_merge($taintCheck['taintFlow'], ["Sink: curl_init() initialized with user URL at line {$line}"]);

                            $diff = $this->generateUnifiedDiff(
                                $filePath,
                                $line,
                                $lineStr,
                                "// SECURE: Validate URL scheme and IP address\n\$parsed = parse_url(\$url);\nif (in_array(\$parsed['scheme'] ?? '', ['http', 'https'], true) && filter_var(gethostbyname(\$parsed['host'] ?? ''), FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {\n    \$ch = curl_init(\$url);\n}"
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
                                'Enforce strict URL whitelisting, validate protocol schemes (http/https only), and disallow private/reserved IP ranges (127.0.0.1, 169.254.169.254, RFC 1918) prior to initiating requests.',
                                $diff
                            );
                        }
                    }
                } elseif ($func === 'curl_setopt' || $func === 'curl_setopt_array') {
                    $args = $this->extractCallArguments($tokens, $i);
                    $argsText = '';
                    foreach ($args as $a) {
                        $argsText .= $a->text;
                    }
                    if (str_contains($argsText, 'CURLOPT_URL')) {
                        $taintCheck = $taintAnalyzer->checkExpressionTaint($args, 'ssrf');
                        if ($taintCheck['isTainted']) {
                            $line = $token->line;
                            $lineStr = $this->getLineContent($code, $line);
                            $snippet = $this->extractLineSnippet($code, $line);
                            $flow = array_merge($taintCheck['taintFlow'], ["Sink: curl_setopt(CURLOPT_URL) with untrusted target at line {$line}"]);

                            $diff = $this->generateUnifiedDiff(
                                $filePath,
                                $line,
                                $lineStr,
                                "// SECURE: Enforce outbound destination whitelist before setting CURLOPT_URL"
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
                                'Validate remote endpoints and block loopback/metadata addresses before passing user input to CURLOPT_URL.',
                                $diff
                            );
                        }
                    }
                } elseif (in_array($func, ['file_get_contents', 'fopen'], true)) {
                    $args = $this->extractCallArguments($tokens, $i);
                    $argsText = '';
                    foreach ($args as $a) {
                        $argsText .= $a->text;
                    }

                    // Check if expression looks like an HTTP/URL request
                    if (preg_match('/http:\/\/|https:\/\/|ftp:\/\//i', $argsText)) {
                        $taintCheck = $taintAnalyzer->checkExpressionTaint($args, 'ssrf');
                        if ($taintCheck['isTainted']) {
                            $line = $token->line;
                            $lineStr = $this->getLineContent($code, $line);
                            $snippet = $this->extractLineSnippet($code, $line);
                            $flow = array_merge($taintCheck['taintFlow'], ["Sink: {$token->text}() fetching remote URL at line {$line}"]);

                            $diff = $this->generateUnifiedDiff(
                                $filePath,
                                $line,
                                $lineStr,
                                "// SECURE: Validate URL host against allowed domain whitelist"
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
                                'Do not fetch dynamic URLs directly via file_get_contents/fopen. Verify domain whitelist and filter loopback addresses.',
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
