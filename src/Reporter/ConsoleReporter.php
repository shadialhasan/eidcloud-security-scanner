<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Reporter;

use EidCloud\SecurityScanner\Model\Finding;
use EidCloud\SecurityScanner\Model\ScanResult;
use EidCloud\SecurityScanner\Model\Severity;

class ConsoleReporter
{
    public function __construct(
        private readonly bool $useAnsi = true,
        private readonly bool $verbose = false
    ) {
    }

    public function render(ScanResult $result, ?Severity $failOn = null): string
    {
        $out = [];
        $out[] = $this->renderBanner();

        $findings = $result->getFindings();
        if (empty($findings)) {
            $out[] = $this->color("\n [✓] PASS: No security vulnerabilities detected across all scanned files.\n", "\033[1;32m");
            $out[] = $this->renderSummary($result, $failOn);
            return implode("\n", $out);
        }

        $out[] = $this->color(sprintf("\n Found %d security finding(s):\n", count($findings)), "\033[1;37m");

        foreach ($findings as $idx => $finding) {
            $out[] = $this->renderFinding($idx + 1, $finding);
        }

        $out[] = $this->renderSummary($result, $failOn);

        return implode("\n", $out);
    }

    private function renderBanner(): string
    {
        $logo = <<<BANNER
  ███████╗██╗██████╗  ██████╗██╗      ██████╗ ██╗   ██╗██████╗ 
  ██╔════╝██║██╔══██╗██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗
  █████╗  ██║██║  ██║██║     ██║     ██║   ██║██║   ██║██║  ██║
  ██╔══╝  ██║██║  ██║██║     ██║     ██║   ██║██║   ██║██║  ██║
  ███████╗██║██████╔╝╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝
  ╚══════╝╚═╝╚═════╝  ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ 
               EIDCLOUD STATIC SECURITY SCANNER v1.0.0
BANNER;
        return $this->color($logo, "\033[1;36m");
    }

    private function renderFinding(int $num, Finding $finding): string
    {
        $sev = $finding->getSeverity();
        $sevBadge = $this->color(" {$sev->value} ", $sev->color());

        $lines = [];
        $lines[] = str_repeat("─", 80);
        $lines[] = sprintf(
            "#%d %s %s: %s",
            $num,
            $sevBadge,
            $this->color($finding->getRuleId(), "\033[1m"),
            $this->color($finding->getTitle(), "\033[1m")
        );
        $lines[] = sprintf(
            "  %s %s:%d",
            $this->color("Location:", "\033[0;33m"),
            $finding->getFilePath(),
            $finding->getLine()
        );
        $lines[] = sprintf(
            "  %s %s",
            $this->color("Description:", "\033[0;33m"),
            $finding->getDescription()
        );

        // Code snippet
        $lines[] = "";
        $lines[] = $this->color("  Vulnerable Code Snippet:", "\033[1;30m");
        $snippetLines = explode("\n", $finding->getCodeSnippet());
        foreach ($snippetLines as $s) {
            $lines[] = "    " . $s;
        }

        // Taint flow
        if (!empty($finding->getTaintFlow())) {
            $lines[] = "";
            $lines[] = $this->color("  Taint Propagation Trace:", "\033[1;35m");
            foreach ($finding->getTaintFlow() as $stepIdx => $step) {
                $arrow = ($stepIdx === 0) ? " └── [SOURCE] " : "      └── ──> ";
                $lines[] = $this->color($arrow, "\033[0;35m") . $step;
            }
        }

        // Remediation
        $lines[] = "";
        $lines[] = sprintf("  %s %s", $this->color("Remediation:", "\033[1;32m"), $finding->getRemediation());

        // Diff suggestion
        if ($finding->getDiffSuggestion() !== null) {
            $lines[] = "";
            $lines[] = $this->color("  Suggested Code Patch:", "\033[1;34m");
            $diffLines = explode("\n", $finding->getDiffSuggestion());
            foreach ($diffLines as $dl) {
                if (str_starts_with($dl, '+')) {
                    $lines[] = "    " . $this->color($dl, "\033[0;32m");
                } elseif (str_starts_with($dl, '-')) {
                    $lines[] = "    " . $this->color($dl, "\033[0;31m");
                } else {
                    $lines[] = "    " . $this->color($dl, "\033[0;90m");
                }
            }
        }

        return implode("\n", $lines);
    }

    private function renderSummary(ScanResult $result, ?Severity $failOn): string
    {
        $counts = $result->countsBySeverity();
        $total = count($result->getFindings());

        $lines = [];
        $lines[] = "\n" . str_repeat("═", 80);
        $lines[] = $this->color("                      SCAN EXECUTION SUMMARY", "\033[1;37m");
        $lines[] = str_repeat("═", 80);
        $lines[] = sprintf(" Files Scanned: %d   |   Lines of Code: %d   |   Scan Duration: %.3fs",
            $result->getScannedFilesCount(),
            $result->getScannedLinesCount(),
            $result->getDuration()
        );
        $lines[] = str_repeat("─", 80);

        $critStr = $this->color(sprintf("CRITICAL: %d", $counts['CRITICAL']), Severity::CRITICAL->color());
        $highStr = $this->color(sprintf("HIGH: %d", $counts['HIGH']), Severity::HIGH->color());
        $medStr  = $this->color(sprintf("MEDIUM: %d", $counts['MEDIUM']), Severity::MEDIUM->color());
        $lowStr  = $this->color(sprintf("LOW: %d", $counts['LOW']), Severity::LOW->color());

        $lines[] = sprintf(" Breakdown:  %s    %s    %s    %s    (Total: %d)", $critStr, $highStr, $medStr, $lowStr, $total);
        $lines[] = str_repeat("─", 80);

        if ($failOn !== null) {
            $failed = $result->hasSeverityOrAbove($failOn);
            if ($failed) {
                $statusMsg = sprintf(" [✗] FAILED: Security gate triggered (Found vulnerabilities meeting threshold: %s)", $failOn->value);
                $lines[] = $this->color($statusMsg, "\033[1;37;41m");
            } else {
                $statusMsg = sprintf(" [✓] PASSED: No vulnerabilities meet or exceed threshold: %s", $failOn->value);
                $lines[] = $this->color($statusMsg, "\033[1;32m");
            }
        }
        $lines[] = str_repeat("═", 80) . "\n";

        return implode("\n", $lines);
    }

    private function color(string $text, string $ansi): string
    {
        if (!$this->useAnsi) {
            return $text;
        }
        return "{$ansi}{$text}\033[0m";
    }
}
