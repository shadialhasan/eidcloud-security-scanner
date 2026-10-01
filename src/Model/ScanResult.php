<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Model;

class ScanResult
{
    /**
     * @param Finding[] $findings
     */
    public function __construct(
        private array $findings = [],
        private int $scannedFilesCount = 0,
        private int $scannedLinesCount = 0,
        private float $duration = 0.0
    ) {
    }

    public function addFinding(Finding $finding): void
    {
        $this->findings[] = $finding;
    }

    /**
     * @return Finding[]
     */
    public function getFindings(): array
    {
        return $this->findings;
    }

    public function getScannedFilesCount(): int
    {
        return $this->scannedFilesCount;
    }

    public function setScannedFilesCount(int $count): void
    {
        $this->scannedFilesCount = $count;
    }

    public function getScannedLinesCount(): int
    {
        return $this->scannedLinesCount;
    }

    public function setScannedLinesCount(int $count): void
    {
        $this->scannedLinesCount = $count;
    }

    public function getDuration(): float
    {
        return $this->duration;
    }

    public function setDuration(float $duration): void
    {
        $this->duration = $duration;
    }

    /**
     * @return array<string, int>
     */
    public function countsBySeverity(): array
    {
        $counts = [
            Severity::CRITICAL->value => 0,
            Severity::HIGH->value => 0,
            Severity::MEDIUM->value => 0,
            Severity::LOW->value => 0,
        ];

        foreach ($this->findings as $finding) {
            $counts[$finding->getSeverity()->value]++;
        }

        return $counts;
    }

    public function hasSeverityOrAbove(Severity $threshold): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->getSeverity()->meetsOrExceeds($threshold)) {
                return true;
            }
        }
        return false;
    }

    public function toArray(): array
    {
        return [
            'summary' => [
                'files_scanned' => $this->scannedFilesCount,
                'lines_scanned' => $this->scannedLinesCount,
                'total_findings' => count($this->findings),
                'duration_seconds' => round($this->duration, 4),
                'counts_by_severity' => $this->countsBySeverity(),
            ],
            'findings' => array_map(fn(Finding $f) => $f->toArray(), $this->findings),
        ];
    }
}
