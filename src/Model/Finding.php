<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Model;

class Finding
{
    /**
     * @param string[] $taintFlow
     */
    public function __construct(
        private readonly string $ruleId,
        private readonly string $title,
        private readonly string $description,
        private readonly Severity $severity,
        private readonly string $filePath,
        private readonly int $line,
        private readonly string $codeSnippet,
        private readonly array $taintFlow = [],
        private readonly string $remediation = '',
        private readonly ?string $diffSuggestion = null
    ) {
    }

    public function getRuleId(): string
    {
        return $this->ruleId;
    }

    public function getTitle(): string
    {
        return $this->title;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getSeverity(): Severity
    {
        return $this->severity;
    }

    public function getFilePath(): string
    {
        return $this->filePath;
    }

    public function getLine(): int
    {
        return $this->line;
    }

    public function getCodeSnippet(): string
    {
        return $this->codeSnippet;
    }

    /**
     * @return string[]
     */
    public function getTaintFlow(): array
    {
        return $this->taintFlow;
    }

    public function getRemediation(): string
    {
        return $this->remediation;
    }

    public function getDiffSuggestion(): ?string
    {
        return $this->diffSuggestion;
    }

    public function toArray(): array
    {
        return [
            'rule_id' => $this->ruleId,
            'title' => $this->title,
            'description' => $this->description,
            'severity' => $this->severity->value,
            'file' => $this->filePath,
            'line' => $this->line,
            'snippet' => $this->codeSnippet,
            'taint_flow' => $this->taintFlow,
            'remediation' => $this->remediation,
            'diff_suggestion' => $this->diffSuggestion,
        ];
    }
}
