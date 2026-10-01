<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Model;

enum Severity: string
{
    case CRITICAL = 'CRITICAL';
    case HIGH = 'HIGH';
    case MEDIUM = 'MEDIUM';
    case LOW = 'LOW';

    public function weight(): int
    {
        return match ($this) {
            self::CRITICAL => 4,
            self::HIGH => 3,
            self::MEDIUM => 2,
            self::LOW => 1,
        };
    }

    public function color(): string
    {
        return match ($this) {
            self::CRITICAL => "\033[1;37;41m", // Bright white on red
            self::HIGH => "\033[1;31m",       // Bold red
            self::MEDIUM => "\033[1;33m",     // Bold yellow
            self::LOW => "\033[1;36m",        // Bold cyan
        };
    }

    public static function fromString(string $name): self
    {
        $upper = strtoupper(trim($name));
        return match ($upper) {
            'CRITICAL' => self::CRITICAL,
            'HIGH' => self::HIGH,
            'MEDIUM' => self::MEDIUM,
            'LOW' => self::LOW,
            default => throw new \InvalidArgumentException("Invalid severity level: {$name}"),
        };
    }

    public function meetsOrExceeds(Severity $threshold): bool
    {
        return $this->weight() >= $threshold->weight();
    }
}
