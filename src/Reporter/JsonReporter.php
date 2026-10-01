<?php

declare(strict_types=1);

namespace EidCloud\SecurityScanner\Reporter;

use EidCloud\SecurityScanner\Model\ScanResult;

class JsonReporter
{
    public function render(ScanResult $result, bool $pretty = true): string
    {
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        if ($pretty) {
            $flags |= JSON_PRETTY_PRINT;
        }

        return (string)json_encode($result->toArray(), $flags);
    }
}
