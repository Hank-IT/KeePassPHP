<?php

declare(strict_types=1);

namespace KeePassPHP\Tests\Fixtures;

use KeePassPHP\Contracts\RandomStream;

final class SequenceRandomStream implements RandomStream
{
    public function __construct(
        private string $bytes,
        private int $offset = 0,
    ) {}

    public function getNextBytes(int $n): string
    {
        $chunk = substr($this->bytes, $this->offset, $n);
        $this->offset += strlen($chunk);

        return $chunk;
    }
}
