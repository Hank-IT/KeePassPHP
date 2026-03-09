<?php

declare(strict_types=1);

namespace KeePassPHP;

final readonly class Kdbx4WriteOptions
{
    public function __construct(
        public int $rounds = 600000,
        public bool $compress = true,
        public int $innerRandomStream = Kdbx4Writer::INNER_RANDOM_STREAM_SALSA20,
        public string $generator = 'KeePassPHP',
        public int $blockSize = 1048576,
    ) {}
}
