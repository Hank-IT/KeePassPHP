<?php

declare(strict_types=1);

namespace KeePassPHP;

final readonly class KdbxMetadata
{
    public function __construct(
        public int $majorVersion,
        public int $minorVersion,
        public int $formatVersion,
        public string $formatLabel,
        public bool $isDecryptableByCurrentLibrary,
        public ?string $cipherUuidHex,
        public ?string $cipherName,
        public ?bool $isCompressed,
        public ?string $kdfUuidHex,
        public ?string $kdfName,
        public ?int $innerRandomStreamId,
        public ?string $innerRandomStreamName,
        public ?string $databaseName = null,
    ) {}
}
