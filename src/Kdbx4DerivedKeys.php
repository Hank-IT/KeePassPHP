<?php

declare(strict_types=1);

namespace KeePassPHP;

final readonly class Kdbx4DerivedKeys
{
    public function __construct(
        public string $encryptionKey,
        public string $hmacBaseKey,
    ) {}

    public function getHeaderHmacKey(): string
    {
        return hash('sha512', str_repeat("\xFF", 8) . $this->hmacBaseKey, true);
    }

    public function getBlockHmacKey(int $index): string
    {
        return hash('sha512', self::packUInt64($index) . $this->hmacBaseKey, true);
    }

    private static function packUInt64(int $value): string
    {
        return pack('V2', $value & 0xFFFFFFFF, ($value >> 32) & 0xFFFFFFFF);
    }
}
