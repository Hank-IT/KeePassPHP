<?php

declare(strict_types=1);

namespace KeePassPHP\Readers;

use KeePassPHP\Kdbx4DerivedKeys;

final class HmacBlockReader extends Reader
{
    protected bool $hasError = false;
    protected bool $hasReachedEnd = false;
    protected int $currentIndex = 0;
    protected string $currentBlock = '';
    protected int $currentSize = 0;
    protected int $currentPos = 0;

    public function __construct(
        protected readonly Reader $base,
        protected readonly Kdbx4DerivedKeys $keys,
    ) {}

    public function read(int $n): ?string
    {
        if ($n < 1) {
            return '';
        }

        $bytes = '';
        $remaining = $n;
        while ($remaining > 0) {
            if ($this->currentPos >= $this->currentSize) {
                if (!$this->readBlock()) {
                    return $bytes === '' ? null : $bytes;
                }
            }

            $copyLength = min($remaining, $this->currentSize - $this->currentPos);
            $bytes .= substr($this->currentBlock, $this->currentPos, $copyLength);
            $this->currentPos += $copyLength;
            $remaining -= $copyLength;
        }

        return $bytes;
    }

    public function readToTheEnd(): ?string
    {
        $bytes = $this->read($this->currentSize - $this->currentPos) ?? '';
        while ($this->readBlock()) {
            $bytes .= $this->currentBlock;
        }

        return $bytes === '' ? null : $bytes;
    }

    public function canRead(): bool
    {
        if ($this->hasReachedEnd) {
            return false;
        }

        return !$this->hasError && $this->base->canRead();
    }

    public function close(): void
    {
        $this->base->close();
    }

    public function isCorrupted(): bool
    {
        return $this->hasError;
    }

    private function readBlock(): bool
    {
        if (!$this->canRead()) {
            return false;
        }

        $expectedHmac = $this->base->read(32);
        $sizeBytes = $this->base->read(4);
        if (
            $expectedHmac === null
            || strlen($expectedHmac) !== 32
            || $sizeBytes === null
            || strlen($sizeBytes) !== 4
        ) {
            $this->hasError = true;

            return false;
        }

        $size = unpack('V', $sizeBytes);
        if ($size === false || !isset($size[1]) || !is_int($size[1])) {
            $this->hasError = true;

            return false;
        }

        $data = $size[1] > 0 ? $this->base->read($size[1]) : '';
        if ($data === null || strlen($data) !== $size[1]) {
            $this->hasError = true;

            return false;
        }

        $actualHmac = hash_hmac(
            'sha256',
            self::packUInt64($this->currentIndex) . $sizeBytes . $data,
            $this->keys->getBlockHmacKey($this->currentIndex),
            true,
        );
        $this->currentIndex++;

        if (!hash_equals($expectedHmac, $actualHmac)) {
            $this->hasError = true;

            return false;
        }

        if ($size[1] === 0) {
            $this->hasReachedEnd = true;

            return false;
        }

        $this->currentBlock = $data;
        $this->currentSize = $size[1];
        $this->currentPos = 0;

        return true;
    }

    private static function packUInt64(int $value): string
    {
        return pack('V2', $value & 0xFFFFFFFF, ($value >> 32) & 0xFFFFFFFF);
    }
}
