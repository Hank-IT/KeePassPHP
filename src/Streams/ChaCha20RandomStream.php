<?php

declare(strict_types=1);

namespace KeePassPHP\Streams;

use KeePassPHP\Contracts\RandomStream;

final class ChaCha20RandomStream implements RandomStream
{
    public const int KEY_LEN = 32;
    public const int NONCE_LEN = 12;
    public const int BLOCK_LEN = 64;

    private string $buffer = '';
    private int $bufferPos = self::BLOCK_LEN;
    private int $counter = 0;

    private function __construct(
        private readonly string $key,
        private readonly string $nonce,
    ) {}

    public static function create(string $key, string $nonce): ?self
    {
        if (strlen($key) !== self::KEY_LEN || strlen($nonce) !== self::NONCE_LEN) {
            return null;
        }

        return new self($key, $nonce);
    }

    public static function fromInnerKey(string $innerKey): ?self
    {
        $hash = hash('sha512', $innerKey, true);

        return self::create(substr($hash, 0, self::KEY_LEN), substr($hash, self::KEY_LEN, self::NONCE_LEN));
    }

    public function getNextBytes(int $n): string
    {
        if ($n < 1) {
            return '';
        }

        $bytes = '';
        $remaining = $n;
        while ($remaining > 0) {
            if ($this->bufferPos === self::BLOCK_LEN) {
                $this->generateBlock();
            }

            $copyLength = min(self::BLOCK_LEN - $this->bufferPos, $remaining);
            $bytes .= substr($this->buffer, $this->bufferPos, $copyLength);
            $this->bufferPos += $copyLength;
            $remaining -= $copyLength;
        }

        return $bytes;
    }

    private function generateBlock(): void
    {
        $iv = pack('V', $this->counter) . $this->nonce;
        $block = openssl_encrypt(
            str_repeat("\x00", self::BLOCK_LEN),
            'chacha20',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
        );
        if ($block === false || strlen($block) !== self::BLOCK_LEN) {
            throw new \RuntimeException('Unable to generate ChaCha20 random stream block.');
        }

        $this->buffer = $block;
        $this->bufferPos = 0;
        $this->counter++;
    }
}
