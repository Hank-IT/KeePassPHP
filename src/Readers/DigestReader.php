<?php

declare(strict_types=1);

namespace KeePassPHP\Readers;

use HashContext;

/**
 * A Reader implementation, backed by another reader, which can compute the
 * hash of all the read data.
 */
final class DigestReader extends Reader
{
    /**
     * Constructs a new DigestReader implementation, reading from the Reader
     * $base and hashing all data with the algorithm $hashAlgo.
     *
     * @param Reader $base     A Reader instance.
     * @param string $hashAlgo A hash algorithm name.
     */
    public function __construct(
        protected readonly Reader $base,
        string $hashAlgo,
    ) {
        $this->context = hash_init($hashAlgo);
    }

    protected readonly HashContext $context;

    public function read(int $n): ?string
    {
        return $this->updateDigest($this->base->read($n));
    }

    public function readToTheEnd(): ?string
    {
        return $this->updateDigest($this->base->readToTheEnd());
    }

    public function canRead(): bool
    {
        return $this->base->canRead();
    }

    public function close(): void
    {
        $this->base->close();
    }

    /**
     * Gets the hash of all read data so far.
     *
     * @return string A raw hash string.
     */
    public function getDigest(): string
    {
        return hash_final(hash_copy($this->context), true);
    }

    private function updateDigest(?string $data): ?string
    {
        if ($data !== null) {
            hash_update($this->context, $data);
        }

        return $data;
    }
}
