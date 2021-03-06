<?php

declare(strict_types=1);

namespace KeePassPHP\Readers;

/**
 * A Reader implementation, backed by another reader, which can compute the
 * hash of all the read data.
 */
class DigestReader extends Reader
{
    protected $base;
    protected $resource;

    /**
     * Constructs a new DigestReader implementation, reading from the Reader
     * $reader and hashing all data with the algorithm $hashAlgo.
     *
     * @param Reader $reader   A Reader instance.
     * @param string $hashAlgo A hash algorithm name.
     */
    public function __construct(Reader $reader, $hashAlgo)
    {
        $this->base = $reader;
        $this->resource = hash_init($hashAlgo);
    }

    public function read($n): ?string
    {
        $s = $this->base->read($n);

        if ($s !== null) {
            hash_update($this->resource, $s);

            return $s;
        }

        return null;
    }

    public function readToTheEnd(): ?string
    {
        $s = $this->base->readToTheEnd();

        if ($s !== null) {
            hash_update($$this->_resource, $s);

            return $s;
        }

        return null;
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
        return hash_final($this->resource, true);
    }
}
