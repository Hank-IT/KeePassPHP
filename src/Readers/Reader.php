<?php

declare(strict_types=1);

namespace KeePassPHP\Readers;

/**
 * Base class for all readers.
 *
 * Instances of this class can read bytes from a source until no more can be
 * produced. The backing data source can be a string, a file, a network
 * resource, or a transformation of another reader.
 */
abstract class Reader
{
    /**
     * Checks whether more bytes can be read from this instance.
     *
     * @return bool True if more bytes can be read, false otherwise.
     */
    abstract public function canRead(): bool;

    /**
     * Tries to read up to $n bytes from this instance.
     *
     * If the result contains fewer than $n bytes, the underlying byte stream
     * has ended and no further bytes can be read.
     *
     * @return string A string containing at most $n bytes, or null if no more bytes can be read.
     */
    abstract public function read(int $n): ?string;

    /**
     * Reads all remaining bytes from this instance.
     *
     * @return string|null A string containing all remaining bytes, or null if
     *                     no more bytes can be read.
     */
    abstract public function readToTheEnd(): ?string;

    /**
     * Closes this instance, possibly dismissing the resources it was using.
     */
    abstract public function close(): void;

    /**
     * Tries to read up to $n bytes from this instance and return them as a
     * little-endian integer.
     *
     * Depending on the platform, PHP may not be able to correctly handle
     * integers greater than 2**31.
     *
     * @return int At most $n bytes encoded into one integer, or 0 if no more
     *             bytes can be read.
     */
    final public function readNumber(int $n): int
    {
        $bytes = $this->read($n);
        if ($bytes === null || $bytes === '') {
            return 0;
        }

        $length = strlen($bytes);
        $value = 0;
        for ($i = 0; $i < $length; $i++) {
            $value |= ord($bytes[$i]) << (8 * $i);
        }

        return $value;
    }

    /**
     * Tries to read one (1) byte from this instance, and return it as an integer.
     *
     * @return int One read byte as an integer, or 0 if no more bytes can be read.
     */
    final public function readByte(): int
    {
        $byte = $this->read(1);

        return $byte === null || $byte === '' ? 0 : ord($byte[0]);
    }
}
