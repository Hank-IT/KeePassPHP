<?php

declare(strict_types=1);

namespace KeePassPHP\Readers;

/**
 * A Reader implementation, backed by another reader, decoding a stream made
 * of hashed blocks (used by KeePass). More precisely, it is a sequence of
 * blocks, each block containing some data and a hash of this data, in order to
 * control its integrity. The format of a block is the following:
 * - 4 bytes (little-endian integer): block index (starting from 0)
 * - 32 bytes: hash of the block data
 * - 4 bytes (little-endian integer): length (in bytes) of the block data
 * - n bytes: block data (where n is the number found previously).
 */
class HashedBlockReader extends Reader
{
    protected $base;
    protected $hashAlgo;
    protected $hasError;
    protected $stopOnError;
    protected $currentIndex;
    protected $currentBlock;
    protected $currentSize;
    protected $currentPos;

    /**
     * Default block size used by KeePass.
     */
    const DEFAULT_BLOCK_SIZE = 1048576; // 1024*1024

    /**
     * Constructs a new HashedBlockReader instance, reading from the reader
     * $reader and using the algorithm $hashAlgo to compute block hashs.
     *
     * @param Reader $reader      A Reader instance.
     * @param string $hashAlgo    A hash algorithm name.
     * @param bool   $stopOnError Whether to stop reading immediatly when an integrity
     *                            check fails. If set to false, reading will continue after an
     *                            error but it may well be complete garbage.
     */
    public function __construct(Reader $reader, string $hashAlgo, bool $stopOnError = true)
    {
        $this->base = $reader;
        $this->hashAlgo = $hashAlgo;
        $this->stopOnError = $stopOnError;
        $this->hasError = false;
        $this->currentIndex = 0;
        $this->currentBlock = null;
        $this->currentSize = 0;
        $this->currentPos = 0;
    }

    public function read($n): ?string
    {
        $s = '';
        $remaining = $n;
        while ($remaining > 0) {
            if ($this->currentPos >= $this->currentSize) {
                if (!$this->readBlock()) {
                    return $s;
                }
            }
            $t = min($remaining, $this->currentSize - $this->currentPos);
            $s .= substr($this->currentBlock, $this->currentPos, $t);
            $this->currentPos += $t;
            $remaining -= $t;
        }

        return $s;
    }

    public function readToTheEnd(): ?string
    {
        $s = $this->read($this->currentSize - $this->currentPos);
        while ($this->readBlock()) {
            $s .= $this->currentBlock;
        }

        return $s;
    }

    public function canRead(): bool
    {
        return (!$this->hasError || !$this->stopOnError) &&
            $this->base->canRead();
    }

    public function close(): void
    {
        $this->base->close();
    }

    /**
     * Whether this instance data is corrupted.
     *
     * @return bool true if the data read so far is corrupted, false otherwise.
     */
    public function isCorrupted(): bool
    {
        return $this->hasError;
    }

    protected function readBlock(): bool
    {
        if (!$this->canRead()) {
            return false;
        }

        $bl = $this->base->read(4);
        if ($bl != pack('V', $this->currentIndex)) {
            $this->hasError = true;
            if ($this->stopOnError) {
                return false;
            }
        }
        $this->currentIndex++;

        $hash = $this->base->read(32);
        if (strlen($hash) != 32) {
            $this->hasError = true;

            return false;
        }

        // May not work on 32 bit platforms if $blockSize is greather
        // than 2**31, but in KeePass implementation it is set at 2**20.
        $blockSize = $this->base->readNumber(4);
        if ($blockSize <= 0) {
            return false;
        }

        $block = $this->base->read($blockSize);
        if (strlen($block) != $blockSize) {
            $this->hasError = true;

            return false;
        }

        if ($hash !== hash($this->hashAlgo, $block, true)) {
            $this->hasError = true;
            if ($this->stopOnError) {
                return false;
            }
        }

        $this->currentBlock = $block;
        $this->currentSize = $blockSize;
        $this->currentPos = 0;

        return true;
    }

    /**
     * Computes the hashed-by-blocks version of the string $source: splits it
     * in blocks, computes each block hash, and concats everything together in
     * a string that can be read again with a HashedBlockReader instance.
     *
     * @param string $source   The string to hash by blocks.
     * @param string $hashAlgo A hash algorithm name.
     *
     * @return string The hashed-by-blocks version of $source.
     */
    public static function hashString(string $source, string $hashAlgo): string
    {
        $len = strlen($source);
        $blockSize = self::DEFAULT_BLOCK_SIZE;
        $binBlockSize = pack('V', $blockSize);
        $r = '';

        $blockIndex = 0;
        $i = 0;
        while ($len >= $i + $blockSize) {
            $block = substr($source, $i, $blockSize);
            $r .= pack('V', $blockIndex)
                .hash($hashAlgo, $block, true)
                .$binBlockSize
                .$block;
            $i += $blockSize;
            $blockIndex++;
        }
        $rem = $len - $i;
        if ($rem != 0) {
            $block = substr($source, $i);
            $r .= pack('V', $blockIndex)
                .hash($hashAlgo, $block, true)
                .pack('V', strlen($block))
                .$block;
        }

        return $r;
    }
}
