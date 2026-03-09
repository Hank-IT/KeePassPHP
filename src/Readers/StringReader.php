<?php

declare(strict_types=1);

namespace KeePassPHP\Readers;

/**
 * An implementation of the Reader class, using a string as source.
 */
final class StringReader extends Reader
{
    protected ?string $source;
    protected int $length;
    protected int $position = 0;

    /**
     * Constructs a new StringReader instance that reads the string $source.
     *
     * @param string $source A source string.
     */
    public function __construct(string $source)
    {
        $this->source = $source;
        $this->length = strlen($source);
    }

    public function read(int $n): ?string
    {
        if ($n < 1) {
            return '';
        }

        if (!$this->canRead()) {
            return null;
        }

        $source = $this->source;
        if ($source === null) {
            return null;
        }

        $chunkLength = min($n, $this->length - $this->position);
        $chunk = substr($source, $this->position, $chunkLength);
        $this->position += $chunkLength;

        return $chunk;
    }

    public function canRead(): bool
    {
        return $this->source !== null && $this->position < $this->length;
    }

    public function readToTheEnd(): ?string
    {
        if (!$this->canRead()) {
            return null;
        }

        $source = $this->source;
        if ($source === null) {
            return null;
        }

        $remaining = substr($source, $this->position);
        $this->position = $this->length;

        return $remaining;
    }

    public function close(): void
    {
        $this->source = null;
        $this->length = 0;
        $this->position = 0;
    }
}
