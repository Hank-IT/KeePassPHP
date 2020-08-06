<?php

declare(strict_types=1);

namespace KeePassPHP\Readers;

/**
 * An implementation of the Reader class, using a string as source.
 */
class StringReader extends Reader
{
    protected $str;
    protected $n;
    protected $pt;

    /**
     * Constructs a new StringReader instance that reads the string $s.
     *
     * @param string $s A non-null string.
     */
    public function __construct($s)
    {
        $this->str = $s;
        $this->pt = 0;
        $this->n = strlen($s);
    }

    public function read($n): ?string
    {
        if (!$this->canRead()) {
            return null;
        }

        $t = min($n, $this->n - $this->pt);
        $res = substr($this->str, $this->pt, $t);
        $this->pt += $t;

        return $res;
    }

    public function canRead(): bool
    {
        return $this->pt < $this->n;
    }

    public function readToTheEnd(): ?string
    {
        if (!$this->canRead()) {
            return null;
        }

        $res = substr($this->str, $this->pt);
        $this->pt = $this->n;

        return $res;
    }

    public function close(): void
    {
        $this->str = null;
        $this->n = 0;
        $this->pt = 0;
    }
}
