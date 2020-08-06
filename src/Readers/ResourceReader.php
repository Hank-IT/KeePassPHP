<?php

declare(strict_types=1);

namespace KeePassPHP\Readers;

/**
 * A Reader implementation reading from a PHP resource pointer (such as a
 * pointer obtained through the function fopen).
 */
class ResourceReader extends Reader
{
    private $_res;

    /**
     * Constructs a new ResourceReader instance that reads the PHP resource
     * pointer $f.
     *
     * @param resource $f A PHP resource pointer.
     */
    protected function __construct($f)
    {
        $this->_res = $f;
    }

    /**
     * Creates a new ResourceReader instance reading the file $path.
     *
     * @param string $path A file path.
     *
     * @return static A new ResourceReader instance if $path could be opened and is
     *                readable, false otherwise.
     */
    public static function openFile($path)
    {
        if (is_readable($path)) {
            $f = fopen($path, 'rb');
            if ($f !== false) {
                return new static($f);
            }
        }

        return null;
    }

    public function read($n): ?string
    {
        if ($this->canRead()) {
            $s = fread($this->_res, $n);
            if ($s !== false) {
                return $s;
            }
        }

        return null;
    }

    public function readToTheEnd(): ?string
    {
        if (!$this->canRead()) {
            return null;
        }

        ob_start();
        fpassthru($this->_res);
        $r = ob_get_contents();
        ob_end_clean();

        return $r;
    }

    public function canRead(): bool
    {
        return !feof($this->_res);
    }

    public function close(): void
    {
        fclose($this->_res);
    }
}
