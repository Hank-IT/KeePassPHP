<?php

declare(strict_types=1);

namespace KeePassPHP\Readers;

/**
 * An implementation of the Reader class, using a string as source.
 */
class StringReader extends Reader
{
    private $_str;
    private $_n;
    private $_pt;

    /**
     * Constructs a new StringReader instance that reads the string $s.
     *
     * @param string $s A non-null string.
     */
    public function __construct($s)
    {
        $this->_str = $s;
        $this->_pt = 0;
        $this->_n = strlen($s);
    }

    public function read($n)
    {
        if (!$this->canRead()) {
            return null;
        }

        $t = min($n, $this->_n - $this->_pt);
        $res = substr($this->_str, $this->_pt, $t);
        $this->_pt += $t;

        return $res;
    }

    public function canRead()
    {
        return $this->_pt < $this->_n;
    }

    public function readToTheEnd()
    {
        if (!$this->canRead()) {
            return null;
        }

        $res = substr($this->_str, $this->_pt);
        $this->_pt = $this->_n;

        return $res;
    }

    public function close()
    {
        $this->_str = null;
        $this->_n = 0;
        $this->_pt = 0;
    }
}
