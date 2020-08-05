<?php

declare(strict_types=1);

namespace KeePassPHP\Readers;

/**
 * A Reader implementation, backed by another reader, which can compute the
 * hash of all the read data.
 */
class DigestReader extends Reader
{
    private $_base;
    private $_resource;

    /**
     * Constructs a new DigestReader implementation, reading from the Reader
     * $reader and hashing all data with the algorithm $hashAlgo.
     *
     * @param Reader $reader   A Reader instance.
     * @param string $hashAlgo A hash algorithm name.
     */
    public function __construct(Reader $reader, $hashAlgo)
    {
        $this->_base = $reader;
        $this->_resource = hash_init($hashAlgo);
    }

    public function read($n)
    {
        $s = $this->_base->read($n);
        if ($s !== null) {
            hash_update($this->_resource, $s);

            return $s;
        }

        return null;
    }

    public function readToTheEnd()
    {
        $s = $this->_base->readToTheEnd();
        if ($s !== null) {
            hash_update($$this->_resource, $s);

            return $s;
        }

        return null;
    }

    public function canRead()
    {
        return $this->_base->canRead();
    }

    public function close()
    {
        $this->_base->close();
    }

    /**
     * Gets the hash of all read data so far.
     *
     * @return string A raw hash string.
     */
    public function GetDigest()
    {
        return hash_final($this->_resource, true);
    }
}
