<?php

declare(strict_types=1);

namespace KeePassPHP\Keys;

use KeePassPHP\Contracts\Key;

/**
 * A KeePass composite key, used in the decryption of a kdbx file. It takes
 * several iKeys and hashes all of them toghether to build the composite key.
 */
class CompositeKey implements Key
{
    private $_keys;
    private $_hashAlgo;

    /**
     * Constructs a new CompositeKey instance using $hashAlgo to hash all
     * keys all together.
     * @param string $hashAlgo A hash algorithm name.
     */
    public function __construct($hashAlgo)
    {
        $this->_keys = array();
        $this->_hashAlgo = $hashAlgo;
    }

    /**
     * Adds the given key $key to this CompositeKey.
     * @param Key $key An iKey instance to add.
     */
    public function addKey(Key $key)
    {
        array_push($this->_keys, $key->getHash());
    }

    /**
     * Computes the hash of all the keys of this CompositeKey.
     * @return string A raw hash string.
     */
    public function getHash()
    {
        $h = hash_init($this->_hashAlgo);
        foreach($this->_keys as &$v)
            hash_update($h, $v);
        $r = hash_final($h, true);
        unset($h);
        return $r;
    }
}