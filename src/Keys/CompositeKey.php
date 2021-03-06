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
    protected $keys;
    protected $hashAlgo;

    /**
     * Constructs a new CompositeKey instance using $hashAlgo to hash all
     * keys all together.
     *
     * @param string $hashAlgo A hash algorithm name.
     */
    public function __construct($hashAlgo)
    {
        $this->keys = [];
        $this->hashAlgo = $hashAlgo;
    }

    /**
     * Adds the given key $key to this CompositeKey.
     *
     * @param Key $key An iKey instance to add.
     */
    public function addKey(Key $key)
    {
        array_push($this->keys, $key->getHash());
    }

    /**
     * Computes the hash of all the keys of this CompositeKey.
     *
     * @return string A raw hash string.
     */
    public function getHash(): string
    {
        $h = hash_init($this->hashAlgo);
        foreach ($this->keys as &$v) {
            hash_update($h, $v);
        }
        $r = hash_final($h, true);
        unset($h);

        return $r;
    }
}
