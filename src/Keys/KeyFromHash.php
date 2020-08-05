<?php

declare(strict_types=1);

namespace KeePassPHP\Keys;

use KeePassPHP\Contracts\Key;

/**
 * An iKey built from something already hashed.
 */
class KeyFromHash implements Key
{
    protected $hash;

    /**
     * Stores the given hash string.
     *
     * @param string $h A raw hash string.
     */
    public function __construct($h)
    {
        $this->hash = $h;
    }

    /**
     * Retrieves the stored hash.
     *
     * @return string A raw hash string.
     */
    public function getHash()
    {
        return $this->hash;
    }
}
