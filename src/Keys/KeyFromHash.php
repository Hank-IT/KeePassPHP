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
     * @param string $hash A raw hash string.
     */
    public function __construct(string $hash)
    {
        $this->hash = $hash;
    }

    /**
     * Retrieves the stored hash.
     *
     * @return string A raw hash string.
     */
    public function getHash(): string
    {
        return $this->hash;
    }
}
