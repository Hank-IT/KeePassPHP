<?php

declare(strict_types=1);

namespace KeePassPHP\Keys;

use KeePassPHP\Contracts\Key;

/**
 * An iKey built from something already hashed.
 */
class KeyFromHash implements Key
{
    /**
     * Stores the given hash string.
     *
     * @param string $hash A raw hash string.
     */
    public function __construct(protected readonly string $hash) {}

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
