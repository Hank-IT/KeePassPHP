<?php

declare(strict_types=1);

namespace KeePassPHP\Keys;

/**
 * An iKey built from a string password.
 */
class KeyFromPassword extends KeyFromHash
{
    /**
     * Constructs a KeyFromPassword instance from the password $pwd.
     *
     * @param string $pwd      A string.
     * @param string $hashAlgo A hash algorithm name.
     */
    public function __construct(string $pwd, string $hashAlgo)
    {
        parent::__construct(hash($hashAlgo, $pwd, true));
    }
}
