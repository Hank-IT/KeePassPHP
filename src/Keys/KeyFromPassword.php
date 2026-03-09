<?php

declare(strict_types=1);

namespace KeePassPHP\Keys;

/**
 * A key derived from a password string.
 */
final class KeyFromPassword extends KeyFromHash
{
    /**
     * @param string $password A password string.
     * @param string $hashAlgo A hash algorithm name.
     *
     * @throws \ValueError If the hash algorithm is not supported.
     */
    public function __construct(string $password, string $hashAlgo)
    {
        parent::__construct(hash($hashAlgo, $password, true));
    }
}
