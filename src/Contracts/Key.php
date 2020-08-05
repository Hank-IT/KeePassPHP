<?php

declare(strict_types=1);

namespace KeePassPHP\Contracts;

/**
 * An object that contains a secret in the form of a hash.
 */
interface Key
{
    /**
     * Gets this instance hash.
     *
     * @return string A raw hash string.
     */
    public function getHash();
}
