<?php

declare(strict_types=1);

namespace KeePassPHP\Contracts;

/**
 * An object that can yield a string.
 */
interface BoxedString
{
    /**
     * Gets the boxed string.
     *
     * @return string a string.
     */
    public function getPlainString(): string;
}
