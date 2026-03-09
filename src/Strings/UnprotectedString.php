<?php

declare(strict_types=1);

namespace KeePassPHP\Strings;

use KeePassPHP\Contracts\BoxedString;

/**
 * A boxed plain string.
 */
final class UnprotectedString implements BoxedString
{
    public function __construct(private readonly string $string) {}

    /**
     * Gets the boxed string.
     *
     * @return string A string.
     */
    public function getPlainString(): string
    {
        return $this->string;
    }
}
