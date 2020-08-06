<?php

declare(strict_types=1);

namespace KeePassPHP\Strings;

use KeePassPHP\Contracts\BoxedString;

/**
 * A boxed plain string.
 */
class UnprotectedString implements BoxedString
{
    protected $string;

    public function __construct(string $string)
    {
        $this->string = $string;
    }

    /**
     * Gets the boxed string.
     *
     * @return string a string.
     */
    public function getPlainString(): string
    {
        return $this->string;
    }
}
