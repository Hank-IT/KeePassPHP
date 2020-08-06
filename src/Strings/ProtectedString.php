<?php

declare(strict_types=1);

namespace KeePassPHP\Strings;

use KeePassPHP\Contracts\BoxedString;

/**
 * A string protected by a mask to xor.
 */
class ProtectedString implements BoxedString
{
    protected $string;
    protected $random;

    public function __construct(string $string, string $random)
    {
        $this->string = $string;

        $this->random = $random;
    }

    /**
     * Gets the real content of the protected string.
     *
     * @return string a string.
     */
    public function getPlainString(): string
    {
        return $this->string ^ $this->random;
    }
}
