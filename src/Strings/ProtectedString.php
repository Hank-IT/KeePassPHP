<?php

declare(strict_types=1);

namespace KeePassPHP\Strings;

use KeePassPHP\Contracts\BoxedString;

/**
 * A string protected by a mask to xor.
 */
final class ProtectedString implements BoxedString
{
    public function __construct(
        private readonly string $string,
        private readonly string $random,
    ) {}

    /**
     * Gets the real content of the protected string.
     *
     * @return string A string.
     */
    public function getPlainString(): string
    {
        return $this->string ^ $this->random;
    }
}
