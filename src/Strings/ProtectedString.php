<?php

declare(strict_types=1);

namespace KeePassPHP\Strings;

use KeePassPHP\Contracts\BoxedString;

/**
 * A string protected by a mask to xor.
 */
class ProtectedString implements BoxedString
{
    private $_string;
    private $_random;

    public function __construct($string, $random)
    {
        $this->_string = $string;
        $this->_random = $random;
    }

    /**
     * Gets the real content of the protected string.
     *
     * @return string a string.
     */
    public function getPlainString()
    {
        return $this->_string ^ $this->_random;
    }
}
