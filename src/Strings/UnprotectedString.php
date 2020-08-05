<?php

declare(strict_types=1);

namespace KeePassPHP\Strings;

use KeePassPHP\Contracts\BoxedString;

/**
 * A boxed plain string.
 */
class UnprotectedString implements BoxedString
{
    private $_string;

    public function __construct($string)
    {
        $this->_string = $string;
    }

    /**
     * Gets the boxed string.
     *
     * @return string a string.
     */
    public function getPlainString()
    {
        return $this->_string;
    }
}
