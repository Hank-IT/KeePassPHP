<?php

declare(strict_types=1);

namespace KeePassPHP\Keys;

use KeePassPHP\ProtectedXMLReader;

/**
 * An iKey built from a KeePass key file. Supports XML, binary and hex files.
 * If the parsing of the file is successful, the property $isParsed is set to
 * true, and false otherwise; its value must then be checked when a new
 * KeyFromFile object is created, to see whether something went wrong or not:
 * if it false, the hash that this object may return will probably mean
 * nothing.
 */
class KeyFromFile extends KeyFromHash
{
    const XML_ROOT = 'KeyFile';
    const XML_KEY = 'Key';
    const XML_DATA = 'Data';

    public $isParsed = false;

    /**
     * Tries to parse $content to find the hash inside. If the parsing is
     * successfully, the property $this->isParsed is set to true.
     *
     * @param string $content A key file content.
     */
    public function __construct($content)
    {
        $this->isParsed = $this->tryParseXML($content) || $this->tryParse($content);
    }

    /**
     * Tries to parse $content as a binary or a hex key file.
     *
     * @param string $content A key file content.
     *
     * @return bool in case of success, false otherwise.
     */
    protected function tryParse($content)
    {
        if (strlen($content) == 32) {
            $this->hash = $content;

            return true;
        }

        if (strlen($content) == 64) {
            $this->hash = hex2bin($content);

            return true;
        }

        return false;
    }

    /**
     * Tries to parse $content as a KeePass XML key file.
     *
     * @param string $content A key file content.
     *
     * @return bool in case of success, false otherwise.
     */
    protected function tryParseXML($content)
    {
        $xml = new ProtectedXMLReader(null);

        if (! $xml->XML($content) || ! $xml->read(-1)) {
            return false;
        }

        if ($xml->isElement(self::XML_ROOT)) {
            $d = $xml->depth();
            while ($xml->read($d)) {
                if ($xml->isElement(self::XML_KEY)) {
                    $keyD = $xml->depth();
                    while ($xml->read($keyD)) {
                        if ($xml->isElement(self::XML_DATA)) {
                            $value = $xml->readTextInside();
                            $this->hash = base64_decode($value);
                            $xml->close();

                            return true;
                        }
                    }
                }
            }
        }
        $xml->close();

        return false;
    }
}
