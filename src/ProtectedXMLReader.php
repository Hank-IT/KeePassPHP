<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Contracts\BoxedString;
use KeePassPHP\Contracts\RandomStream;
use KeePassPHP\Strings\ProtectedString;
use KeePassPHP\Strings\UnprotectedString;
use XMLReader;

/**
 * An XML reader with specific methods to ignore non-Element or text nodes,
 * and parse KeePass-style "protected" strings.
 */
final class ProtectedXMLReader
{
    private const int STOP = 0;
    private const int GO_ON = 1;
    private const int DO_NOT_READ = 2;

    public const string XML_ATTR_PROTECTED = 'Protected';

    private readonly XMLReader $reader;
    private int $state = self::GO_ON;

    public function __construct(private readonly ?RandomStream $randomStream = null)
    {
        $this->reader = new XMLReader();
    }

    public function open(string $file): bool
    {
        return is_file($file) && $this->reader->open($file, 'UTF-8') === true;
    }

    public function XML(string $src): bool
    {
        return $this->reader->XML($src, 'UTF-8') === true;
    }

    public function close(): bool
    {
        return $this->reader->close();
    }

    public function depth(): int
    {
        return $this->reader->depth;
    }

    public function isElement(string $name): bool
    {
        return strcasecmp($name, $this->reader->name) === 0;
    }

    public function getAttribute(string $name): ?string
    {
        return $this->reader->getAttribute($name);
    }

    public function read(int $depth): bool
    {
        if ($this->state === self::STOP) {
            return false;
        }

        if ($this->state === self::GO_ON) {
            do {
                if (! $this->reader->read()) {
                    $this->state = self::STOP;

                    return false;
                }
            } while ($this->reader->nodeType !== XMLReader::ELEMENT);
        }

        if ($this->reader->depth > $depth) {
            $this->state = self::GO_ON;

            return true;
        }

        $this->state = self::DO_NOT_READ;

        return false;
    }

    public function readTextInside(bool $asProtectedString = false): BoxedString|string|null
    {
        if ($this->state !== self::GO_ON || $this->reader->isEmptyElement) {
            return null;
        }

        $isProtected = $this->reader->hasAttributes
            && self::isXmlBooleanTrue($this->reader->getAttribute(self::XML_ATTR_PROTECTED));

        if (! $this->reader->read()) {
            $this->state = self::STOP;

            return null;
        }

        if ($this->reader->nodeType === XMLReader::TEXT || $this->reader->nodeType === XMLReader::CDATA) {
            return $this->decodeTextValue($this->reader->value, $isProtected, $asProtectedString);
        }

        if ($this->reader->nodeType === XMLReader::ELEMENT) {
            $this->state = self::DO_NOT_READ;
        }

        return null;
    }

    private function decodeTextValue(string $value, bool $isProtected, bool $asProtectedString): BoxedString|string|null
    {
        if (! $isProtected || $value === '' || $this->randomStream === null) {
            return $asProtectedString ? new UnprotectedString($value) : $value;
        }

        $decodedValue = base64_decode($value, true);
        if ($decodedValue === false) {
            return null;
        }

        $random = $this->randomStream->getNextBytes(strlen($decodedValue));

        return $asProtectedString
            ? new ProtectedString($decodedValue, $random)
            : ($decodedValue ^ $random);
    }

    private static function isXmlBooleanTrue(?string $value): bool
    {
        return $value !== null
            && (
                strcasecmp($value, 'true') === 0
                || $value === '1'
            );
    }
}
