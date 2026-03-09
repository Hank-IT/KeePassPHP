<?php

declare(strict_types=1);

namespace KeePassPHP\Keys;

use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\ProtectedXMLReader;

/**
 * A key built from a KeePass key file. Supports XML, binary, hex, and
 * arbitrary-file key material.
 */
class KeyFromFile extends KeyFromHash
{
    public const string XML_ROOT = 'KeyFile';
    public const string XML_KEY = 'Key';
    public const string XML_META = 'Meta';
    public const string XML_VERSION = 'Version';
    public const string XML_DATA = 'Data';
    public const string XML_DATA_HASH = 'Hash';
    private const int XML_DATA_HASH_BYTES = 4;

    /**
     * @throws KeePassPHPException
     */
    public function __construct(string $content)
    {
        parent::__construct($this->parse($content));
    }

    /**
     * @throws KeePassPHPException
     */
    private function parse(string $content): string
    {
        if ($this->looksLikeXml($content)) {
            return $this->parseXml($content);
        }

        return $this->parseRawOrHex($content) ?? $this->hashFileContent($content);
    }

    private function parseRawOrHex(string $content): ?string
    {
        if (strlen($content) === 32) {
            return $content;
        }

        if (strlen($content) === 64) {
            $decoded = hex2bin($content);
            if ($decoded !== false) {
                return $decoded;
            }
        }

        return null;
    }

    private function hashFileContent(string $content): string
    {
        return hash('sha256', $content, true);
    }

    /**
     * @throws KeePassPHPException
     */
    private function parseXml(string $content): string
    {
        $xml = new ProtectedXMLReader();
        if (! $xml->XML($content) || ! $xml->read(-1)) {
            throw new KeePassPHPException('Key file parse: invalid XML content.');
        }

        if (! $xml->isElement(self::XML_ROOT)) {
            $xml->close();

            throw new KeePassPHPException(sprintf('Key file parse: root element must be %s.', self::XML_ROOT));
        }

        try {
            $depth = $xml->depth();
            $version = null;

            while ($xml->read($depth)) {
                if ($xml->isElement(self::XML_META)) {
                    $metaDepth = $xml->depth();
                    while ($xml->read($metaDepth)) {
                        if ($xml->isElement(self::XML_VERSION)) {
                            $versionValue = $xml->readTextInside();
                            $version = is_string($versionValue) ? $versionValue : null;
                        }
                    }
                }

                if ($xml->isElement(self::XML_KEY)) {
                    $keyDepth = $xml->depth();
                    while ($xml->read($keyDepth)) {
                        if ($xml->isElement(self::XML_DATA)) {
                            $integrityHash = $xml->getAttribute(self::XML_DATA_HASH);
                            $value = $xml->readTextInside();
                            if (! is_string($value)) {
                                throw new KeePassPHPException('Key file parse: missing key data.');
                            }

                            $majorVersion = $this->parseVersionMajor($version);
                            if ($majorVersion === 1) {
                                $decoded = base64_decode($value, true);
                                if ($decoded === false) {
                                    throw new KeePassPHPException('Key file parse: invalid base64 key data.');
                                }

                                return $decoded;
                            }

                            if ($majorVersion === 2) {
                                $decoded = hex2bin((string) preg_replace('/\s+/m', '', $value));
                                if ($decoded === false) {
                                    throw new KeePassPHPException('Key file parse: invalid hexadecimal key data.');
                                }

                                if (! $this->verifyIntegrityHash($decoded, $integrityHash)) {
                                    throw new KeePassPHPException('Key file parse: key data integrity hash mismatch.');
                                }

                                return $decoded;
                            }

                            throw new KeePassPHPException(
                                sprintf('Key file parse: unsupported XML key file version %s.', (string) $version)
                            );
                        }
                    }
                }
            }
        } finally {
            $xml->close();
        }

        throw new KeePassPHPException('Key file parse: missing key data element.');
    }

    private function looksLikeXml(string $content): bool
    {
        return str_starts_with(ltrim($content), '<');
    }

    private function parseVersionMajor(?string $version): ?int
    {
        if ($version === null) {
            return null;
        }

        if (! preg_match('/^\s*(\d+)(?:\.\d+)?\s*$/', $version, $matches)) {
            return null;
        }

        return (int) $matches[1];
    }

    private function verifyIntegrityHash(string $decoded, ?string $integrityHash): bool
    {
        if ($integrityHash === null || $integrityHash === '') {
            return true;
        }

        $normalizedHash = strtoupper(trim($integrityHash));
        if (! preg_match('/^[0-9A-F]{8}$/', $normalizedHash)) {
            return false;
        }

        $expectedHash = strtoupper(substr(hash('sha256', $decoded), 0, self::XML_DATA_HASH_BYTES * 2));

        return hash_equals($expectedHash, $normalizedHash);
    }
}
