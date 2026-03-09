<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Readers\Reader;
use KeePassPHP\Readers\StringReader;

final class Kdbx4Header
{
    public const string SIGNATURE1 = "\x03\xD9\xA2\x9A";
    public const string SIGNATURE2 = "\x67\xFB\x4B\xB5";
    public const string HEADER_END = "\x0D\x0A\x0D\x0A";

    public const string CIPHER_AES = "\x31\xC1\xF2\xE6\xBF\x71\x43\x50\xBE\x58\x05\x21\x6A\xFC\x5A\xFF";
    public const string CIPHER_CHACHA20 = "\xD6\x03\x8A\x2B\x8B\x6F\x4C\xB5\xA5\x24\x33\x9A\x31\xDB\xB5\x9A";

    public const string KDF_AES = "\xC9\xD9\xF3\x9A\x62\x8A\x44\x60\xBF\x74\x0D\x08\xC1\x8A\x4F\xEA";
    public const string KDF_ARGON2D = "\xEF\x63\x6D\xDF\x8C\x29\x44\x4B\x91\xF7\xA9\xA4\x03\xE3\x0A\x0C";
    public const string KDF_ARGON2ID = "\x9E\x29\x8B\x19\x56\xDB\x47\x73\xB2\x3D\xFC\x3E\xC6\xF0\xA1\xE6";

    public const int COMPRESSION_NONE = 1;
    public const int COMPRESSION_GZIP = 2;

    public int $formatVersion = 0;
    public int $majorVersion = 0;
    public int $minorVersion = 0;
    public ?string $cipher = null;
    public int $compression = 0;
    public ?string $masterSeed = null;
    public ?string $encryptionIV = null;

    /** @var array<string, bool|int|string> */
    public array $kdfParameters = [];

    private string $binary = '';

    public static function fromBinary(string $binary): self
    {
        return self::fromReader(new StringReader($binary));
    }

    public static function fromReader(Reader $reader): self
    {
        $binary = self::readExact($reader, 8, 'Kdbx4 header: signature is incomplete.');
        if (substr($binary, 0, 4) !== self::SIGNATURE1 || substr($binary, 4, 4) !== self::SIGNATURE2) {
            throw new KeePassPHPException('Kdbx4 header: signature not correct.');
        }

        $formatVersionBytes = self::readExact($reader, 4, 'Kdbx4 header: format version is incomplete.');
        $binary .= $formatVersionBytes;

        $formatVersion = unpack('V', $formatVersionBytes);
        if ($formatVersion === false || !isset($formatVersion[1]) || !is_int($formatVersion[1])) {
            throw new KeePassPHPException('Kdbx4 header: invalid format version.');
        }

        $header = new self();
        $header->binary = $binary;
        $header->formatVersion = $formatVersion[1];
        $header->majorVersion = ($formatVersion[1] >> 16) & 0xFFFF;
        $header->minorVersion = $formatVersion[1] & 0xFFFF;

        if ($header->majorVersion !== 4) {
            throw new KeePassPHPException('Kdbx4 header: version not supported.');
        }

        while (true) {
            $fieldIdBytes = self::readExact($reader, 1, 'Kdbx4 header: field ID is incomplete.');
            $fieldLengthBytes = self::readExact($reader, 4, 'Kdbx4 header: field length is incomplete.');

            $fieldLength = unpack('V', $fieldLengthBytes);
            if ($fieldLength === false || !isset($fieldLength[1]) || !is_int($fieldLength[1])) {
                throw new KeePassPHPException('Kdbx4 header: invalid field length.');
            }

            $fieldValue = self::readExact(
                $reader,
                $fieldLength[1],
                'Kdbx4 header: incomplete header field.'
            );

            $header->binary .= $fieldIdBytes . $fieldLengthBytes . $fieldValue;
            $fieldId = ord($fieldIdBytes);

            if ($fieldId === 0) {
                if ($fieldValue !== self::HEADER_END) {
                    throw new KeePassPHPException('Kdbx4 header: invalid end-of-header marker.');
                }

                break;
            }

            $header->assignField($fieldId, $fieldValue);
        }

        return $header;
    }

    public function getBinary(): string
    {
        return $this->binary;
    }

    public function getKdfUuid(): ?string
    {
        $uuid = $this->kdfParameters['$UUID'] ?? null;

        return is_string($uuid) ? $uuid : null;
    }

    public function check(): bool
    {
        return $this->cipher !== null
            && $this->compression !== 0
            && $this->masterSeed !== null
            && $this->encryptionIV !== null
            && $this->getKdfUuid() !== null;
    }

    private function assignField(int $fieldId, string $field): void
    {
        match ($fieldId) {
            2 => $this->cipher = $field,
            3 => $this->compression = match (self::unpackInt32($field, 'compression')) {
                0 => self::COMPRESSION_NONE,
                1 => self::COMPRESSION_GZIP,
                default => 0,
            },
            4 => $this->masterSeed = $field,
            7 => $this->encryptionIV = $field,
            11 => $this->kdfParameters = KdbxVariantDictionary::parse($field),
            default => null,
        };
    }

    /**
     * @throws KeePassPHPException
     */
    private static function readExact(Reader $reader, int $length, string $error): string
    {
        if ($length === 0) {
            return '';
        }

        $bytes = $reader->read($length);
        if ($bytes === null || strlen($bytes) !== $length) {
            throw new KeePassPHPException($error);
        }

        return $bytes;
    }

    /**
     * @throws KeePassPHPException
     */
    private static function unpackInt32(string $bytes, string $fieldName): int
    {
        if (strlen($bytes) !== 4) {
            throw new KeePassPHPException(sprintf('Kdbx4 header: invalid %s field.', $fieldName));
        }

        $value = unpack('V', $bytes);
        if ($value === false || !isset($value[1]) || !is_int($value[1])) {
            throw new KeePassPHPException(sprintf('Kdbx4 header: invalid %s field.', $fieldName));
        }

        return $value[1];
    }
}
