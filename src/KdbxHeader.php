<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Readers\DigestReader;
use KeePassPHP\Readers\Reader;

/**
 * This class represents the header of a Kdbx file, which is the un-encrypted
 * part of the file containing information on the encrypted content, on
 * how to decrypt it, and some integrity data.
 */
final class KdbxHeader
{
    public const string SIGNATURE1 = "\x03\xD9\xA2\x9A";
    public const string SIGNATURE2 = "\x67\xFB\x4B\xB5";
    public const string VERSION = "\x01\x00\x03\x00";
    public const int MAXIMAL_VERSION = 3;

    public const string CIPHER_AES = "\x31\xC1\xF2\xE6\xBF\x71\x43\x50\xBE\x58\x05\x21\x6A\xFC\x5A\xFF";

    public const int COMPRESSION_NONE = 1;
    public const int COMPRESSION_GZIP = 2;
    public const int RANDOMSTREAM_NONE = 1;
    public const int RANDOMSTREAM_SALSA20 = 3;

    public const string INT_0 = "\x00\x00\x00\x00";
    public const string INT_1 = "\x01\x00\x00\x00";
    public const string INT_2 = "\x02\x00\x00\x00";

    public ?string $cipher = null;
    public int $compression = 0;
    public ?string $masterSeed = null;
    public ?string $transformSeed = null;
    public ?string $rounds = null;
    public ?string $encryptionIV = null;
    public ?string $randomStreamKey = null;
    public ?string $startBytes = null;
    public int $randomStream = 0;
    public ?string $headerHash = null;

    public function toBinary(string $hashAlgo): string
    {
        $binary = self::SIGNATURE1 . self::SIGNATURE2 . self::VERSION
            . self::fieldToString(2, $this->cipher)
            . self::fieldToString(
                3,
                $this->compression === self::COMPRESSION_GZIP ? self::INT_1 : self::INT_0
            )
            . self::fieldToString(4, $this->masterSeed)
            . self::fieldToString(5, $this->transformSeed)
            . self::fieldToString(6, $this->rounds)
            . self::fieldToString(7, $this->encryptionIV)
            . self::fieldToString(8, $this->randomStreamKey)
            . self::fieldToString(9, $this->startBytes)
            . self::fieldToString(
                10,
                $this->randomStream === self::RANDOMSTREAM_SALSA20 ? self::INT_2 : self::INT_0
            )
            . self::fieldToString(0, null);

        $this->headerHash = hash($hashAlgo, $binary, true);

        return $binary;
    }

    private static function fieldToString(int $id, ?string $value): string
    {
        $value ??= '';
        $length = strlen($value);

        return chr($id) . ($length === 0 ? "\x00\x00" : pack('v', $length) . $value);
    }

    public function check(): bool
    {
        return $this->cipher !== null
            && $this->compression !== 0
            && $this->masterSeed !== null
            && $this->transformSeed !== null
            && $this->rounds !== null
            && $this->encryptionIV !== null
            && $this->startBytes !== null
            && $this->headerHash !== null
            && $this->randomStreamKey !== null
            && $this->randomStream !== 0;
    }

    public static function fromReader(Reader $reader, string $hashAlgo): self
    {
        $digestReader = new DigestReader($reader, $hashAlgo);

        $sig1 = $digestReader->read(4);
        $sig2 = $digestReader->read(4);
        if ($sig1 !== self::SIGNATURE1 || $sig2 !== self::SIGNATURE2) {
            throw new KeePassPHPException('Kdbx header: signature not correct.');
        }

        $digestReader->readNumber(2);
        $upperVersion = $digestReader->readNumber(2);
        if ($upperVersion > self::MAXIMAL_VERSION) {
            throw new KeePassPHPException('Kdbx header: version not supported.');
        }

        $header = new self();
        $ended = false;

        while (! $ended) {
            $fieldId = $digestReader->readByte();
            $fieldLength = $digestReader->readNumber(2);
            $field = null;

            if ($fieldLength > 0) {
                $field = $digestReader->read($fieldLength);
                if ($field === null || strlen($field) !== $fieldLength) {
                    throw new KeePassPHPException('Kdbx header: incomplete header field.');
                }
            }

            if ($fieldId === 0) {
                $ended = true;
                continue;
            }

            $header->assignField($fieldId, $field);
        }

        $header->headerHash = $digestReader->getDigest();

        return $header;
    }

    private function assignField(int $fieldId, ?string $field): void
    {
        match ($fieldId) {
            2 => $this->cipher = $field,
            3 => $this->compression = match ($field) {
                self::INT_0 => self::COMPRESSION_NONE,
                self::INT_1 => self::COMPRESSION_GZIP,
                default => $this->compression,
            },
            4 => $this->masterSeed = $field,
            5 => $this->transformSeed = $field,
            6 => $this->rounds = $field,
            7 => $this->encryptionIV = $field,
            8 => $this->randomStreamKey = $field,
            9 => $this->startBytes = $field,
            10 => $this->randomStream = match ($field) {
                self::INT_0 => self::RANDOMSTREAM_NONE,
                self::INT_2 => self::RANDOMSTREAM_SALSA20,
                default => $this->randomStream,
            },
            default => null,
        };
    }
}
