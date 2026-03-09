<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Exceptions\KeePassPHPException;

final class KdbxVariantDictionary
{
    /**
     * @return array<string, bool|int|string>
     * @throws KeePassPHPException
     */
    public static function parse(string $bytes): array
    {
        $offset = 0;
        if (strlen($bytes) < 2) {
            throw new KeePassPHPException('KDBX: invalid variant dictionary header.');
        }

        $version = unpack('v', substr($bytes, $offset, 2));
        $offset += 2;
        if ($version === false || !isset($version[1]) || !is_int($version[1])) {
            throw new KeePassPHPException('KDBX: invalid variant dictionary version.');
        }

        $result = [];
        $length = strlen($bytes);

        while ($offset < $length) {
            $type = ord($bytes[$offset]);
            $offset++;

            if ($type === 0) {
                break;
            }

            $nameLength = self::readInt32($bytes, $offset);
            $name = substr($bytes, $offset, $nameLength);
            if (strlen($name) !== $nameLength) {
                throw new KeePassPHPException('KDBX: truncated variant dictionary name.');
            }
            $offset += $nameLength;

            $valueLength = self::readInt32($bytes, $offset);
            $valueBytes = substr($bytes, $offset, $valueLength);
            if (strlen($valueBytes) !== $valueLength) {
                throw new KeePassPHPException('KDBX: truncated variant dictionary value.');
            }
            $offset += $valueLength;

            $value = self::decodeValue($type, $valueBytes);
            if ($value !== null) {
                $result[$name] = $value;
            }
        }

        return $result;
    }

    /**
     * @throws KeePassPHPException
     */
    private static function readInt32(string $bytes, int &$offset): int
    {
        $chunk = substr($bytes, $offset, 4);
        if (strlen($chunk) !== 4) {
            throw new KeePassPHPException('KDBX: invalid Int32 in variant dictionary.');
        }

        $offset += 4;
        $value = unpack('V', $chunk);
        if ($value === false || !isset($value[1]) || !is_int($value[1])) {
            throw new KeePassPHPException('KDBX: failed to unpack Int32 in variant dictionary.');
        }

        return $value[1];
    }

    /**
     * @throws KeePassPHPException
     */
    private static function decodeValue(int $type, string $valueBytes): bool|int|string|null
    {
        return match ($type) {
            0x04, 0x0C => self::unpackInt32($valueBytes),
            0x05, 0x0D => self::unpackUInt64($valueBytes),
            0x08 => self::unpackBool($valueBytes),
            0x18, 0x42 => $valueBytes,
            default => null,
        };
    }

    /**
     * @throws KeePassPHPException
     */
    private static function unpackInt32(string $valueBytes): int
    {
        if (strlen($valueBytes) !== 4) {
            throw new KeePassPHPException('KDBX: invalid Int32 value in variant dictionary.');
        }

        $value = unpack('V', $valueBytes);
        if ($value === false || !isset($value[1]) || !is_int($value[1])) {
            throw new KeePassPHPException('KDBX: failed to unpack Int32 value in variant dictionary.');
        }

        return $value[1];
    }

    /**
     * @throws KeePassPHPException
     */
    private static function unpackUInt64(string $valueBytes): int
    {
        if (strlen($valueBytes) !== 8) {
            throw new KeePassPHPException('KDBX: invalid UInt64 value in variant dictionary.');
        }

        $parts = unpack('V2', $valueBytes);
        if (
            $parts === false
            || !isset($parts[1], $parts[2])
            || !is_int($parts[1])
            || !is_int($parts[2])
        ) {
            throw new KeePassPHPException('KDBX: failed to unpack UInt64 value in variant dictionary.');
        }

        return ($parts[2] << 32) | $parts[1];
    }

    /**
     * @throws KeePassPHPException
     */
    private static function unpackBool(string $valueBytes): bool
    {
        if (strlen($valueBytes) !== 1) {
            throw new KeePassPHPException('KDBX: invalid Boolean value in variant dictionary.');
        }

        return ord($valueBytes) !== 0;
    }
}
