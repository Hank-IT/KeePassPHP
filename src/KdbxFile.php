<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Contracts\Key;
use KeePassPHP\Contracts\OpenedKdbxFile;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Readers\Reader;
use KeePassPHP\Readers\StringReader;

final class KdbxFile
{
    public const string HASH = 'SHA256';

    public static function forEncryption(int|string $rounds): Kdbx3File
    {
        return Kdbx3File::forEncryption($rounds);
    }

    public static function decrypt(Reader $reader, Key $key): OpenedKdbxFile
    {
        $prefix = $reader->read(12);
        if ($prefix === null || strlen($prefix) !== 12) {
            throw new KeePassPHPException('Kdbx file decrypt: file header is incomplete.');
        }

        $remaining = $reader->readToTheEnd() ?? '';
        $data = $prefix . $remaining;

        $formatVersion = unpack('V', substr($data, 8, 4));
        if ($formatVersion === false || !isset($formatVersion[1]) || !is_int($formatVersion[1])) {
            throw new KeePassPHPException('Kdbx file decrypt: invalid format version.');
        }

        $majorVersion = ($formatVersion[1] >> 16) & 0xFFFF;
        $buffer = new StringReader($data);

        return match ($majorVersion) {
            3 => Kdbx3File::decrypt($buffer, $key),
            4 => Kdbx4File::decrypt($buffer, $key),
            default => throw new KeePassPHPException(
                sprintf('Kdbx file decrypt: unsupported major version %d.', $majorVersion)
            ),
        };
    }
}
