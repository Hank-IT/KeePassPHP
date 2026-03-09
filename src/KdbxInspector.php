<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Readers\Reader;
use KeePassPHP\Readers\ResourceReader;

final class KdbxInspector
{
    private const string KDBX_SIGNATURE_1 = "\x03\xD9\xA2\x9A";
    private const string KDBX_SIGNATURE_2 = "\x67\xFB\x4B\xB5";
    private const string HEADER_END_V4 = "\x0D\x0A\x0D\x0A";

    private const array CIPHERS = [
        '31C1F2E6BF714350BE5805216AFC5AFF' => 'AES-256',
        'D6038A2B8B6F4CB5A524339A31DBB59A' => 'ChaCha20',
    ];

    private const array KDFS = [
        'C9D9F39A628A4460BF740D08C18A4FEA' => 'AES-KDF',
        'EF636DDF8C29444B91F7A9A403E30A0C' => 'Argon2d',
        '9E298B1956DB4773B23DFC3EC6F0A1E6' => 'Argon2id',
    ];

    private const array V3_INNER_RANDOM_STREAMS = [
        0 => 'ArcFourVariant',
        1 => 'None',
        2 => 'Salsa20',
    ];

    /**
     * @throws KeePassPHPException
     */
    public static function inspect(Reader $reader): KdbxMetadata
    {
        $sig1 = $reader->read(4);
        $sig2 = $reader->read(4);
        if ($sig1 !== self::KDBX_SIGNATURE_1 || $sig2 !== self::KDBX_SIGNATURE_2) {
            throw new KeePassPHPException('KDBX inspect: signature not correct.');
        }

        $formatVersion = $reader->readNumber(4);
        $majorVersion = ($formatVersion >> 16) & 0xFFFF;
        $minorVersion = $formatVersion & 0xFFFF;

        return match ($majorVersion) {
            3 => self::inspectV3($reader, $formatVersion, $majorVersion, $minorVersion),
            4 => self::inspectV4($reader, $formatVersion, $majorVersion, $minorVersion),
            default => throw new KeePassPHPException(
                sprintf('KDBX inspect: unsupported major version %d.', $majorVersion)
            ),
        };
    }

    /**
     * @throws KeePassPHPException
     */
    public static function inspectFile(string $path): KdbxMetadata
    {
        $reader = ResourceReader::openFile($path);
        if ($reader === null) {
            throw new KeePassPHPException(sprintf('KDBX inspect: unable to open file %s.', $path));
        }

        try {
            return self::inspect($reader);
        } finally {
            $reader->close();
        }
    }

    /**
     * @throws KeePassPHPException
     */
    private static function inspectV3(
        Reader $reader,
        int $formatVersion,
        int $majorVersion,
        int $minorVersion,
    ): KdbxMetadata {
        $cipherUuidHex = null;
        $compression = null;
        $innerRandomStreamId = null;

        while (true) {
            $fieldId = $reader->readByte();
            $fieldLength = $reader->readNumber(2);
            $fieldValue = $fieldLength > 0 ? $reader->read($fieldLength) : '';

            if ($fieldValue === null || strlen($fieldValue) !== $fieldLength) {
                throw new KeePassPHPException('KDBX inspect: incomplete v3 header field.');
            }

            if ($fieldId === 0) {
                break;
            }

            if ($fieldId === 2) {
                $cipherUuidHex = strtoupper(bin2hex($fieldValue));
            } elseif ($fieldId === 3) {
                $compressionFlags = unpack('V', $fieldValue);
                if ($compressionFlags === false || ! isset($compressionFlags[1]) || ! is_int($compressionFlags[1])) {
                    throw new KeePassPHPException('KDBX inspect: invalid v3 compression field.');
                }

                $compression = $compressionFlags[1] === 1;
            } elseif ($fieldId === 10) {
                $innerRandomStream = unpack('V', $fieldValue);
                if ($innerRandomStream === false || ! isset($innerRandomStream[1]) || ! is_int($innerRandomStream[1])) {
                    throw new KeePassPHPException('KDBX inspect: invalid v3 inner random stream field.');
                }

                $innerRandomStreamId = $innerRandomStream[1];
            }
        }

        return new KdbxMetadata(
            majorVersion: $majorVersion,
            minorVersion: $minorVersion,
            formatVersion: $formatVersion,
            formatLabel: sprintf('KDBX %d.%d', $majorVersion, $minorVersion),
            isDecryptableByCurrentLibrary: true,
            cipherUuidHex: $cipherUuidHex,
            cipherName: $cipherUuidHex !== null ? (self::CIPHERS[$cipherUuidHex] ?? null) : null,
            isCompressed: $compression,
            kdfUuidHex: 'C9D9F39A628A4460BF740D08C18A4FEA',
            kdfName: 'AES-KDF',
            innerRandomStreamId: $innerRandomStreamId,
            innerRandomStreamName: $innerRandomStreamId !== null
                ? (self::V3_INNER_RANDOM_STREAMS[$innerRandomStreamId] ?? null)
                : null,
        );
    }

    /**
     * @throws KeePassPHPException
     */
    private static function inspectV4(
        Reader $reader,
        int $formatVersion,
        int $majorVersion,
        int $minorVersion,
    ): KdbxMetadata {
        $cipherUuidHex = null;
        $compression = null;
        $kdfUuidHex = null;

        while (true) {
            $fieldId = $reader->readByte();
            $fieldLength = $reader->readNumber(4);
            $fieldValue = $fieldLength > 0 ? $reader->read($fieldLength) : '';

            if ($fieldValue === null || strlen($fieldValue) !== $fieldLength) {
                throw new KeePassPHPException('KDBX inspect: incomplete v4 header field.');
            }

            if ($fieldId === 0) {
                if ($fieldValue !== self::HEADER_END_V4) {
                    throw new KeePassPHPException('KDBX inspect: invalid v4 end-of-header marker.');
                }

                break;
            }

            if ($fieldId === 2) {
                $cipherUuidHex = strtoupper(bin2hex($fieldValue));
            } elseif ($fieldId === 3) {
                $compressionFlags = unpack('V', $fieldValue);
                if ($compressionFlags === false || ! isset($compressionFlags[1]) || ! is_int($compressionFlags[1])) {
                    throw new KeePassPHPException('KDBX inspect: invalid v4 compression field.');
                }

                $compression = $compressionFlags[1] === 1 ? true : ($compressionFlags[1] === 0 ? false : null);
            } elseif ($fieldId === 11) {
                $kdfParams = KdbxVariantDictionary::parse($fieldValue);
                $uuid = $kdfParams['$UUID'] ?? null;
                $kdfUuidHex = is_string($uuid) ? strtoupper(bin2hex($uuid)) : null;
            }
        }

        return new KdbxMetadata(
            majorVersion: $majorVersion,
            minorVersion: $minorVersion,
            formatVersion: $formatVersion,
            formatLabel: sprintf('KDBX %d.%d', $majorVersion, $minorVersion),
            isDecryptableByCurrentLibrary: $cipherUuidHex === strtoupper(bin2hex(Kdbx4Header::CIPHER_AES))
                && $kdfUuidHex === strtoupper(bin2hex(Kdbx4Header::KDF_AES)),
            cipherUuidHex: $cipherUuidHex,
            cipherName: $cipherUuidHex !== null ? (self::CIPHERS[$cipherUuidHex] ?? null) : null,
            isCompressed: $compression,
            kdfUuidHex: $kdfUuidHex,
            kdfName: $kdfUuidHex !== null ? (self::KDFS[$kdfUuidHex] ?? null) : null,
            innerRandomStreamId: null,
            innerRandomStreamName: null,
        );
    }
}
