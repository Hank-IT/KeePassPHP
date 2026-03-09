<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Cipher\CipherOpenSSL;
use KeePassPHP\Contracts\Cipher;
use KeePassPHP\Contracts\Key;
use KeePassPHP\Exceptions\KeePassPHPException;

final class Kdbx4KeyDerivation
{
    public static function derive(Key $key, Kdbx4Header $header): Kdbx4DerivedKeys
    {
        if ($header->masterSeed === null) {
            throw new KeePassPHPException('Kdbx4 file decrypt: missing master seed.');
        }

        $kdfUuid = $header->getKdfUuid();
        if ($kdfUuid === null) {
            throw new KeePassPHPException('Kdbx4 file decrypt: missing KDF UUID.');
        }

        $transformedKey = match ($kdfUuid) {
            Kdbx4Header::KDF_AES => self::deriveAesKdf($key, $header),
            Kdbx4Header::KDF_ARGON2ID => throw new KeePassPHPException(
                'Kdbx4 file decrypt: Argon2id is unsupported.'
            ),
            Kdbx4Header::KDF_ARGON2D => throw new KeePassPHPException(
                'Kdbx4 file decrypt: Argon2d is unsupported.'
            ),
            default => throw new KeePassPHPException('Kdbx4 file decrypt: unsupported KDF.'),
        };

        return new Kdbx4DerivedKeys(
            encryptionKey: hash(KdbxFile::HASH, $header->masterSeed . $transformedKey, true),
            hmacBaseKey: hash('sha512', $header->masterSeed . $transformedKey . "\x01", true),
        );
    }

    private static function deriveAesKdf(Key $key, Kdbx4Header $header): string
    {
        $seed = $header->kdfParameters['S'] ?? null;
        $rounds = $header->kdfParameters['R'] ?? null;

        if (!is_string($seed) || !is_int($rounds) || $rounds < 0) {
            throw new KeePassPHPException('Kdbx4 file decrypt: invalid AES-KDF parameters.');
        }

        $cipher = new CipherOpenSSL('aes-256-ecb', $seed, '', Cipher::PADDING_NONE);
        $transformedKey = $cipher->encryptManyTimes($key->getHash(), $rounds);
        if ($transformedKey === null) {
            throw new KeePassPHPException('Kdbx4 file decrypt: AES-KDF transformation failed.');
        }

        return hash(KdbxFile::HASH, $transformedKey, true);
    }
}
