<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\KdbxFile;
use KeePassPHP\Keys\CompositeKey;
use KeePassPHP\Keys\KeyFromPassword;
use KeePassPHP\Readers\StringReader;
use PHPUnit\Framework\TestCase;

final class KdbxFileTest extends TestCase
{
    public function testEncryptAndDecryptRoundTrip(): void
    {
        $file = KdbxFile::forEncryption(1);

        $key = new KeyFromPassword('secret', KdbxFile::HASH);
        $payload = '<xml>payload</xml>';
        $encrypted = $file->encrypt($payload, $key);

        $decrypted = KdbxFile::decrypt(new StringReader($encrypted), $key);

        self::assertSame($payload, $decrypted->getContent());
    }

    public function testForEncryptionThrowsOnNonPositiveRounds(): void
    {
        $this->expectException(KeePassPHPException::class);
        $this->expectExceptionMessage('Kdbx file encrypt: rounds must be strictly positive.');

        KdbxFile::forEncryption(0);
    }

    public function testPasswordKeyMatchesEquivalentCompositeKeyForKdbx3(): void
    {
        $file = KdbxFile::forEncryption(1);
        $payload = '<xml>payload</xml>';

        $passwordKey = new KeyFromPassword('secret', KdbxFile::HASH);
        $compositeKey = new CompositeKey(KdbxFile::HASH);
        $compositeKey->addKey(new KeyFromPassword('secret', KdbxFile::HASH));

        $encrypted = $file->encrypt($payload, $passwordKey);
        $decrypted = KdbxFile::decrypt(new StringReader($encrypted), $compositeKey);

        self::assertSame($payload, $decrypted->getContent());
    }
}
