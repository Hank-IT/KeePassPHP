<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\KdbxFile;
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
}
