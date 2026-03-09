<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Database;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\KdbxFile;
use KeePassPHP\KdbxInspector;
use KeePassPHP\Readers\StringReader;
use KeePassPHP\Tests\Fixtures\Kdbx4FixtureBuilder;
use PHPUnit\Framework\TestCase;

final class Kdbx4FileTest extends TestCase
{
    public function testDecryptsAesKdfKdbx4FilesThroughFacade(): void
    {
        $fixture = Kdbx4FixtureBuilder::buildAesKdfDatabase();

        $file = KdbxFile::decrypt(new StringReader($fixture['payload']), $fixture['key']);

        self::assertSame(4, $file->getMajorVersion());
        self::assertNotNull($file->getContent());
        self::assertNotNull($file->getRandomStream());
    }

    public function testDatabaseCanLoadFromKdbx4Payload(): void
    {
        $fixture = Kdbx4FixtureBuilder::buildAesKdfDatabase();

        $database = Database::fromKdbx(new StringReader($fixture['payload']), $fixture['key']);

        self::assertSame($fixture['database_name'], $database->getName());
        self::assertSame($fixture['entry_password'], $database->getPassword('entry-1'));
    }

    public function testInspectorMarksSupportedKdbx4AsDecryptable(): void
    {
        $fixture = Kdbx4FixtureBuilder::buildAesKdfDatabase();

        $metadata = KdbxInspector::inspect(new StringReader($fixture['payload']));

        self::assertSame('KDBX 4.1', $metadata->formatLabel);
        self::assertTrue($metadata->isDecryptableByCurrentLibrary);
        self::assertSame('AES-256', $metadata->cipherName);
        self::assertSame('AES-KDF', $metadata->kdfName);
    }

    public function testDecryptRejectsArgon2idKdf(): void
    {
        $fixture = Kdbx4FixtureBuilder::buildArgon2idDatabase();

        $this->expectException(KeePassPHPException::class);
        $this->expectExceptionMessage('Argon2id is unsupported');

        KdbxFile::decrypt(new StringReader($fixture['payload']), $fixture['key']);
    }
}
