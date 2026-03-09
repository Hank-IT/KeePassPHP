<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Database;
use KeePassPHP\Entry;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Group;
use KeePassPHP\Kdbx4WriteOptions;
use KeePassPHP\Kdbx4Writer;
use KeePassPHP\KdbxFile;
use KeePassPHP\KdbxInspector;
use KeePassPHP\Keys\CompositeKey;
use KeePassPHP\Keys\KeyFromPassword;
use KeePassPHP\Readers\ResourceReader;
use KeePassPHP\Readers\StringReader;
use KeePassPHP\Strings\UnprotectedString;
use PHPUnit\Framework\TestCase;

final class Kdbx4WriterTest extends TestCase
{
    public function testWritesKdbx41ThatCanBeInspectedAndReadBack(): void
    {
        $database = new Database();
        $database->setName('Generated Database');

        $customIconUuid = self::uuid('00112233445566778899AABBCCDDEEFF');
        $database->setCustomIcon($customIconUuid, base64_encode('icon-data'));

        $group = new Group();
        $group->uuid = self::uuid('102132435465768798A9BACBDCEDFE0F');
        $group->name = 'Root';
        $group->customIcon = $customIconUuid;

        $entry = new Entry();
        $entry->uuid = self::uuid('0F1E2D3C4B5A69788796A5B4C3D2E1F0');
        $entry->customIcon = $customIconUuid;
        $entry->tags = 'generated';
        $entry->setStringField(Database::KEY_TITLE, new UnprotectedString('Example'));
        $entry->setStringField(Database::KEY_USERNAME, new UnprotectedString('alice'));
        $entry->setStringField('Environment', new UnprotectedString('test'));
        $entry->setPassword(new UnprotectedString('secret-password'));

        $historyEntry = new Entry();
        $historyEntry->uuid = self::uuid('AABBCCDDEEFF00112233445566778899');
        $historyEntry->setStringField(Database::KEY_TITLE, new UnprotectedString('Example'));
        $historyEntry->setPassword(new UnprotectedString('old-password'));
        $entry->addHistoryEntry($historyEntry);

        $group->addEntry($entry);
        $database->addGroup($group);

        $key = new KeyFromPassword('master-password', 'SHA256');
        $payload = $database->toKdbx4($key);

        $metadata = KdbxInspector::inspect(new StringReader($payload));

        self::assertSame('KDBX 4.1', $metadata->formatLabel);
        self::assertTrue($metadata->isDecryptableByCurrentLibrary);
        self::assertSame('AES-256', $metadata->cipherName);
        self::assertSame('AES-KDF', $metadata->kdfName);

        $opened = KdbxFile::decrypt(new StringReader($payload), $key);
        self::assertNotNull($opened->getContent());
        self::assertStringContainsString('Protected="True"', (string) $opened->getContent());

        $decoded = Database::fromKdbx(new StringReader($payload), $key);

        self::assertSame('Generated Database', $decoded->getName());
        self::assertSame('secret-password', $decoded->getPassword($entry->uuid ?? ''));
        self::assertSame('alice', $decoded->getStringField($entry->uuid ?? '', Database::KEY_USERNAME));
        self::assertSame('test', $decoded->getStringField($entry->uuid ?? '', 'Environment'));
        self::assertSame(
            'data:image/png;base64,' . base64_encode('icon-data'),
            $decoded->getCustomIcon($customIconUuid),
        );
        self::assertCount(1, $decoded->getGroups());
        self::assertCount(1, $decoded->getGroups()[0]->entries);
        self::assertCount(1, $decoded->getGroups()[0]->entries[0]->history);
        self::assertSame('generated', $decoded->getGroups()[0]->entries[0]->tags);
        self::assertSame($customIconUuid, $decoded->getGroups()[0]->customIcon);
        self::assertSame($customIconUuid, $decoded->getGroups()[0]->entries[0]->customIcon);
    }

    public function testRejectsUnsupportedInnerRandomStreamForWriting(): void
    {
        $database = new Database();
        $database->setName('Generated Database');

        $group = new Group();
        $group->name = 'Root';
        $database->addGroup($group);

        $this->expectException(KeePassPHPException::class);
        $this->expectExceptionMessage('unsupported inner random stream');

        Kdbx4Writer::write(
            $database,
            new KeyFromPassword('master-password', 'SHA256'),
            new Kdbx4WriteOptions(innerRandomStream: 99),
        );
    }

    public function testPasswordKeyMatchesEquivalentCompositeKeyForKdbx4Writing(): void
    {
        $database = new Database();
        $database->setName('Generated Database');

        $group = new Group();
        $group->uuid = self::uuid('0123456789ABCDEFFEDCBA9876543210');
        $group->name = 'Root';

        $entry = new Entry();
        $entry->uuid = self::uuid('00112233445566778899AABBCCDDEEFF');
        $entry->setStringField(Database::KEY_TITLE, new UnprotectedString('Example'));
        $entry->setPassword(new UnprotectedString('secret-password'));

        $group->addEntry($entry);
        $database->addGroup($group);

        $passwordKey = new KeyFromPassword('master-password', 'SHA256');
        $payload = $database->toKdbx4($passwordKey);

        $compositeKey = new CompositeKey('SHA256');
        $compositeKey->addKey(new KeyFromPassword('master-password', 'SHA256'));

        $decoded = Database::fromKdbx(new StringReader($payload), $compositeKey);

        self::assertSame('Generated Database', $decoded->getName());
        self::assertSame('secret-password', $decoded->getPassword($entry->uuid ?? ''));
    }

    public function testWrittenKdbx4CanBeReopenedFromFile(): void
    {
        $database = new Database();
        $database->setName('Generated Database');

        $group = new Group();
        $group->uuid = self::uuid('11111111111111111111111111111111');
        $group->name = 'Root';

        $entry = new Entry();
        $entry->uuid = self::uuid('22222222222222222222222222222222');
        $entry->setStringField(Database::KEY_TITLE, new UnprotectedString('Example'));
        $entry->setPassword(new UnprotectedString('secret-password'));

        $group->addEntry($entry);
        $database->addGroup($group);

        $payload = $database->toKdbx4(new KeyFromPassword('master-password', 'SHA256'));

        $path = tempnam(sys_get_temp_dir(), 'kdbx4-');
        self::assertNotFalse($path);

        try {
            self::assertNotFalse(file_put_contents($path, $payload));

            $reader = ResourceReader::openFile($path);
            self::assertNotNull($reader);

            try {
                $decoded = Database::fromKdbx(
                    $reader,
                    new KeyFromPassword('master-password', 'SHA256'),
                );
            } finally {
                $reader->close();
            }

            self::assertSame('Generated Database', $decoded->getName());
            self::assertSame('secret-password', $decoded->getPassword($entry->uuid ?? ''));
        } finally {
            unlink($path);
        }
    }

    private static function uuid(string $hex): string
    {
        $binary = hex2bin($hex);
        if ($binary === false) {
            throw new KeePassPHPException(sprintf('Invalid test UUID hex: %s', $hex));
        }

        return base64_encode($binary);
    }
}
