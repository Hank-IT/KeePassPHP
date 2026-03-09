<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Database;
use KeePassPHP\Entry;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Group;
use KeePassPHP\Kdbx4WriteOptions;
use KeePassPHP\Kdbx4Writer;
use KeePassPHP\KdbxInspector;
use KeePassPHP\Keys\KeyFromPassword;
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

    private static function uuid(string $hex): string
    {
        $binary = hex2bin($hex);
        if ($binary === false) {
            throw new KeePassPHPException(sprintf('Invalid test UUID hex: %s', $hex));
        }

        return base64_encode($binary);
    }
}
