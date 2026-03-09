<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Database;
use KeePassPHP\Entry;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Filters\AllFilter;
use PHPUnit\Framework\TestCase;

final class EntryTest extends TestCase
{
    public function testFromArrayBuildsStringFieldsAndHistory(): void
    {
        $entry = Entry::fromArray(
            [
                Database::XML_UUID => 'entry-1',
                Database::XML_TAGS => 'prod',
                Database::KEY_STRINGFIELDS => [
                    Database::KEY_TITLE => 'Example',
                    'Environment' => 'Production',
                ],
                Database::XML_HISTORY => [
                    [
                        Database::XML_UUID => 'history-1',
                        Database::KEY_STRINGFIELDS => [
                            Database::KEY_TITLE => 'Old title',
                        ],
                    ],
                ],
            ],
            '1',
        );

        self::assertSame('entry-1', $entry->uuid);
        self::assertSame('prod', $entry->tags);
        self::assertSame('Example', $entry->getStringField(Database::KEY_TITLE));
        self::assertSame(['Environment'], $entry->listCustomFields());

        $serialized = $entry->toArray(new AllFilter());

        self::assertArrayHasKey(Database::KEY_STRINGFIELDS, $serialized);
        self::assertArrayHasKey(Database::XML_HISTORY, $serialized);
    }

    public function testFromArrayThrowsOnEmptyArray(): void
    {
        $this->expectException(KeePassPHPException::class);
        $this->expectExceptionMessage('Entry array load: array is empty.');

        Entry::fromArray([], '1');
    }
}
