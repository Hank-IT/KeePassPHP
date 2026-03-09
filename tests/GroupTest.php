<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Database;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Filters\AllFilter;
use KeePassPHP\Group;
use PHPUnit\Framework\TestCase;

final class GroupTest extends TestCase
{
    public function testFromArrayBuildsNestedGroupsAndEntries(): void
    {
        $group = Group::fromArray(
            [
                Database::XML_UUID => 'group-1',
                Database::XML_NAME => 'Root',
                Database::GROUPS => [
                    [
                        Database::XML_UUID => 'group-2',
                        Database::XML_NAME => 'Child',
                    ],
                ],
                Database::ENTRIES => [
                    [
                        Database::XML_UUID => 'entry-1',
                        Database::KEY_STRINGFIELDS => [
                            Database::KEY_TITLE => 'Example',
                        ],
                    ],
                ],
            ],
            '1',
        );

        self::assertSame('group-1', $group->uuid);
        self::assertSame('Root', $group->name);
        self::assertCount(1, $group->groups);
        self::assertCount(1, $group->entries);
        self::assertSame('Example', $group->getStringField('entry-1', Database::KEY_TITLE));

        $serialized = $group->toArray(new AllFilter());

        self::assertArrayHasKey(Database::GROUPS, $serialized);
        self::assertArrayHasKey(Database::ENTRIES, $serialized);
    }

    public function testFromArrayThrowsOnEmptyArray(): void
    {
        $this->expectException(KeePassPHPException::class);
        $this->expectExceptionMessage('Group array load: array is empty.');

        Group::fromArray([], '1');
    }
}
