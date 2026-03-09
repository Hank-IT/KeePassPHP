<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Database;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Tests\Fixtures\SequenceRandomStream;
use PHPUnit\Framework\TestCase;

final class DatabaseTest extends TestCase
{
    public function testLoadFromXmlParsesProtectedPasswordsAndCustomFields(): void
    {
        $random = 'mask';
        $password = 'pass';
        $protectedValue = base64_encode($password ^ $random);
        $headerHash = base64_encode('header-hash');

        $xml = <<<XML
            <?xml version="1.0" encoding="UTF-8"?>
            <KeePassFile>
              <Meta>
                <HeaderHash>{$headerHash}</HeaderHash>
                <DatabaseName>Demo</DatabaseName>
                <CustomIcons>
                  <Icon>
                    <UUID>icon-1</UUID>
                    <Data>iVBORw0KGgo=</Data>
                  </Icon>
                </CustomIcons>
              </Meta>
              <Root>
                <Group>
                  <UUID>group-1</UUID>
                  <Name>Root</Name>
                  <Entry>
                    <UUID>entry-1</UUID>
                    <String>
                      <Key>Title</Key>
                      <Value>Example</Value>
                    </String>
                    <String>
                      <Key>Password</Key>
                      <Value Protected="True">{$protectedValue}</Value>
                    </String>
                    <String>
                      <Key>Environment</Key>
                      <Value>Prod</Value>
                    </String>
                  </Entry>
                </Group>
              </Root>
            </KeePassFile>
            XML;

        $database = Database::fromXML($xml, new SequenceRandomStream($random));

        self::assertSame('Demo', $database->getName());
        self::assertSame($password, $database->getPassword('entry-1'));
        self::assertSame('Example', $database->getStringField('entry-1', Database::KEY_TITLE));
        self::assertSame(['Environment'], $database->listCustomFields('entry-1'));
        self::assertSame('data:image/png;base64,iVBORw0KGgo=', $database->getCustomIcon('icon-1'));

        $serialized = $database->toArray();
        self::assertArrayHasKey(Database::GROUPS, $serialized);
        self::assertStringNotContainsString(
            Database::KEY_PASSWORD,
            json_encode($serialized, JSON_THROW_ON_ERROR)
        );
    }

    public function testLoadFromXmlThrowsOnInvalidRootElement(): void
    {
        $this->expectException(KeePassPHPException::class);
        $this->expectExceptionMessage("Database XML load: the root element is not 'KeePassFile'.");

        Database::fromXML('<Root />', null);
    }
}
