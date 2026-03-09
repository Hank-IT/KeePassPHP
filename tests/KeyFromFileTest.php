<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Keys\KeyFromFile;
use PHPUnit\Framework\TestCase;

final class KeyFromFileTest extends TestCase
{
    public function testParsesRawBinaryKeyFiles(): void
    {
        $content = str_repeat('a', 32);
        $key = new KeyFromFile($content);

        self::assertSame($content, $key->getHash());
    }

    public function testParsesHexKeyFiles(): void
    {
        $content = bin2hex(str_repeat('b', 32));
        $key = new KeyFromFile($content);

        self::assertSame(str_repeat('b', 32), $key->getHash());
    }

    public function testParsesXmlVersionOneKeyFiles(): void
    {
        $hash = random_bytes(32);
        $xml = <<<XML
            <?xml version="1.0" encoding="UTF-8"?>
            <KeyFile>
              <Meta>
                <Version>1.0</Version>
              </Meta>
              <Key>
                <Data>%s</Data>
              </Key>
            </KeyFile>
            XML;

        $key = new KeyFromFile(sprintf($xml, base64_encode($hash)));

        self::assertSame($hash, $key->getHash());
    }

    public function testParsesXmlVersionTwoKeyFiles(): void
    {
        $hash = random_bytes(32);
        $formattedHash = chunk_split(strtoupper(bin2hex($hash)), 8, " \n");
        $integrityHash = strtoupper(substr(hash('sha256', $hash), 0, 8));
        $xml = <<<XML
            <?xml version="1.0" encoding="UTF-8"?>
            <KeyFile>
              <Meta>
                <Version>2.0</Version>
              </Meta>
              <Key>
                <Data Hash="%s">%s</Data>
              </Key>
            </KeyFile>
            XML;

        $key = new KeyFromFile(sprintf($xml, $integrityHash, $formattedHash));

        self::assertSame($hash, $key->getHash());
    }

    public function testRejectsXmlVersionTwoKeyFilesWithInvalidIntegrityHash(): void
    {
        $this->expectException(KeePassPHPException::class);
        $this->expectExceptionMessage('integrity hash mismatch');

        $hash = random_bytes(32);
        $xml = <<<XML
            <?xml version="1.0" encoding="UTF-8"?>
            <KeyFile>
              <Meta>
                <Version>2.0</Version>
              </Meta>
              <Key>
                <Data Hash="DEADBEEF">%s</Data>
              </Key>
            </KeyFile>
            XML;

        new KeyFromFile(sprintf($xml, strtoupper(bin2hex($hash))));
    }

    public function testFallsBackToHashedArbitraryFiles(): void
    {
        $content = "arbitrary\nkey-file\npayload";
        $key = new KeyFromFile($content);

        self::assertSame(hash('sha256', $content, true), $key->getHash());
    }

    public function testRejectsInvalidXmlKeyFiles(): void
    {
        $this->expectException(KeePassPHPException::class);
        $this->expectExceptionMessage('missing key data element');

        new KeyFromFile('<KeyFile><Meta><Version>3.0</Version></Meta></KeyFile>');
    }
}
