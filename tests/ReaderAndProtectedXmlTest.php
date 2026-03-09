<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\ProtectedXMLReader;
use KeePassPHP\Readers\DigestReader;
use KeePassPHP\Readers\HashedBlockReader;
use KeePassPHP\Readers\ResourceReader;
use KeePassPHP\Readers\StringReader;
use KeePassPHP\Strings\ProtectedString;
use KeePassPHP\Strings\UnprotectedString;
use KeePassPHP\Tests\Fixtures\SequenceRandomStream;
use PHPUnit\Framework\TestCase;

final class ReaderAndProtectedXmlTest extends TestCase
{
    public function testDigestReaderUpdatesDigestWhenReadingToEnd(): void
    {
        $reader = new DigestReader(new StringReader('abc'), 'sha256');

        self::assertSame('abc', $reader->readToTheEnd());
        self::assertSame(hash('sha256', 'abc', true), $reader->getDigest());
    }

    public function testHashedBlockReaderHashStringAppendsTerminatorBlock(): void
    {
        $hashed = HashedBlockReader::hashString('payload', 'sha256');

        self::assertSame(
            pack('V', 1) . str_repeat("\x00", 32) . pack('V', 0),
            substr($hashed, -40),
        );
    }

    public function testHashedBlockReaderCanReadTerminatedPayload(): void
    {
        $payload = 'payload';
        $reader = new HashedBlockReader(
            new StringReader(HashedBlockReader::hashString($payload, 'sha256')),
            'sha256',
        );

        self::assertSame($payload, $reader->readToTheEnd());
        self::assertFalse($reader->isCorrupted());
    }

    public function testResourceReaderCanReadFileAndBeClosedSafely(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'kphptest-');
        self::assertNotFalse($path);

        try {
            self::assertNotFalse(file_put_contents($path, 'payload'));

            $reader = ResourceReader::openFile($path);

            self::assertNotNull($reader);
            self::assertTrue($reader->canRead());
            self::assertSame('pay', $reader->read(3));
            self::assertSame('load', $reader->readToTheEnd());

            $reader->close();

            self::assertFalse($reader->canRead());
            self::assertNull($reader->read(1));
            $reader->close();
        } finally {
            unlink($path);
        }
    }

    public function testStringReaderHandlesZeroLengthReadsAndClose(): void
    {
        $reader = new StringReader('payload');

        self::assertSame('', $reader->read(0));
        self::assertSame('pay', $reader->read(3));

        $reader->close();

        self::assertFalse($reader->canRead());
        self::assertNull($reader->read(1));
        self::assertNull($reader->readToTheEnd());
    }

    public function testProtectedXmlReaderCanReturnPlainAndBoxedStrings(): void
    {
        $random = 'mask';
        $plain = 'pass';
        $protectedValue = base64_encode($plain ^ $random);
        $xml = <<<XML
            <?xml version="1.0" encoding="UTF-8"?>
            <Root>
              <Value Protected="true">{$protectedValue}</Value>
            </Root>
            XML;

        $reader = new ProtectedXMLReader(new SequenceRandomStream($random));
        self::assertTrue($reader->XML($xml));
        self::assertTrue($reader->read(-1));
        self::assertTrue($reader->read($reader->depth()));

        self::assertSame($plain, $reader->readTextInside());

        $reader = new ProtectedXMLReader(new SequenceRandomStream($random));
        self::assertTrue($reader->XML($xml));
        self::assertTrue($reader->read(-1));
        self::assertTrue($reader->read($reader->depth()));

        $boxed = $reader->readTextInside(true);

        self::assertInstanceOf(ProtectedString::class, $boxed);
        self::assertSame($plain, $boxed->getPlainString());
    }

    public function testProtectedXmlReaderReturnsUnprotectedBoxedStringForPlainValues(): void
    {
        $reader = new ProtectedXMLReader();
        self::assertTrue($reader->XML('<Root><Value>plain</Value></Root>'));
        self::assertTrue($reader->read(-1));
        self::assertTrue($reader->read($reader->depth()));

        $boxed = $reader->readTextInside(true);

        self::assertInstanceOf(UnprotectedString::class, $boxed);
        self::assertSame('plain', $boxed->getPlainString());
    }
}
