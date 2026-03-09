<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\KdbxHeader;
use KeePassPHP\Readers\StringReader;
use PHPUnit\Framework\TestCase;

final class KdbxHeaderTest extends TestCase
{
    public function testToBinaryAndFromReaderRoundTrip(): void
    {
        $header = new KdbxHeader();
        $header->cipher = KdbxHeader::CIPHER_AES;
        $header->compression = KdbxHeader::COMPRESSION_NONE;
        $header->masterSeed = str_repeat('a', 32);
        $header->transformSeed = str_repeat('b', 32);
        $header->rounds = pack('V', 1) . "\x00\x00\x00\x00";
        $header->encryptionIV = str_repeat('c', 16);
        $header->randomStreamKey = str_repeat('d', 32);
        $header->startBytes = str_repeat('e', 32);
        $header->randomStream = KdbxHeader::RANDOMSTREAM_NONE;

        $binary = $header->toBinary('sha256');
        $parsed = KdbxHeader::fromReader(new StringReader($binary), 'sha256');

        self::assertSame($header->cipher, $parsed->cipher);
        self::assertSame($header->compression, $parsed->compression);
        self::assertSame($header->masterSeed, $parsed->masterSeed);
        self::assertSame($header->transformSeed, $parsed->transformSeed);
        self::assertSame($header->rounds, $parsed->rounds);
        self::assertSame($header->encryptionIV, $parsed->encryptionIV);
        self::assertSame($header->randomStreamKey, $parsed->randomStreamKey);
        self::assertSame($header->startBytes, $parsed->startBytes);
        self::assertSame($header->randomStream, $parsed->randomStream);
        self::assertSame($header->headerHash, $parsed->headerHash);
    }

    public function testFromReaderThrowsOnInvalidSignature(): void
    {
        $this->expectException(KeePassPHPException::class);
        $this->expectExceptionMessage('Kdbx header: signature not correct.');

        KdbxHeader::fromReader(new StringReader('invalid'), 'sha256');
    }
}
