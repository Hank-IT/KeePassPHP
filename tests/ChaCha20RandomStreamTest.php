<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Streams\ChaCha20RandomStream;
use PHPUnit\Framework\TestCase;

final class ChaCha20RandomStreamTest extends TestCase
{
    public function testCreateRejectsInvalidKeyOrNonceLengths(): void
    {
        self::assertNull(ChaCha20RandomStream::create('short', str_repeat("\x00", 12)));
        self::assertNull(ChaCha20RandomStream::create(str_repeat("\x00", 32), 'short'));
    }

    public function testGeneratedBytesMatchKnownChaCha20Vector(): void
    {
        $key = hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
        $nonce = hex2bin('000000090000004A00000000');

        self::assertNotFalse($key);
        self::assertNotFalse($nonce);

        $stream = ChaCha20RandomStream::create($key, $nonce);

        self::assertNotNull($stream);
        self::assertSame(
            hex2bin(
                '10f1e7e4d13b5915500fdd1fa32071c4'
                . 'c7d1f4c733c068030422aa9ac3d46c4e'
                . 'd2826446079faa0914c2d705d98b02a2'
                . 'b5129cd1de164eb9cbd083e8a2503c4e',
            ),
            $stream->getNextBytes(64),
        );
    }
}
