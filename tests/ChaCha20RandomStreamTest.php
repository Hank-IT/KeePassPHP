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
        $stream = ChaCha20RandomStream::create(str_repeat("\x00", 32), str_repeat("\x00", 12));

        self::assertNotNull($stream);
        self::assertSame(
            hex2bin(
                '76b8e0ada0f13d90405d6ae55386bd28'
                . 'bdd219b8a08ded1aa836efcc8b770dc7'
                . 'da41597c5157488d7724e03fb8d84a37'
                . '6a43b8f41518a11cc387b669b2ee6586',
            ),
            $stream->getNextBytes(64),
        );
    }
}
