<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Streams\Salsa20RandomStream;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class Salsa20RandomStreamTest extends TestCase
{
    public function testCreateRejectsInvalidKeyOrIvLengths(): void
    {
        self::assertNull(Salsa20RandomStream::create('short', str_repeat("\x00", 8)));
        self::assertNull(Salsa20RandomStream::create(str_repeat("\x00", 32), 'short'));
    }

    public function testGeneratedBytesMatchPublishedSalsa20Vector(): void
    {
        $key = hex2bin('8000000000000000000000000000000000000000000000000000000000000000');
        self::assertNotFalse($key);

        $stream = Salsa20RandomStream::create(
            $key,
            str_repeat("\x00", 8),
        );

        self::assertNotNull($stream);
        self::assertSame(
            hex2bin(
                'e3be8fdd8beca2e3ea8ef9475b29a6e7'
                . '003951e1097a5c38d23b7a5fad9f6844'
                . 'b22c97559e2723c7cbbd3fe4fc8d9a07'
                . '44652a83e72a9c461876af4d7ef1a117',
            ),
            $stream->getNextBytes(64),
        );
    }

    public function testCounterCarriesOnlyAfterOverflow(): void
    {
        $stream = Salsa20RandomStream::create(str_repeat("\x00", 32), str_repeat("\x00", 8));

        self::assertNotNull($stream);

        $reflection = new ReflectionClass($stream);

        $stateProperty = $reflection->getProperty('state');
        $stateProperty->setAccessible(true);
        $state = $stateProperty->getValue($stream);
        self::assertIsArray($state);

        $state[16] = 0xFFFE;
        $state[17] = 0;
        $state[18] = 0;
        $state[19] = 0;
        $stateProperty->setValue($stream, $state);

        $outputProperty = $reflection->getProperty('output');
        $outputProperty->setAccessible(true);
        $outputProperty->setValue($stream, '');

        $outputPosProperty = $reflection->getProperty('outputPos');
        $outputPosProperty->setAccessible(true);
        $outputPosProperty->setValue($stream, Salsa20RandomStream::OUTPUT_LEN);

        $stream->getNextBytes(Salsa20RandomStream::OUTPUT_LEN);

        $state = $stateProperty->getValue($stream);
        self::assertIsArray($state);
        self::assertSame(0xFFFF, $state[16]);
        self::assertSame(0, $state[17]);
        self::assertSame(0, $state[18]);
        self::assertSame(0, $state[19]);
    }
}
