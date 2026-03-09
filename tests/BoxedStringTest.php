<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Strings\ProtectedString;
use KeePassPHP\Strings\UnprotectedString;
use PHPUnit\Framework\TestCase;

final class BoxedStringTest extends TestCase
{
    public function testUnprotectedStringReturnsOriginalValue(): void
    {
        $boxed = new UnprotectedString('secret');

        self::assertSame('secret', $boxed->getPlainString());
    }

    public function testProtectedStringUnmasksStoredValue(): void
    {
        $plain = 'secret';
        $mask = 'mask12';
        $boxed = new ProtectedString($plain ^ $mask, $mask);

        self::assertSame($plain, $boxed->getPlainString());
    }
}
