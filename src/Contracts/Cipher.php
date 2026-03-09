<?php

declare(strict_types=1);

namespace KeePassPHP\Contracts;

interface Cipher
{
    public const int PADDING_NONE = 0;
    public const int PADDING_PKCS7 = 1;

    public function encrypt(string $string): ?string;

    public function encryptManyTimes(string $string, int $rounds): ?string;

    public function decrypt(string $string): ?string;
}
