<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Contracts\Key;
use KeePassPHP\Keys\CompositeKey;

final class KdbxKeyHash
{
    public static function resolveCompositeHash(Key $key): string
    {
        $hash = $key->getHash();

        if ($key instanceof CompositeKey) {
            return $hash;
        }

        return hash(KdbxFile::HASH, $hash, true);
    }
}
