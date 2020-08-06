<?php

declare(strict_types=1);

namespace KeePassPHP\Filters;

use KeePassPHP\Entry;
use KeePassPHP\Group;
use KeePassPHP\Contracts\Filter;

class AllExceptFromPasswordsFilter implements Filter
{
    public function acceptEntry(Entry $entry): bool
    {
        return true;
    }

    public function acceptGroup(Group $group): bool
    {
        return true;
    }

    public function acceptHistoryEntry(Entry $historyEntry): bool
    {
        return true;
    }

    public function acceptTags(): bool
    {
        return true;
    }

    public function acceptIcons(): bool
    {
        return true;
    }

    public function acceptPasswords(): bool
    {
        return false;
    }

    public function acceptStrings(string $key): bool
    {
        return true;
    }
}
