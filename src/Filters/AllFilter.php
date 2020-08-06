<?php

declare(strict_types=1);

namespace KeePassPHP\Filters;

use KeePassPHP\Contracts\Filter;
use KeePassPHP\Entry;
use KeePassPHP\Group;

class AllFilter implements Filter
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
        return true;
    }

    public function acceptStrings(string $key): bool
    {
        return true;
    }
}
