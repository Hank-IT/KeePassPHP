<?php

declare(strict_types=1);

namespace KeePassPHP\Filters;

use KeePassPHP\Contracts\Filter;
use KeePassPHP\Entry;
use KeePassPHP\Group;

class AllExceptFromPasswordsFilter implements Filter
{
    public function acceptEntry(Entry $entry)
    {
        return true;
    }

    public function acceptGroup(Group $group)
    {
        return true;
    }

    public function acceptHistoryEntry(Entry $historyEntry)
    {
        return true;
    }

    public function acceptTags()
    {
        return true;
    }

    public function acceptIcons()
    {
        return true;
    }

    public function acceptPasswords()
    {
        return false;
    }

    public function acceptStrings($key)
    {
        return true;
    }
}
