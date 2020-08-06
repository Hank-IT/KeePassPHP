<?php

declare(strict_types=1);

namespace KeePassPHP\Contracts;

use KeePassPHP\Entry;
use KeePassPHP\Group;

/**
 * Implementation of database filters.
 *
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 *
 * @link       https://github.com/shkdee/KeePassPHP
 */

/**
 * A set of rules to determine which data to write when serializing a database.
 * Implementing this interface makes it possible to write only specific data.
 */
interface Filter
{
    /**
     * Returns true if the given entry must be serialized (otherwise it will be
     * discarded).
     *
     * @param Entry $entry An entry.
     *
     * @return bool
     */
    public function acceptEntry(Entry $entry): bool;

    /**
     * Returns true if the given group must be serialized (otherwise it will be
     * discarded).
     *
     * @param Entry $entry A group.
     *
     * @return bool
     */
    public function acceptGroup(Group $group): bool;

    /**
     * Returns true if the given history entry must be serialized (otherwise it
     * will be discarded).
     *
     * @param Entry $entry A history entry.
     *
     * @return bool
     */
    public function acceptHistoryEntry(Entry $entry): bool;

    /**
     * Returns true if tags must be serialized.
     *
     * @return bool
     */
    public function acceptTags(): bool;

    /**
     * Returns true if icons must be serialized.
     *
     * @return bool
     */
    public function acceptIcons(): bool;

    /**
     * Returns true if passwords must be serialized.
     * WARNING: it is NOT recommended to return true in implementations of this
     * method, because passwords should not be copied in most cases.
     *
     * @return bool
     */
    public function acceptPasswords(): bool;

    /**
     * Returns true if string fields with the given key must be serialized.
     *
     * @param $key string A string field key.
     *
     * @return bool
     */
    public function acceptStrings(string $key): bool;
}
