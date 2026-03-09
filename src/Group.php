<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Contracts\BoxedString;
use KeePassPHP\Contracts\Filter;
use KeePassPHP\Exceptions\KeePassPHPException;

/**
 * A class that manages a group of a KeePass 2.x password database.
 */
final class Group
{
    public ?string $uuid = null;
    public ?string $name = null;
    public ?string $icon = null;
    public ?string $customIcon = null;

    /** @var list<Group> */
    public array $groups = [];

    /** @var list<Entry> */
    public array $entries = [];

    public function getPassword(string $uuid): ?BoxedString
    {
        foreach ($this->entries as $entry) {
            if ($entry->uuid === $uuid) {
                return $entry->password;
            }
        }

        foreach ($this->groups as $group) {
            $value = $group->getPassword($uuid);
            if ($value !== null) {
                return $value;
            }
        }

        return null;
    }

    public function getStringField(string $uuid, string $key): ?string
    {
        foreach ($this->entries as $entry) {
            if ($entry->uuid === $uuid) {
                return $entry->getStringField($key);
            }
        }

        foreach ($this->groups as $group) {
            $value = $group->getStringField($uuid, $key);
            if ($value !== null) {
                return $value;
            }
        }

        return null;
    }

    /**
     * @return list<string>|null
     */
    public function listCustomFields(string $uuid): ?array
    {
        foreach ($this->entries as $entry) {
            if ($entry->uuid === $uuid) {
                return $entry->listCustomFields();
            }
        }

        foreach ($this->groups as $group) {
            $value = $group->listCustomFields($uuid);
            if ($value !== null) {
                return $value;
            }
        }

        return null;
    }

    public function addGroup(self $group): void
    {
        $this->groups[] = $group;
    }

    public function addEntry(Entry $entry): void
    {
        $this->entries[] = $entry;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(Filter $filter): array
    {
        $result = [];
        if ($this->uuid !== null) {
            $result[Database::XML_UUID] = $this->uuid;
        }
        if ($this->name !== null) {
            $result[Database::XML_NAME] = $this->name;
        }
        if ($this->icon !== null && $filter->acceptIcons()) {
            $result[Database::XML_ICONID] = $this->icon;
        }
        if ($this->customIcon !== null && $filter->acceptIcons()) {
            $result[Database::XML_CUSTOMICONUUID] = $this->customIcon;
        }

        $groups = [];
        foreach ($this->groups as $group) {
            if ($filter->acceptGroup($group)) {
                $groups[] = $group->toArray($filter);
            }
        }
        if ($groups !== []) {
            $result[Database::GROUPS] = $groups;
        }

        $entries = [];
        foreach ($this->entries as $entry) {
            if ($filter->acceptEntry($entry)) {
                $entries[] = $entry->toArray($filter);
            }
        }
        if ($entries !== []) {
            $result[Database::ENTRIES] = $entries;
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $array
     * @throws KeePassPHPException
     */
    public static function fromArray(array $array, string $version): self
    {
        if ($array === []) {
            throw new KeePassPHPException('Group array load: array is empty.');
        }

        $group = new self();
        $uuid = Database::getIfSet($array, Database::XML_UUID);
        $name = Database::getIfSet($array, Database::XML_NAME);
        $icon = Database::getIfSet($array, Database::XML_ICONID);
        $customIcon = Database::getIfSet($array, Database::XML_CUSTOMICONUUID);

        $group->uuid = is_string($uuid) ? $uuid : null;
        $group->name = is_string($name) ? $name : null;
        $group->icon = is_string($icon) ? $icon : null;
        $group->customIcon = is_string($customIcon) ? $customIcon : null;

        $groups = Database::getIfSet($array, Database::GROUPS);
        if (is_array($groups)) {
            foreach ($groups as $subgroup) {
                if (is_array($subgroup)) {
                    /** @var array<string, mixed> $subgroup */
                    $group->addGroup(self::fromArray($subgroup, $version));
                }
            }
        }

        $entries = Database::getIfSet($array, Database::ENTRIES);
        if (is_array($entries)) {
            foreach ($entries as $entry) {
                if (is_array($entry)) {
                    /** @var array<string, mixed> $entry */
                    $group->addEntry(Entry::fromArray($entry, $version));
                }
            }
        }

        return $group;
    }

    public static function fromXML(ProtectedXMLReader $reader): self
    {
        $group = new self();
        $depth = $reader->depth();
        while ($reader->read($depth)) {
            if ($reader->isElement(Database::XML_GROUP)) {
                $group->addGroup(self::fromXML($reader));
                continue;
            }

            if ($reader->isElement(Database::XML_ENTRY)) {
                $group->addEntry(Entry::fromXML($reader));
                continue;
            }

            if ($reader->isElement(Database::XML_UUID)) {
                $value = $reader->readTextInside();
                $group->uuid = is_string($value) ? $value : null;
            } elseif ($reader->isElement(Database::XML_NAME)) {
                $value = $reader->readTextInside();
                $group->name = is_string($value) ? $value : null;
            } elseif ($reader->isElement(Database::XML_ICONID)) {
                $value = $reader->readTextInside();
                $group->icon = is_string($value) ? $value : null;
            } elseif ($reader->isElement(Database::XML_CUSTOMICONUUID)) {
                $value = $reader->readTextInside();
                $group->customIcon = is_string($value) ? $value : null;
            }
        }

        return $group;
    }
}
