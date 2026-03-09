<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Contracts\BoxedString;
use KeePassPHP\Contracts\Filter;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Strings\UnprotectedString;

final class Entry
{
    private const string LEGACY_ARRAY_FORMAT_VERSION = '0';

    public ?string $uuid = null;
    public ?string $icon = null;
    public ?string $customIcon = null;
    public ?string $tags = null;
    public ?BoxedString $password = null;

    /** @var array<string, BoxedString> */
    public array $stringFields = [];

    /** @var list<Entry> */
    public array $history = [];

    public function getStringField(string $key): string
    {
        $value = $this->stringFields[$key] ?? null;

        return $value?->getPlainString() ?? '';
    }

    /**
     * @return list<string>
     */
    public function listCustomFields(): array
    {
        $standard = [
            Database::KEY_PASSWORD,
            Database::KEY_TITLE,
            Database::KEY_USERNAME,
            Database::KEY_URL,
            Database::KEY_NOTES,
        ];

        return array_values(array_diff(array_keys($this->stringFields), $standard));
    }

    public function addHistoryEntry(self $entry): void
    {
        $this->history[] = $entry;
    }

    public function setPassword(BoxedString $password): void
    {
        $this->password = $password;
    }

    public function setStringField(string $key, BoxedString $value): void
    {
        if (strcasecmp($key, Database::KEY_PASSWORD) === 0) {
            $this->password = $value;

            return;
        }

        $this->stringFields[$key] = $value;
    }

    private function readString(ProtectedXMLReader $reader): void
    {
        $depth = $reader->depth();
        $key = null;
        $value = null;

        while ($reader->read($depth)) {
            if ($reader->isElement(Database::XML_STRING_KEY)) {
                $keyValue = $reader->readTextInside();
                $key = is_string($keyValue) ? $keyValue : null;
            } elseif ($reader->isElement(Database::XML_STRING_VALUE)) {
                $boxedValue = $reader->readTextInside(true);
                $value = $boxedValue instanceof BoxedString ? $boxedValue : null;
            }
        }

        if ($key === null || $value === null) {
            return;
        }

        if (strcasecmp($key, Database::KEY_PASSWORD) === 0) {
            $this->password = $value;

            return;
        }

        $this->stringFields[$key] = $value;
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
        if ($this->icon !== null && $filter->acceptIcons()) {
            $result[Database::XML_ICONID] = $this->icon;
        }
        if ($this->customIcon !== null && $filter->acceptIcons()) {
            $result[Database::XML_CUSTOMICONUUID] = $this->customIcon;
        }
        if ($this->tags !== null && $filter->acceptTags()) {
            $result[Database::XML_TAGS] = $this->tags;
        }

        $stringFields = [];
        if ($this->password !== null && $filter->acceptPasswords()) {
            $stringFields[Database::KEY_PASSWORD] = $this->password->getPlainString();
        }

        foreach ($this->stringFields as $key => $value) {
            if ($filter->acceptStrings($key)) {
                $stringFields[$key] = $value->getPlainString();
            }
        }

        if ($stringFields !== []) {
            $result[Database::KEY_STRINGFIELDS] = $stringFields;
        }

        $history = [];
        foreach ($this->history as $entry) {
            if ($filter->acceptHistoryEntry($entry)) {
                $history[] = $entry->toArray($filter);
            }
        }
        if ($history !== []) {
            $result[Database::XML_HISTORY] = $history;
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
            throw new KeePassPHPException('Entry array load: array is empty.');
        }

        $entry = new self();
        $uuid = Database::getIfSet($array, Database::XML_UUID);
        $icon = Database::getIfSet($array, Database::XML_ICONID);
        $customIcon = Database::getIfSet($array, Database::XML_CUSTOMICONUUID);
        $tags = Database::getIfSet($array, Database::XML_TAGS);

        $entry->uuid = is_string($uuid) ? $uuid : null;
        $entry->icon = is_string($icon) ? $icon : null;
        $entry->customIcon = is_string($customIcon) ? $customIcon : null;
        $entry->tags = is_string($tags) ? $tags : null;

        if (version_compare($version, self::LEGACY_ARRAY_FORMAT_VERSION, '<=')) {
            foreach ([Database::KEY_TITLE, Database::KEY_USERNAME, Database::KEY_URL] as $key) {
                $value = Database::getIfSet($array, $key);
                if (is_string($value)) {
                    $entry->stringFields[$key] = new UnprotectedString($value);
                }
            }
        } else {
            $stringFields = Database::getIfSet($array, Database::KEY_STRINGFIELDS);
            if (is_array($stringFields)) {
                foreach ($stringFields as $key => $value) {
                    if (is_string($key) && is_string($value)) {
                        $entry->stringFields[$key] = new UnprotectedString($value);
                    }
                }
            }
        }

        $history = Database::getIfSet($array, Database::XML_HISTORY);
        if (is_array($history)) {
            foreach ($history as $historyEntry) {
                if (is_array($historyEntry)) {
                    /** @var array<string, mixed> $historyEntry */
                    $entry->addHistoryEntry(self::fromArray($historyEntry, $version));
                }
            }
        }

        return $entry;
    }

    public static function fromXML(ProtectedXMLReader $reader): self
    {
        $entry = new self();
        $depth = $reader->depth();
        while ($reader->read($depth)) {
            if ($reader->isElement(Database::XML_STRING)) {
                $entry->readString($reader);
                continue;
            }

            if ($reader->isElement(Database::XML_HISTORY)) {
                $historyDepth = $reader->depth();
                while ($reader->read($historyDepth)) {
                    if ($reader->isElement(Database::XML_ENTRY)) {
                        $entry->addHistoryEntry(self::fromXML($reader));
                    }
                }
                continue;
            }

            if ($reader->isElement(Database::XML_UUID)) {
                $value = $reader->readTextInside();
                $entry->uuid = is_string($value) ? $value : null;
            } elseif ($reader->isElement(Database::XML_ICONID)) {
                $value = $reader->readTextInside();
                $entry->icon = is_string($value) ? $value : null;
            } elseif ($reader->isElement(Database::XML_CUSTOMICONUUID)) {
                $value = $reader->readTextInside();
                $entry->customIcon = is_string($value) ? $value : null;
            } elseif ($reader->isElement(Database::XML_TAGS)) {
                $value = $reader->readTextInside();
                $entry->tags = is_string($value) ? $value : null;
            }
        }

        return $entry;
    }
}
