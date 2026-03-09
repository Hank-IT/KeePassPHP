<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Contracts\Filter;
use KeePassPHP\Contracts\Key;
use KeePassPHP\Contracts\RandomStream;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Filters\AllExceptFromPasswordsFilter;
use KeePassPHP\Readers\Reader;

final class Database
{
    public const string XML_KEEPASSFILE = 'KeePassFile';
    public const string XML_META = 'Meta';
    public const string XML_HEADERHASH = 'HeaderHash';
    public const string XML_DATABASENAME = 'DatabaseName';
    public const string XML_CUSTOMICONS = 'CustomIcons';
    public const string XML_ICON = 'Icon';
    public const string XML_UUID = 'UUID';
    public const string XML_DATA = 'Data';
    public const string XML_ROOT = 'Root';
    public const string XML_GROUP = 'Group';
    public const string XML_ENTRY = 'Entry';
    public const string XML_NAME = 'Name';
    public const string XML_ICONID = 'IconID';
    public const string XML_CUSTOMICONUUID = 'CustomIconUUID';
    public const string XML_STRING = 'String';
    public const string XML_STRING_KEY = 'Key';
    public const string XML_STRING_VALUE = 'Value';
    public const string XML_HISTORY = 'History';
    public const string XML_TAGS = 'Tags';

    public const string KEY_PASSWORD = 'Password';
    public const string KEY_STRINGFIELDS = 'StringFields';
    public const string KEY_TITLE = 'Title';
    public const string KEY_USERNAME = 'UserName';
    public const string KEY_URL = 'URL';
    public const string KEY_NOTES = 'Notes';

    public const string GROUPS = 'Groups';
    public const string ENTRIES = 'Entries';

    protected ?string $name = null;

    /** @var list<Group> */
    protected array $groups = [];

    /** @var array<string, string> */
    protected array $customIcons = [];

    protected ?string $headerHash = null;

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    /**
     * @return list<Group>
     */
    public function getGroups(): array
    {
        return $this->groups;
    }

    /**
     * @return array<string, string>
     */
    public function getCustomIcons(): array
    {
        return $this->customIcons;
    }

    public function getCustomIcon(string $uuid): ?string
    {
        if (! isset($this->customIcons[$uuid])) {
            return null;
        }

        return 'data:image/png;base64,' . $this->customIcons[$uuid];
    }

    public function setCustomIcon(string $uuid, string $data): void
    {
        $this->customIcons[$uuid] = $data;
    }

    public function getPassword(string $uuid): ?string
    {
        foreach ($this->groups as $group) {
            $value = $group->getPassword($uuid);
            if ($value !== null) {
                return $value->getPlainString();
            }
        }

        return null;
    }

    public function getStringField(string $uuid, string $key): ?string
    {
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
        foreach ($this->groups as $group) {
            $value = $group->listCustomFields($uuid);
            if ($value !== null) {
                return $value;
            }
        }

        return null;
    }

    protected function parseCustomIcon(ProtectedXMLReader $reader): void
    {
        $uuid = null;
        $data = null;
        $depth = $reader->depth();

        while ($reader->read($depth)) {
            if ($reader->isElement(self::XML_UUID)) {
                $uuidValue = $reader->readTextInside();
                $uuid = is_string($uuidValue) ? $uuidValue : null;
            } elseif ($reader->isElement(self::XML_DATA)) {
                $dataValue = $reader->readTextInside();
                $data = is_string($dataValue) ? $dataValue : null;
            }
        }

        if ($uuid !== null && $data !== null) {
            $this->customIcons[$uuid] = $data;
        }
    }

    public function addGroup(Group $group): void
    {
        $this->groups[] = $group;
    }

    protected function parseXML(ProtectedXMLReader $reader): void
    {
        $depth = $reader->depth();
        while ($reader->read($depth)) {
            if ($reader->isElement(self::XML_META)) {
                $metaDepth = $reader->depth();
                while ($reader->read($metaDepth)) {
                    if ($reader->isElement(self::XML_HEADERHASH)) {
                        $headerHashValue = $reader->readTextInside();
                        $decodedHash = is_string($headerHashValue)
                            ? base64_decode($headerHashValue, true)
                            : false;
                        $this->headerHash = $decodedHash === false ? null : $decodedHash;
                    } elseif ($reader->isElement(self::XML_DATABASENAME)) {
                        $nameValue = $reader->readTextInside();
                        $this->name = is_string($nameValue) ? $nameValue : null;
                    } elseif ($reader->isElement(self::XML_CUSTOMICONS)) {
                        $iconsDepth = $reader->depth();
                        while ($reader->read($iconsDepth)) {
                            if ($reader->isElement(self::XML_ICON)) {
                                $this->parseCustomIcon($reader);
                            }
                        }
                    }
                }
                continue;
            }

            if ($reader->isElement(self::XML_ROOT)) {
                $rootDepth = $reader->depth();
                while ($reader->read($rootDepth)) {
                    if ($reader->isElement(self::XML_GROUP)) {
                        $this->addGroup(Group::fromXML($reader));
                    }
                }
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(?Filter $filter = null): array
    {
        $filter ??= new AllExceptFromPasswordsFilter();

        $result = [];
        if ($this->name !== null) {
            $result[self::XML_DATABASENAME] = $this->name;
        }

        if ($this->customIcons !== [] && $filter->acceptIcons()) {
            $result[self::XML_CUSTOMICONS] = $this->customIcons;
        }

        $groups = [];
        foreach ($this->groups as $group) {
            if ($filter->acceptGroup($group)) {
                $groups[] = $group->toArray($filter);
            }
        }

        if ($groups !== []) {
            $result[self::GROUPS] = $groups;
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
            throw new KeePassPHPException('Database array load: array is empty.');
        }

        $db = new self();
        $name = self::getIfSet($array, self::XML_DATABASENAME);
        $customIcons = self::getIfSet($array, self::XML_CUSTOMICONS);
        $groups = self::getIfSet($array, self::GROUPS);

        $db->name = is_string($name) ? $name : null;

        if (is_array($customIcons)) {
            foreach ($customIcons as $uuid => $iconData) {
                if (is_string($uuid) && is_string($iconData)) {
                    $db->customIcons[$uuid] = $iconData;
                }
            }
        }

        if (is_array($groups)) {
            foreach ($groups as $group) {
                if (is_array($group)) {
                    /** @var array<string, mixed> $group */
                    $db->addGroup(Group::fromArray($group, $version));
                }
            }
        }

        if ($db->name === null && $db->groups === []) {
            throw new KeePassPHPException('Database array load: empty database.');
        }

        return $db;
    }

    public static function fromXML(string $xml, ?RandomStream $randomStream): self
    {
        $reader = new ProtectedXMLReader($randomStream);

        if (! $reader->XML($xml) || ! $reader->read(-1)) {
            $reader->close();

            throw new KeePassPHPException('Database XML load: cannot parse the XML string.');
        }

        if (! $reader->isElement(self::XML_KEEPASSFILE)) {
            $reader->close();

            throw new KeePassPHPException(
                "Database XML load: the root element is not '" . self::XML_KEEPASSFILE . "'."
            );
        }

        $db = new self();
        $db->parseXML($reader);
        $reader->close();

        if ($db->name === null && $db->groups === []) {
            throw new KeePassPHPException('Database XML load: empty database.');
        }

        return $db;
    }

    public static function fromKdbx(Reader $reader, Key $key): self
    {
        $kdbx = KdbxFile::decrypt($reader, $key);

        $content = $kdbx->getContent();
        if ($content === null) {
            throw new KeePassPHPException('Database Kdbx load: decrypted content is empty.');
        }

        $db = self::fromXML($content, $kdbx->getRandomStream());

        if ($kdbx->getMajorVersion() === 3 && $db->headerHash !== $kdbx->getHeaderHash()) {
            throw new KeePassPHPException('Database Kdbx load: header hash is not correct.');
        }

        return $db;
    }

    public function toKdbx4(Key $key, ?Kdbx4WriteOptions $options = null): string
    {
        return Kdbx4Writer::write($this, $key, $options);
    }

    /**
     * @param array<string, mixed> $array
     */
    public static function getIfSet(array $array, string $key): mixed
    {
        return $array[$key] ?? null;
    }
}
