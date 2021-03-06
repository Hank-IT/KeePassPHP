<?php

namespace KeePassPHP;

use KeePassPHP\Contracts\Filter;
use KeePassPHP\Contracts\Key;
use KeePassPHP\Contracts\RandomStream;
use KeePassPHP\Filters\AllExceptFromPasswordsFilter;
use KeePassPHP\Readers\Reader;

/**
 * A class that manages a KeePass 2.x password database.
 *
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 *
 * @link       https://github.com/shkdee/KeePassPHP
 */
class Database
{
    const XML_KEEPASSFILE = 'KeePassFile';
    const XML_META = 'Meta';
    const XML_HEADERHASH = 'HeaderHash';
    const XML_DATABASENAME = 'DatabaseName';
    const XML_CUSTOMICONS = 'CustomIcons';
    const XML_ICON = 'Icon';
    const XML_UUID = 'UUID';
    const XML_DATA = 'Data';
    const XML_ROOT = 'Root';
    const XML_GROUP = 'Group';
    const XML_ENTRY = 'Entry';
    const XML_NAME = 'Name';
    const XML_ICONID = 'IconID';
    const XML_CUSTOMICONUUID = 'CustomIconUUID';
    const XML_STRING = 'String';
    const XML_STRING_KEY = 'Key';
    const XML_STRING_VALUE = 'Value';
    const XML_HISTORY = 'History';
    const XML_TAGS = 'Tags';

    const KEY_PASSWORD = 'Password';
    const KEY_STRINGFIELDS = 'StringFields';
    const KEY_TITLE = 'Title';
    const KEY_USERNAME = 'UserName';
    const KEY_URL = 'URL';
    const KEY_NOTES = 'Notes';

    const GROUPS = 'Groups';
    const ENTRIES = 'Entries';

    protected $name;
    protected $groups;

    /** Associative array (icon uuid in base64 => icon data in base64) keeping
     * the data of all custom icons. */
    protected $customIcons;

    /** Header hash registered in this database. */
    protected $headerHash;

    private function __construct()
    {
        $this->name = null;
        $this->groups = null;
        $this->customIcons = null;
        $this->headerHash = null;
    }

    /**
     * Gets the name of this database.
     *
     * @return string This database name.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Gets the groups of this database.
     *
     * @return array An array of Group instances.
     */
    public function getGroups(): array
    {
        return $this->groups;
    }

    /**
     * Gets the data of the custom icon whose uuid is $uuid.
     *
     * @param string $uuid A custom icon uuid in base64.
     *
     * @return string|null A custom icon data in base64 if it exists, null otherwise.
     */
    public function getCustomIcon(string $uuid): ?string
    {
        return $this->customIcons == null ? null
            : 'data:image/png;base64,'.$this->customIcons[$uuid];
    }

    /**
     * Gets the password of the entry whose uuid is $uuid.
     *
     * @param string $uuid An entry uuid in base64.
     *
     * @return string|null The decrypted password if the entry exists, null otherwise.
     */
    public function getPassword(string $uuid): ?string
    {
        if (is_null($this->groups)) {
            return null;
        }

        foreach ($this->groups as &$group) {
            if (! is_null($value = $group->getPassword($uuid))) {
                return $value->getPlainString();
            }
        }

        return null;
    }

    /**
     * Gets the string field value of the entry whose uuid is $uuid.
     *
     * @param string $uuid An entry uuid in base64.
     * @param string $key  A key.
     *
     * @return string|null A string of value the field if the entry if exists,
     *                     an empty string if the entry exists but the string field,
     *                     null if entry does not exists.
     */
    public function getStringField(string $uuid, string $key): ?string
    {
        if (is_null($this->groups)) {
            return null;
        }

        foreach ($this->groups as &$group) {
            if (! is_null( $value = $group->getStringField($uuid, $key))) {
                return $value;
            }
        }

        return null;
    }

    /**
     * List custom string field variables of the entry whose uuid is $uuid.
     *
     * @param string $uuid An entry uuid in base64.
     *
     * @return string|null A list of custom fields if the entry exists, null if entry does not exists.
     */
    public function listCustomFields(string $uuid): ?string
    {
        if (is_null($this->groups)) {
            return null;
        }

        foreach ($this->groups as &$group) {
            if (! is_null($value = $group->listCustomFields($uuid))) {
                return $value;
            }
        }

        return null;
    }

    /**
     * Parses a custom icon XML element node, and adds the result to the
     * $customIcons array.
     *
     * @param ProtectedXMLReader $reader A ProtectedXMLReader instance located at a custom icon element node.
     */
    protected function parseCustomIcon(ProtectedXMLReader $reader): void
    {
        $uuid = null;
        $data = null;
        $d = $reader->depth();

        while ($reader->read($d)) {
            if ($reader->isElement(self::XML_UUID)) {
                $uuid = $reader->readTextInside();
            } elseif ($reader->isElement(self::XML_DATA)) {
                $data = $reader->readTextInside();
            }
        }

        if (!empty($uuid) && !empty($data)) {
            if ($this->customIcons == null) {
                $this->customIcons = [];
            }
            $this->customIcons[$uuid] = $data;
        }
    }

    /**
     * Adds a Group instance to this Database.
     *
     * @param Group|null $group A Group instance, possibly null (it is then ignored).
     */
    protected function addGroup(?Group $group): void
    {
        if (is_null($group)) {
            return;
        }

        if (is_null($this->groups)) {
            $this->groups = [];
        }

        $this->groups[] = $group;
    }

    /**
     * Loads the content of a Database from a ProtectedXMLReader instance
     * reading a KeePass 2.x database and located at a KeePass file element
     * node.
     *
     * @param ProtectedXMLReader $reader A XML reader.
     */
    protected function parseXML(ProtectedXMLReader $reader): void
    {
        $d = $reader->depth();
        while ($reader->read($d)) {
            if ($reader->isElement(self::XML_META)) {
                $metaD = $reader->depth();
                while ($reader->read($metaD)) {
                    if ($reader->isElement(self::XML_HEADERHASH)) {
                        $this->headerHash = base64_decode($reader->readTextInside());
                    } elseif ($reader->isElement(self::XML_DATABASENAME)) {
                        $this->name = $reader->readTextInside();
                    } elseif ($reader->isElement(self::XML_CUSTOMICONS)) {
                        $iconsD = $reader->depth();
                        while ($reader->read($iconsD)) {
                            if ($reader->isElement(self::XML_ICON)) {
                                $this->parseCustomIcon($reader);
                            }
                        }
                    }
                }
            } elseif ($reader->isElement(self::XML_ROOT)) {
                $rootD = $reader->depth();
                while ($reader->read($rootD)) {
                    if ($reader->isElement(self::XML_GROUP)) {
                        $this->addGroup(Group::loadFromXML($reader));
                    }
                }
            }
        }
    }

    /**
     * Creates an array describing this database (with respect to the filter).
     * This array can be safely serialized to json after.
     *
     * @param Filter|null $filter A filter to select the data that is actually copied to
     *                       the array (if null, it will serialize everything except
     *                       from passowrds).
     *
     * @return array An array containing this database (except passwords).
     */
    public function toArray(Filter $filter = null): array
    {
        if (is_null($filter)) {
            $filter = new AllExceptFromPasswordsFilter();
        }

        $result = [];
        if (! is_null($this->name)) {
            $result[self::XML_DATABASENAME] = $this->name;
        }

        if (! is_null($this->customIcons) && $filter->acceptIcons()) {
            $result[self::XML_CUSTOMICONS] = $this->customIcons;
        }

        if (! is_null($this->groups)) {
            $groups = [];
            foreach ($this->groups as &$group) {
                if ($filter->acceptGroup($group)) {
                    $groups[] = $group->toArray($filter);
                }
            }

            if (! empty($groups)) {
                $result[self::GROUPS] = $groups;
            }
        }

        return $result;
    }

    /**
     * Creates a new Database instance from an array created by the method
     * toArray() of another Database instance.
     *
     * @param array  $array   An array created by the method toArray().
     * @param string $version The version of the array format.
     * @param string &$error  A string that will receive a message in case of error.
     *
     * @return self|null A Database instance if the parsing went okay, null otherwise.
     */
    public static function loadFromArray(array $array, $version, &$error): ?self
    {
        if ($array == null) {
            $error = 'Database array load: array is empty.';

            return null;
        }

        $db = new Database();
        $db->name = self::getIfSet($array, self::XML_DATABASENAME);
        $db->customIcons = self::getIfSet($array, self::XML_CUSTOMICONS);
        $groups = self::getIfSet($array, self::GROUPS);

        if (!empty($groups)) {
            foreach ($groups as &$group) {
                $db->addGroup(Group::loadFromArray($group, $version));
            }
        }

        if (is_null($db->name) && is_null($db->groups)) {
            $error = 'Database array load: empty database.';

            return null;
        }

        $error = null;

        return $db;
    }

    /**
     * Creates a new Database instance from an XML string with the format of
     * a KeePass 2.x database.
     *
     * @param string       $xml          An XML string.
     * @param RandomStream $randomStream A RandomStream instance to decrypt protected data.
     * @param string       &$error       A string that will receive a message in case of error.
     *
     * @return self|null A Database instance if the parsing went okay, null otherwise.
     */
    public static function loadFromXML($xml, RandomStream $randomStream, &$error): ?self
    {
        $reader = new ProtectedXMLReader($randomStream);

        if (! $reader->XML($xml) || ! $reader->read(-1)) {
            $error = 'Database XML load: cannot parse the XML string.';
            $reader->close();

            return null;
        }

        if (! $reader->isElement(self::XML_KEEPASSFILE)) {
            $error = "Database XML load: the root element is not '".self::XML_KEEPASSFILE."'.";
            $reader->close();

            return null;
        }

        $db = new Database();
        $db->parseXML($reader);
        $reader->close();

        if (is_null($db->name) && is_null($db->groups)) {
            $error = 'Database XML load: empty database.';

            return null;
        }

        $error = null;

        return $db;
    }

    /**
     * Creates a new Database instance from a .kdbx (KeePass 2.x) file.
     *
     * @param Reader $reader A Reader instance that reads a .kdbx file.
     * @param Key    $key    A Key instance to use to decrypt the .kdbx file.
     * @param string &$error A string that will receive a message in case of error.
     *
     * @return self|null A Database instance if the parsing went okay, null otherwise.
     */
    public static function loadFromKdbx(Reader $reader, Key $key, &$error): ?self
    {
        $kdbx = KdbxFile::decrypt($reader, $key, $error);

        if (is_null($kdbx)) {
            return null;
        }

        $db = self::loadFromXML($kdbx->getContent(), $kdbx->getRandomStream(), $error);

        if (is_null($db)) {
            return null;
        }

        if ($db->headerHash !== $kdbx->getHeaderHash()) {
            $error = 'Database Kdbx load: header hash is not correct.';

            return null;
        }

        return $db;
    }

    /**
     * Returns $array[$key] if it exists, null otherwise.
     *
     * @param array  $array An array.
     * @param string $key   An array key.
     *
     * @return mixed $array[$key] if it exists, null otherwise.
     */
    public static function getIfSet(array $array, $key)
    {
        return isset($array[$key]) ? $array[$key] : null;
    }
}
