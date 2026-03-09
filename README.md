# KeePassPHP

KeePassPHP is a PHP library for reading and writing KeePass `.kdbx` databases.

It can:

- inspect KDBX files without decrypting them
- open KeePass 2.x databases and map them to PHP objects
- read groups, entries, passwords, custom fields, and custom icons
- write new KDBX 4.1 databases from the in-memory `Database` model
- work with password keys, key files, and composite keys

It currently supports:

- KDBX 3.x
- KDBX 4.0 / 4.1 when the database uses:
  - outer cipher `AES-256`
  - KDF `AES-KDF`

It does not currently support:

- KDBX 4 databases using `Argon2d`
- KDBX 4 databases using `Argon2id`
- KDBX 4 databases using outer `ChaCha20`

## Requirements

- PHP `>= 8.4`
- `ext-hash`
- `ext-json`
- `ext-openssl`
- `ext-sodium`
- `ext-xmlreader`
- `ext-zlib`

## Installation

```bash
composer require hankit/keepassphp
```

## Quick Start

Open a KeePass database directly:

```php
<?php

use KeePassPHP\Database;
use KeePassPHP\Keys\KeyFromPassword;
use KeePassPHP\Readers\ResourceReader;

$reader = ResourceReader::openFile('/path/to/database.kdbx');
if ($reader === null) {
    throw new RuntimeException('Unable to open database file.');
}

try {
    $database = Database::fromKdbx(
        $reader,
        new KeyFromPassword('secret', 'SHA256'),
    );
} finally {
    $reader->close();
}

echo $database->getName();
echo $database->getPassword('entry-uuid');
```

Use a key file:

```php
<?php

use KeePassPHP\Database;
use KeePassPHP\Keys\KeyFromFile;
use KeePassPHP\Readers\ResourceReader;

$reader = ResourceReader::openFile('/path/to/database.kdbx');
if ($reader === null) {
    throw new RuntimeException('Unable to open database file.');
}

$keyFileContent = file_get_contents('/path/to/database.keyx');
if ($keyFileContent === false) {
    throw new RuntimeException('Unable to read key file.');
}

try {
    $database = Database::fromKdbx(
        $reader,
        new KeyFromFile($keyFileContent),
    );
} finally {
    $reader->close();
}
```

Use a composite key:

```php
<?php

use KeePassPHP\Database;
use KeePassPHP\Keys\CompositeKey;
use KeePassPHP\Keys\KeyFromFile;
use KeePassPHP\Keys\KeyFromPassword;
use KeePassPHP\Readers\ResourceReader;

$reader = ResourceReader::openFile('/path/to/database.kdbx');
if ($reader === null) {
    throw new RuntimeException('Unable to open database file.');
}

$keyFileContent = file_get_contents('/path/to/database.keyx');
if ($keyFileContent === false) {
    throw new RuntimeException('Unable to read key file.');
}

$key = new CompositeKey('SHA256');
$key->addKey(new KeyFromPassword('secret', 'SHA256'));
$key->addKey(new KeyFromFile($keyFileContent));

try {
    $database = Database::fromKdbx($reader, $key);
} finally {
    $reader->close();
}
```

## Inspecting A Database

`KdbxInspector` can read the outer header and tell you what kind of database you are dealing with before you try to decrypt it.

```php
<?php

use KeePassPHP\KdbxInspector;

$metadata = KdbxInspector::inspectFile('/path/to/database.kdbx');

var_dump([
    'format' => $metadata->formatLabel,
    'cipher' => $metadata->cipherName,
    'kdf' => $metadata->kdfName,
    'compressed' => $metadata->isCompressed,
    'decryptable_here' => $metadata->isDecryptableByCurrentLibrary,
]);
```

For KDBX 3.x this also reports the inner random stream. For KDBX 4.x it reports the outer header information that is available without decrypting the payload.

## Reading Data

The `Database` model gives you access to the parsed tree:

```php
<?php

foreach ($database->getGroups() as $group) {
    // Traverse groups and entries from here.
}

$password = $database->getPassword('entry-uuid');
$username = $database->getStringField('entry-uuid', 'UserName');
$customFields = $database->listCustomFields('entry-uuid');
```

You can also serialize the parsed database to arrays:

```php
<?php

$data = $database->toArray();
```

## Creating Databases

New databases are created by building a `Database` object graph in memory and then writing it as KDBX 4.1.

At a minimum you usually:

1. create a `Database`
2. create one or more `Group` objects
3. create `Entry` objects and attach them to groups
4. write the database with `Database::toKdbx4()`

Example:

```php
<?php

use KeePassPHP\Database;
use KeePassPHP\Entry;
use KeePassPHP\Group;
use KeePassPHP\Keys\KeyFromPassword;
use KeePassPHP\Strings\UnprotectedString;

$database = new Database();
$database->setName('Company Vault');

$root = new Group();
$root->uuid = base64_encode(random_bytes(16));
$root->name = 'Root';

$servers = new Group();
$servers->uuid = base64_encode(random_bytes(16));
$servers->name = 'Servers';

$entry = new Entry();
$entry->uuid = base64_encode(random_bytes(16));
$entry->tags = 'production;linux';
$entry->setStringField(Database::KEY_TITLE, new UnprotectedString('Web 01'));
$entry->setStringField(Database::KEY_USERNAME, new UnprotectedString('deploy'));
$entry->setStringField(Database::KEY_URL, new UnprotectedString('ssh://web-01.internal'));
$entry->setStringField('Environment', new UnprotectedString('production'));
$entry->setPassword(new UnprotectedString('secret-password'));

$servers->addEntry($entry);
$root->addGroup($servers);
$database->addGroup($root);

$payload = $database->toKdbx4(
    new KeyFromPassword('master-password', 'SHA256'),
);
```

Useful model methods:

- `Database::setName()` sets the database name shown in KeePass
- `Database::addGroup()` adds a top-level group
- `Database::setCustomIcon()` registers a custom icon by UUID
- `Group::addGroup()` adds a child group
- `Group::addEntry()` adds an entry
- `Entry::setPassword()` sets the password field
- `Entry::setStringField()` sets standard or custom string fields
- `Entry::addHistoryEntry()` adds a history item

Notes:

- `uuid`, `customIcon`, and related UUID fields are expected to be base64-encoded 16-byte values, matching the KeePass XML format
- if you do not set a UUID on a group or entry, the writer will generate a deterministic UUID from the current value or a random UUID if the field is empty
- password values are written as protected values in KDBX 4 output
- non-password string fields are written as plain string values unless you pass a protected boxed string yourself

You can control KDBX 4 writing with `Kdbx4WriteOptions`:

```php
<?php

use KeePassPHP\Kdbx4WriteOptions;

$payload = $database->toKdbx4(
    new KeyFromPassword('master-password', 'SHA256'),
    new Kdbx4WriteOptions(
        rounds: 10000,
        compress: true,
    ),
);
```

## Encryption Support

The low-level `KdbxFile` entrypoint can decrypt both supported KDBX 3 and KDBX 4 files and dispatches to the correct implementation automatically.

Creating encrypted files in the old KDBX 3 format is available through `KdbxFile::forEncryption()`:

```php
<?php

use KeePassPHP\KdbxFile;
use KeePassPHP\Keys\KeyFromPassword;

$file = KdbxFile::forEncryption(6000);
$payload = $file->encrypt('<KeePassFile />', new KeyFromPassword('secret', 'SHA256'));
```

Creating KDBX 4.1 databases is available through the `Database` model:

```php
<?php

use KeePassPHP\Database;
use KeePassPHP\Entry;
use KeePassPHP\Group;
use KeePassPHP\Kdbx4WriteOptions;
use KeePassPHP\Keys\KeyFromPassword;
use KeePassPHP\Strings\UnprotectedString;

$database = new Database();
$database->setName('Generated Database');

$root = new Group();
$root->name = 'Root';

$entry = new Entry();
$entry->setStringField(Database::KEY_TITLE, new UnprotectedString('Example'));
$entry->setStringField(Database::KEY_USERNAME, new UnprotectedString('alice'));
$entry->setPassword(new UnprotectedString('secret-password'));

$root->addEntry($entry);
$database->addGroup($root);

$payload = $database->toKdbx4(
    new KeyFromPassword('master-password', 'SHA256'),
    new Kdbx4WriteOptions(),
);
```

## Supported Formats

### KDBX 3.x

Supported for reading and decryption.

Supported for low-level encryption through `KdbxFile::forEncryption()`.

### KDBX 4.0 / 4.1

Supported for reading and decryption when the outer header uses:

- cipher `AES-256`
- KDF `AES-KDF`

Inner protected values are supported for the current KDBX 4 read path, including KeePass files that use `ChaCha20` as the inner random stream.

Supported for writing in KDBX 4.1 with:

- outer cipher `AES-256`
- KDF `AES-KDF`
- inner random stream `Salsa20` by default

## Limitations

- KDBX 4 with `Argon2d` throws an exception during decryption
- KDBX 4 with `Argon2id` throws an exception during decryption
- KDBX 4 with outer `ChaCha20` throws an exception during decryption
- KDBX 4 writing currently targets `4.1` with `AES-KDF` and outer `AES-256` only
- database name and other XML metadata are only available after successful decryption

## Error Handling

The modernized API throws exceptions for invalid input, unsupported formats, and decryption failures.

The main exception type is:

- `KeePassPHP\Exceptions\KeePassPHPException`

## Development

```bash
composer test
composer stan
composer cs:check
composer cs:fix
composer check
```

There is also an opt-in local playground for manually testing real databases:

```bash
cp playground/keepass-databases.php.dist playground/keepass-databases.php
# edit playground/keepass-databases.php
composer test:playground
```

## Breaking Changes

Recent API and behavior changes are documented in [`BREAKING_CHANGES.md`](BREAKING_CHANGES.md).

## License

MIT
