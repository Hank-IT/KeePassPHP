# Breaking Changes

This file tracks breaking changes introduced during the development leading to the v1 release.

## Platform

- Minimum PHP version is now `8.4`.
- Composer platform requirements are now explicit:
  - `ext-hash`
  - `ext-json`
  - `ext-openssl`
  - `ext-xmlreader`
  - `ext-zlib`

## Error Handling

Several APIs have been moved away from "nullable return value + error message filled by reference" patterns.

### `Database`

The following methods now throw `KeePassPHP\Exceptions\KeePassPHPException` on failure instead of returning `null` and filling `?string &$error`:

- `Database::fromArray()`
- `Database::fromXML()`
- `Database::fromKdbx()`

### `Entry`

The following methods now throw `KeePassPHP\Exceptions\KeePassPHPException` on failure instead of returning `null`:

- `Entry::fromArray()`

### `Group`

The following methods now throw `KeePassPHP\Exceptions\KeePassPHPException` on failure instead of returning `null`:

- `Group::fromArray()`

### `KdbxFile`

The following public APIs now throw `KeePassPHP\Exceptions\KeePassPHPException` on failure instead of returning `null` / `false` and filling `?string &$error`:

- `KdbxFile::forEncryption()`
- `KdbxFile::prepareForEncryption()`
- `KdbxFile::encrypt()`
- `KdbxFile::decrypt()`

`KdbxFile` is now a version-dispatch entrypoint instead of the concrete implementation for all KDBX handling.

- KDBX 3 logic now lives in `Kdbx3File`.
- KDBX 4 logic now lives in `Kdbx4File`.
- `KdbxFile::forEncryption()` returns a `Kdbx3File`.
- `KdbxFile::decrypt()` returns `KeePassPHP\Contracts\OpenedKdbxFile`.

### `KdbxHeader`

The header reader now throws `KeePassPHP\Exceptions\KeePassPHPException` on failure instead of returning `null` and filling `?string &$error`:

- `KdbxHeader::fromReader()`

Previous style:

```php
$error = null;
$database = Database::loadFromXML($xml, $randomStream, $error);

if ($database === null) {
    // inspect $error
}
```

Current style:

```php
use KeePassPHP\Database;
use KeePassPHP\Exceptions\KeePassPHPException;

try {
    $database = Database::fromXML($xml, $randomStream);
} catch (KeePassPHPException $exception) {
    // inspect $exception->getMessage()
}
```

### `KeyFromFile`

`KeyFromFile` now follows a construct-or-throw model.

- The public `isParsed` flag has been removed.
- Invalid key-file content now throws `KeePassPHP\Exceptions\KeePassPHPException` from the constructor.

Previous style:

```php
$key = new KeyFromFile($content);
if (! $key->isParsed) {
    // handle error
}
```

Current style:

```php
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Keys\KeyFromFile;

try {
    $key = new KeyFromFile($content);
} catch (KeePassPHPException $exception) {
    // handle error
}
```

## Renamed Factory Methods

The `Database` factory-style methods were renamed to drop the old `load` prefix:

- `Database::loadFromArray()` -> `Database::fromArray()`
- `Database::loadFromXML()` -> `Database::fromXML()`
- `Database::loadFromKdbx()` -> `Database::fromKdbx()`

The `Entry` factory-style methods were also renamed:

- `Entry::loadFromArray()` -> `Entry::fromArray()`
- `Entry::loadFromXML()` -> `Entry::fromXML()`

The `Group` factory-style methods were also renamed:

- `Group::loadFromArray()` -> `Group::fromArray()`
- `Group::loadFromXML()` -> `Group::fromXML()`

The `KdbxFile` encryption factory and preparation methods were also renamed:

- `KdbxFile::createForEncrypting()` -> `KdbxFile::forEncryption()`
- `KdbxFile::prepareEncrypting()` -> `KdbxFile::prepareForEncryption()`

The `KdbxHeader` reader factory was also renamed:

- `KdbxHeader::load()` -> `KdbxHeader::fromReader()`

## Contract and Namespace Changes

### `Cipher`

The old `KeePassPHP\Cipher\Cipher` abstract class/factory is gone.

- The cipher contract now lives at `KeePassPHP\Contracts\Cipher`.
- The OpenSSL implementation is `KeePassPHP\Cipher\CipherOpenSSL`.
- `Cipher::create(...)` was removed.
- The old mutable setter API was removed.

If you instantiated or configured ciphers manually, update usage to construct `CipherOpenSSL` directly.

### `Key`

The old `iKey` interface is no longer used.

- Use `KeePassPHP\Contracts\Key` instead.

### `OpenedKdbxFile`

A new contract now represents opened/decrypted KDBX payloads:

- `KeePassPHP\Contracts\OpenedKdbxFile`

If you previously assumed that `KdbxFile::decrypt()` always returned a concrete `KdbxFile` instance, update consumers to depend on the shared contract or the version-specific classes.

## Immutability and Final Classes

A number of classes were tightened as part of the refactor. Extending them is now unsupported where they were marked `final`, and mutating them after construction may no longer be possible.

- `KeePassPHP\Database`
- `KeePassPHP\Entry`
- `KeePassPHP\Group`
- `KeePassPHP\KdbxHeader`
- `KeePassPHP\KdbxFile`
- `KeePassPHP\Keys\KeyFromPassword`
- `KeePassPHP\ProtectedXMLReader`
- `KeePassPHP\Readers\DigestReader`
- `KeePassPHP\Readers\HashedBlockReader`
- `KeePassPHP\Readers\ResourceReader`
- `KeePassPHP\Readers\StringReader`
- `KeePassPHP\Streams\Salsa20RandomStream`
- `KeePassPHP\Strings\ProtectedString`
- `KeePassPHP\Strings\UnprotectedString`

## Behavioral Changes

### `KeyFromFile`

KeePass key-file handling is stricter and closer to current KeePass behavior:

- XML `2.x` key files support hexadecimal `<Data>` values.
- XML `2.x` key files verify the optional `Hash` attribute on `<Data>`.
- Non-XML key files now fall back to KeePass-style `SHA-256` hashing when they are not raw 32-byte keys or 64-character hex keys.

### `HashedBlockReader`

`HashedBlockReader::hashString()` now writes the canonical terminating zero-length block expected by KeePass hashed-block streams.

### `DigestReader`

`DigestReader::getDigest()` is now non-destructive. Calling it no longer finalizes the internal digest state.

### `Salsa20RandomStream`

The Salsa20 block counter increment logic was corrected. If you depended on the previous incorrect counter behavior, generated output after enough blocks will differ.

### `KDBX 4`

The library can now decrypt KDBX 4.1 databases when they use:

- outer cipher `AES-256`
- KDF `AES-KDF`

Current limitations:

- outer `ChaCha20` is not supported
- `Argon2d` is unsupported and decrypting such files throws an exception
- `Argon2id` is unsupported and decrypting such files throws an exception
