<?php

declare(strict_types=1);

namespace KeePassPHP;

use DateTimeImmutable;
use DateTimeZone;
use KeePassPHP\Cipher\CipherOpenSSL;
use KeePassPHP\Contracts\BoxedString;
use KeePassPHP\Contracts\Cipher;
use KeePassPHP\Contracts\Key;
use KeePassPHP\Contracts\RandomStream;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Streams\ChaCha20RandomStream;
use KeePassPHP\Streams\Salsa20RandomStream;
use KeePassPHP\Strings\ProtectedString;

final class Kdbx4Writer
{
    private const int FORMAT_VERSION = 0x00040001;

    private const int HEADER_FIELD_END = 0;
    private const int HEADER_FIELD_CIPHER = 2;
    private const int HEADER_FIELD_COMPRESSION = 3;
    private const int HEADER_FIELD_MASTER_SEED = 4;
    private const int HEADER_FIELD_ENCRYPTION_IV = 7;
    private const int HEADER_FIELD_KDF_PARAMETERS = 11;

    private const int VARIANT_TYPE_UINT_64 = 0x05;
    private const int VARIANT_TYPE_BYTE_ARRAY = 0x42;

    private const int INNER_HEADER_END = 0;
    private const int INNER_RANDOM_STREAM_ID = 1;
    private const int INNER_RANDOM_STREAM_KEY = 2;

    public const int INNER_RANDOM_STREAM_NONE = 0;
    public const int INNER_RANDOM_STREAM_SALSA20 = 2;
    public const int INNER_RANDOM_STREAM_CHACHA20 = 3;

    public static function write(Database $database, Key $key, ?Kdbx4WriteOptions $options = null): string
    {
        $options ??= new Kdbx4WriteOptions();
        self::assertWriteOptions($options);
        self::assertDatabaseIsWritable($database);

        $header = self::buildHeader($options);
        $derivedKeys = Kdbx4KeyDerivation::derive($key, $header);

        $innerRandomStreamKey = self::generateInnerRandomStreamKey($options);
        $innerRandomStream = self::createInnerRandomStream($options->innerRandomStream, $innerRandomStreamKey);
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));

        $xml = self::buildXml($database, $innerRandomStream, $now, $options);
        $payload = self::buildInnerHeader($options->innerRandomStream, $innerRandomStreamKey) . $xml;
        if ($options->compress) {
            $encodedPayload = gzencode($payload);
            if ($encodedPayload === false) {
                throw new KeePassPHPException('Kdbx4 write: unable to gzip payload.');
            }

            $payload = $encodedPayload;
        }

        $cipher = new CipherOpenSSL(
            'aes-256-cbc',
            $derivedKeys->encryptionKey,
            (string) $header->encryptionIV,
            Cipher::PADDING_PKCS7,
        );
        $encryptedPayload = $cipher->encrypt($payload);
        if ($encryptedPayload === null || $encryptedPayload === '') {
            throw new KeePassPHPException('Kdbx4 write: unable to encrypt payload.');
        }

        $headerBinary = $header->getBinary();
        $headerHash = hash(KdbxFile::HASH, $headerBinary, true);
        $headerHmac = hash_hmac('sha256', $headerBinary, $derivedKeys->getHeaderHmacKey(), true);

        return $headerBinary
            . $headerHash
            . $headerHmac
            . self::buildHmacBlockStream($encryptedPayload, $derivedKeys, $options->blockSize);
    }

    private static function assertWriteOptions(Kdbx4WriteOptions $options): void
    {
        if ($options->rounds <= 0) {
            throw new KeePassPHPException('Kdbx4 write: rounds must be strictly positive.');
        }

        if ($options->blockSize <= 0) {
            throw new KeePassPHPException('Kdbx4 write: block size must be strictly positive.');
        }

        if (
            $options->innerRandomStream !== self::INNER_RANDOM_STREAM_NONE
            && $options->innerRandomStream !== self::INNER_RANDOM_STREAM_SALSA20
            && $options->innerRandomStream !== self::INNER_RANDOM_STREAM_CHACHA20
        ) {
            throw new KeePassPHPException('Kdbx4 write: unsupported inner random stream.');
        }
    }

    private static function assertDatabaseIsWritable(Database $database): void
    {
        if ($database->getGroups() === []) {
            throw new KeePassPHPException('Kdbx4 write: database must contain at least one group.');
        }
    }

    private static function buildHeader(Kdbx4WriteOptions $options): Kdbx4Header
    {
        $header = new Kdbx4Header();
        $header->formatVersion = self::FORMAT_VERSION;
        $header->majorVersion = 4;
        $header->minorVersion = 1;
        $header->cipher = Kdbx4Header::CIPHER_AES;
        $header->compression = $options->compress ? Kdbx4Header::COMPRESSION_GZIP : Kdbx4Header::COMPRESSION_NONE;
        $header->masterSeed = random_bytes(32);
        $header->encryptionIV = random_bytes(16);
        $header->kdfParameters = [
            '$UUID' => Kdbx4Header::KDF_AES,
            'R' => $options->rounds,
            'S' => random_bytes(32),
        ];

        $headerFields = self::buildHeaderFields($header);

        return Kdbx4Header::fromBinary($headerFields);
    }

    private static function buildHeaderFields(Kdbx4Header $header): string
    {
        return Kdbx4Header::SIGNATURE1
            . Kdbx4Header::SIGNATURE2
            . pack('V', self::FORMAT_VERSION)
            . self::buildHeaderField(self::HEADER_FIELD_CIPHER, (string) $header->cipher)
            . self::buildHeaderField(
                self::HEADER_FIELD_COMPRESSION,
                pack('V', $header->compression === Kdbx4Header::COMPRESSION_GZIP ? 1 : 0)
            )
            . self::buildHeaderField(self::HEADER_FIELD_MASTER_SEED, (string) $header->masterSeed)
            . self::buildHeaderField(self::HEADER_FIELD_ENCRYPTION_IV, (string) $header->encryptionIV)
            . self::buildHeaderField(
                self::HEADER_FIELD_KDF_PARAMETERS,
                self::buildVariantDictionary([
                    '$UUID' => ['type' => self::VARIANT_TYPE_BYTE_ARRAY, 'value' => Kdbx4Header::KDF_AES],
                    'R' => ['type' => self::VARIANT_TYPE_UINT_64, 'value' => self::packUInt64((int) $header->kdfParameters['R'])],
                    'S' => ['type' => self::VARIANT_TYPE_BYTE_ARRAY, 'value' => (string) $header->kdfParameters['S']],
                ])
            )
            . self::buildHeaderField(self::HEADER_FIELD_END, Kdbx4Header::HEADER_END);
    }

    private static function buildHeaderField(int $fieldId, string $value): string
    {
        return chr($fieldId) . pack('V', strlen($value)) . $value;
    }

    /**
     * @param array<string, array{type:int, value:string}> $items
     */
    private static function buildVariantDictionary(array $items): string
    {
        $dictionary = pack('v', 0x0100);
        foreach ($items as $name => $item) {
            $dictionary .= chr($item['type']);
            $dictionary .= pack('V', strlen($name));
            $dictionary .= $name;
            $dictionary .= pack('V', strlen($item['value']));
            $dictionary .= $item['value'];
        }

        return $dictionary . "\x00";
    }

    private static function generateInnerRandomStreamKey(Kdbx4WriteOptions $options): string
    {
        return match ($options->innerRandomStream) {
            self::INNER_RANDOM_STREAM_NONE => '',
            self::INNER_RANDOM_STREAM_SALSA20 => random_bytes(32),
            self::INNER_RANDOM_STREAM_CHACHA20 => random_bytes(64),
            default => throw new KeePassPHPException('Kdbx4 write: unsupported inner random stream.'),
        };
    }

    private static function createInnerRandomStream(int $streamId, string $streamKey): ?RandomStream
    {
        return match ($streamId) {
            self::INNER_RANDOM_STREAM_NONE => null,
            self::INNER_RANDOM_STREAM_SALSA20 => self::createSalsa20Stream($streamKey),
            self::INNER_RANDOM_STREAM_CHACHA20 => self::createChaCha20Stream($streamKey),
            default => throw new KeePassPHPException('Kdbx4 write: unsupported inner random stream.'),
        };
    }

    private static function createSalsa20Stream(string $streamKey): RandomStream
    {
        $stream = Salsa20RandomStream::create(hash(KdbxFile::HASH, $streamKey, true), Kdbx3File::SALSA20_IV);
        if ($stream === null) {
            throw new KeePassPHPException('Kdbx4 write: unable to create Salsa20 stream.');
        }

        return $stream;
    }

    private static function createChaCha20Stream(string $streamKey): RandomStream
    {
        $stream = ChaCha20RandomStream::fromInnerKey($streamKey);
        if ($stream === null) {
            throw new KeePassPHPException('Kdbx4 write: unable to create ChaCha20 stream.');
        }

        return $stream;
    }

    private static function buildInnerHeader(int $streamId, string $streamKey): string
    {
        $header = self::buildInnerHeaderField(self::INNER_RANDOM_STREAM_ID, pack('V', $streamId));
        if ($streamId !== self::INNER_RANDOM_STREAM_NONE) {
            $header .= self::buildInnerHeaderField(self::INNER_RANDOM_STREAM_KEY, $streamKey);
        }

        return $header . self::buildInnerHeaderField(self::INNER_HEADER_END, '');
    }

    private static function buildInnerHeaderField(int $fieldId, string $value): string
    {
        return chr($fieldId) . pack('V', strlen($value)) . $value;
    }

    private static function buildHmacBlockStream(string $payload, Kdbx4DerivedKeys $derivedKeys, int $blockSize): string
    {
        $blocks = '';
        $index = 0;
        $offset = 0;
        $payloadLength = strlen($payload);

        while ($offset < $payloadLength) {
            $chunk = substr($payload, $offset, $blockSize);
            $blocks .= self::buildHmacBlock($index, $chunk, $derivedKeys);
            $offset += strlen($chunk);
            $index++;
        }

        return $blocks . self::buildHmacBlock($index, '', $derivedKeys);
    }

    private static function buildHmacBlock(int $index, string $data, Kdbx4DerivedKeys $derivedKeys): string
    {
        $sizeBytes = pack('V', strlen($data));
        $hmac = hash_hmac(
            'sha256',
            self::packUInt64($index) . $sizeBytes . $data,
            $derivedKeys->getBlockHmacKey($index),
            true,
        );

        return $hmac . $sizeBytes . $data;
    }

    private static function buildXml(
        Database $database,
        ?RandomStream $randomStream,
        DateTimeImmutable $now,
        Kdbx4WriteOptions $options,
    ): string {
        $xml = '<?xml version="1.0" encoding="UTF-8"?>';
        $xml .= '<KeePassFile>';
        $xml .= self::buildMetaXml($database, $now, $options);
        $xml .= '<Root>';
        foreach ($database->getGroups() as $group) {
            $xml .= self::buildGroupXml($group, $randomStream, $now);
        }
        $xml .= '<DeletedObjects/>';
        $xml .= '</Root>';
        $xml .= '</KeePassFile>';

        return $xml;
    }

    private static function buildMetaXml(Database $database, DateTimeImmutable $now, Kdbx4WriteOptions $options): string
    {
        $xml = '<Meta>';
        $xml .= '<Generator>' . self::escape($options->generator) . '</Generator>';

        $name = $database->getName();
        if ($name !== null) {
            $xml .= '<DatabaseName>' . self::escape($name) . '</DatabaseName>';
            $xml .= '<DatabaseNameChanged>' . self::encodeTime($now) . '</DatabaseNameChanged>';
        }

        $customIcons = $database->getCustomIcons();
        if ($customIcons !== []) {
            $xml .= '<CustomIcons>';
            foreach ($customIcons as $uuid => $data) {
                $xml .= '<Icon>';
                $xml .= '<UUID>' . self::escape(self::normalizeUuid($uuid)) . '</UUID>';
                $xml .= '<Data>' . self::escape($data) . '</Data>';
                $xml .= '</Icon>';
            }
            $xml .= '</CustomIcons>';
        }

        $xml .= '<MemoryProtection>';
        $xml .= '<ProtectTitle>False</ProtectTitle>';
        $xml .= '<ProtectUserName>False</ProtectUserName>';
        $xml .= '<ProtectPassword>True</ProtectPassword>';
        $xml .= '<ProtectURL>False</ProtectURL>';
        $xml .= '<ProtectNotes>False</ProtectNotes>';
        $xml .= '</MemoryProtection>';
        $xml .= '</Meta>';

        return $xml;
    }

    private static function buildGroupXml(Group $group, ?RandomStream $randomStream, DateTimeImmutable $now): string
    {
        $xml = '<Group>';
        $xml .= '<UUID>' . self::escape(self::normalizeUuid($group->uuid)) . '</UUID>';
        $xml .= '<Name>' . self::escape($group->name ?? 'Group') . '</Name>';
        if ($group->icon !== null) {
            $xml .= '<IconID>' . self::escape($group->icon) . '</IconID>';
        }
        if ($group->customIcon !== null) {
            $xml .= '<CustomIconUUID>' . self::escape(self::normalizeUuid($group->customIcon)) . '</CustomIconUUID>';
        }
        $xml .= self::buildTimesXml($now);
        $xml .= '<IsExpanded>True</IsExpanded>';

        foreach ($group->groups as $subgroup) {
            $xml .= self::buildGroupXml($subgroup, $randomStream, $now);
        }

        foreach ($group->entries as $entry) {
            $xml .= self::buildEntryXml($entry, $randomStream, $now);
        }

        $xml .= '</Group>';

        return $xml;
    }

    private static function buildEntryXml(Entry $entry, ?RandomStream $randomStream, DateTimeImmutable $now): string
    {
        $xml = '<Entry>';
        $xml .= '<UUID>' . self::escape(self::normalizeUuid($entry->uuid)) . '</UUID>';
        if ($entry->icon !== null) {
            $xml .= '<IconID>' . self::escape($entry->icon) . '</IconID>';
        }
        if ($entry->customIcon !== null) {
            $xml .= '<CustomIconUUID>' . self::escape(self::normalizeUuid($entry->customIcon)) . '</CustomIconUUID>';
        }
        if ($entry->tags !== null) {
            $xml .= '<Tags>' . self::escape($entry->tags) . '</Tags>';
        }
        $xml .= self::buildTimesXml($now);

        $password = $entry->password;
        if ($password !== null) {
            $xml .= self::buildStringFieldXml(Database::KEY_PASSWORD, $password, true, $randomStream);
        }

        foreach ($entry->stringFields as $key => $value) {
            $xml .= self::buildStringFieldXml(
                $key,
                $value,
                $value instanceof ProtectedString,
                $randomStream,
            );
        }

        if ($entry->history !== []) {
            $xml .= '<History>';
            foreach ($entry->history as $historyEntry) {
                $xml .= self::buildEntryXml($historyEntry, $randomStream, $now);
            }
            $xml .= '</History>';
        }

        $xml .= '</Entry>';

        return $xml;
    }

    private static function buildStringFieldXml(
        string $key,
        BoxedString $value,
        bool $protect,
        ?RandomStream $randomStream,
    ): string {
        $plainValue = $value->getPlainString();

        $xml = '<String>';
        $xml .= '<Key>' . self::escape($key) . '</Key>';

        if ($protect && $randomStream !== null) {
            $mask = $randomStream->getNextBytes(strlen($plainValue));
            $xml .= '<Value Protected="True">'
                . self::escape(base64_encode($plainValue ^ $mask))
                . '</Value>';
        } else {
            $xml .= '<Value>' . self::escape($plainValue) . '</Value>';
        }

        $xml .= '</String>';

        return $xml;
    }

    private static function buildTimesXml(DateTimeImmutable $now): string
    {
        $encoded = self::encodeTime($now);

        return '<Times>'
            . '<CreationTime>' . $encoded . '</CreationTime>'
            . '<LastModificationTime>' . $encoded . '</LastModificationTime>'
            . '<LastAccessTime>' . $encoded . '</LastAccessTime>'
            . '<ExpiryTime>' . $encoded . '</ExpiryTime>'
            . '<Expires>False</Expires>'
            . '<UsageCount>0</UsageCount>'
            . '<LocationChanged>' . $encoded . '</LocationChanged>'
            . '</Times>';
    }

    private static function encodeTime(DateTimeImmutable $time): string
    {
        static $epoch = null;
        if (! $epoch instanceof DateTimeImmutable) {
            $epoch = new DateTimeImmutable('0001-01-01 00:00:00', new DateTimeZone('UTC'));
        }

        $seconds = $time->getTimestamp() - $epoch->getTimestamp();

        return base64_encode(self::packUInt64($seconds));
    }

    private static function normalizeUuid(?string $uuid): string
    {
        if (is_string($uuid)) {
            $decoded = base64_decode($uuid, true);
            if ($decoded !== false && strlen($decoded) === 16) {
                return $uuid;
            }

            if (preg_match('/^[0-9a-fA-F]{32}$/', $uuid) === 1) {
                $binary = hex2bin($uuid);
                if ($binary !== false) {
                    return base64_encode($binary);
                }
            }

            return base64_encode(substr(hash('sha256', $uuid, true), 0, 16));
        }

        return base64_encode(random_bytes(16));
    }

    private static function packUInt64(int $value): string
    {
        return pack('V2', $value & 0xFFFFFFFF, ($value >> 32) & 0xFFFFFFFF);
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
    }
}
