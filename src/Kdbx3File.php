<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Cipher\CipherOpenSSL;
use KeePassPHP\Contracts\Cipher;
use KeePassPHP\Contracts\Key;
use KeePassPHP\Contracts\OpenedKdbxFile;
use KeePassPHP\Contracts\RandomStream;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Readers\HashedBlockReader;
use KeePassPHP\Readers\Reader;
use KeePassPHP\Readers\StringReader;
use KeePassPHP\Streams\Salsa20RandomStream;
use Random\RandomException;

/**
 * A class that manages a Kdbx file, which is mainly an encryptable text
 * content and a KdbxHeader that describes how to encrypt or decrypt that
 * content.
 */
final class Kdbx3File implements OpenedKdbxFile
{
    public const string SALSA20_IV = "\xE8\x30\x09\x4B\x97\x20\x5D\x2A";
    public const int CIPHER_LEN = 16;
    public const int SEED_LEN = 32;
    public const int STARTBYTES_LEN = 32;
    public const int ROUNDS_LEN = 8;

    public const string HASH = 'SHA256';

    private ?string $headerBinary = null;
    private ?string $content = null;
    private ?RandomStream $randomStream = null;

    public function __construct(private readonly KdbxHeader $header) {}

    public function getMajorVersion(): int
    {
        return 3;
    }

    public function getHeader(): KdbxHeader
    {
        return $this->header;
    }

    public function getHeaderHash(): ?string
    {
        return $this->header->headerHash;
    }

    public function getContent(): ?string
    {
        return $this->content;
    }

    public function getRandomStream(): ?RandomStream
    {
        return $this->randomStream;
    }

    /**
     * @throws KeePassPHPException
     * @throws RandomException
     */
    public function prepareForEncryption(): void
    {
        $header = $this->getHeader();
        $header->masterSeed = random_bytes(self::SEED_LEN);
        $header->transformSeed = random_bytes(self::SEED_LEN);
        $header->encryptionIV = random_bytes(16);
        $header->randomStreamKey = random_bytes(self::SEED_LEN);
        $header->startBytes = random_bytes(self::STARTBYTES_LEN);

        $this->randomStream = self::createRandomStream($header, 'encrypt');

        $this->headerBinary = $header->toBinary(self::HASH);

        self::assertHeaderIsUsable($header, 'encrypt');
    }

    public function encrypt(string $content, Key $key): string
    {
        if ($content === '') {
            throw new KeePassPHPException('Kdbx file encrypt: empty content.');
        }

        if ($this->headerBinary === null || $this->headerBinary === '') {
            throw new KeePassPHPException('Kdbx file encrypt: encryption not prepared.');
        }

        $header = $this->getHeader();
        if ($header->compression === KdbxHeader::COMPRESSION_GZIP) {
            throw new KeePassPHPException('Kdbx file encrypt: gzip compression not yet supported.');
        }

        $cipher = new CipherOpenSSL(
            self::resolveCipherMethod($header, 'encrypt'),
            self::transformKey($key, $header, 'encrypt'),
            (string) $header->encryptionIV,
            Cipher::PADDING_PKCS7,
        );

        $hashedContent = HashedBlockReader::hashString($content, self::HASH);
        $encrypted = $cipher->encrypt((string) $header->startBytes . $hashedContent);
        if ($encrypted === null || $encrypted === '') {
            throw new KeePassPHPException('Kdbx file encrypt: encryption failed.');
        }

        $this->content = $content;
        $result = $this->headerBinary . $encrypted;
        $this->headerBinary = null;

        return $result;
    }

    public static function forEncryption(int|string $rounds): self
    {
        $rounds = (int) $rounds;
        if ($rounds <= 0) {
            throw new KeePassPHPException('Kdbx file encrypt: rounds must be strictly positive.');
        }

        $header = new KdbxHeader();
        $header->cipher = KdbxHeader::CIPHER_AES;
        $header->compression = KdbxHeader::COMPRESSION_NONE;
        $header->randomStream = KdbxHeader::RANDOMSTREAM_NONE;
        $header->rounds = pack('V', $rounds) . "\x00\x00\x00\x00";

        $file = new self($header);
        $file->prepareForEncryption();

        return $file;
    }

    public static function decrypt(Reader $reader, Key $key): self
    {
        $header = KdbxHeader::fromReader($reader, self::HASH);

        self::assertHeaderIsUsable($header, 'decrypt');

        $randomStream = self::createRandomStream($header, 'decrypt');

        $cipher = new CipherOpenSSL(
            self::resolveCipherMethod($header, 'decrypt'),
            self::transformKey($key, $header, 'decrypt'),
            (string) $header->encryptionIV,
            Cipher::PADDING_PKCS7,
        );

        $encryptedPayload = $reader->readToTheEnd();
        if ($encryptedPayload === null || $encryptedPayload === '') {
            throw new KeePassPHPException('Kdbx file decrypt: encrypted payload is empty.');
        }

        $decrypted = $cipher->decrypt($encryptedPayload);
        if (
            $decrypted === null
            || substr($decrypted, 0, self::STARTBYTES_LEN) !== $header->startBytes
        ) {
            throw new KeePassPHPException('Kdbx file decrypt: decryption failed.');
        }

        $hashedReader = new HashedBlockReader(
            new StringReader(substr($decrypted, self::STARTBYTES_LEN)),
            self::HASH
        );
        $decoded = $hashedReader->readToTheEnd();
        $isCorrupted = $hashedReader->isCorrupted();
        $hashedReader->close();

        if ($decoded === null || $isCorrupted) {
            throw new KeePassPHPException('Kdbx file decrypt: integrity check failed.');
        }

        if ($header->compression === KdbxHeader::COMPRESSION_GZIP) {
            $decoded = gzdecode($decoded);
            if ($decoded === false) {
                throw new KeePassPHPException('Kdbx file decrypt: ungzip error.');
            }
        }

        $file = new self($header);
        $file->content = $decoded;
        $file->randomStream = $randomStream;

        return $file;
    }

    private static function transformKey(Key $key, KdbxHeader $header, string $mode): string
    {
        if ($header->transformSeed === null || $header->masterSeed === null || $header->rounds === null) {
            throw new KeePassPHPException(sprintf('Kdbx file %s: cannot transform key.', $mode));
        }

        $cipher = new CipherOpenSSL('aes-256-ecb', $header->transformSeed, '', Cipher::PADDING_NONE);

        $rounds = unpack('v4', $header->rounds);
        if ($rounds === false) {
            throw new KeePassPHPException(sprintf('Kdbx file %s: cannot transform key.', $mode));
        }

        $roundValues = [];
        foreach (array_values($rounds) as $value) {
            if (! is_int($value)) {
                throw new KeePassPHPException(sprintf('Kdbx file %s: cannot transform key.', $mode));
            }

            $roundValues[] = $value;
        }

        $keyHash = KdbxKeyHash::resolveCompositeHash($key);
        $o = $roundValues[0] | (($roundValues[1] & 0x3fff) << 16);
        $t = (($roundValues[1] & 0xc000) >> 14) | ($roundValues[2] << 2) | (($roundValues[3] & 0x0fff) << 18);
        $h = ($roundValues[3] & 0xf000) >> 12;

        $loop = false;
        do {
            if ($o > 0) {
                $encryptedHash = $cipher->encryptManyTimes($keyHash, $o);
                if ($encryptedHash === null) {
                    throw new KeePassPHPException(sprintf('Kdbx file %s: cannot transform key.', $mode));
                }

                $keyHash = $encryptedHash;
                $o = 0;
            }

            $loop = false;
            if ($t > 0) {
                $t--;
                $o = 0x40000000;
                $loop = true;
            } elseif ($h > 0) {
                $h--;
                $t = 0x3fffffff;
                $o = 0x40000000;
                $loop = true;
            }
        } while ($loop);

        $finalKey = hash(self::HASH, $keyHash, true);

        return hash(self::HASH, $header->masterSeed . $finalKey, true);
    }

    private static function resolveCipherMethod(KdbxHeader $header, string $mode): string
    {
        if ($header->cipher === KdbxHeader::CIPHER_AES) {
            return 'aes-256-cbc';
        }

        throw new KeePassPHPException(sprintf('Kdbx file %s: unkown cipher.', $mode));
    }

    private static function createRandomStream(KdbxHeader $header, string $mode): ?RandomStream
    {
        if ($header->randomStream !== KdbxHeader::RANDOMSTREAM_SALSA20) {
            return null;
        }

        $randomStream = Salsa20RandomStream::create(
            hash(self::HASH, (string) $header->randomStreamKey, true),
            self::SALSA20_IV
        );
        if ($randomStream === null) {
            throw new KeePassPHPException(sprintf('Kdbx file %s: random stream parameters error.', $mode));
        }

        return $randomStream;
    }

    private static function assertHeaderIsUsable(KdbxHeader $header, string $mode): void
    {
        if (!self::headerCheck($header)) {
            throw new KeePassPHPException(sprintf('Kdbx file %s: header check failed.', $mode));
        }
    }

    private static function headerCheck(KdbxHeader $header): bool
    {
        return strlen($header->cipher ?? '') === self::CIPHER_LEN
            && $header->compression !== 0
            && strlen($header->masterSeed ?? '') === self::SEED_LEN
            && strlen($header->transformSeed ?? '') === self::SEED_LEN
            && strlen($header->rounds ?? '') === self::ROUNDS_LEN
            && $header->encryptionIV !== null
            && strlen($header->startBytes ?? '') === self::STARTBYTES_LEN
            && $header->headerHash !== null
            && $header->randomStreamKey !== null
            && $header->randomStream !== 0;
    }
}
