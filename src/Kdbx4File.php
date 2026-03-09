<?php

declare(strict_types=1);

namespace KeePassPHP;

use KeePassPHP\Cipher\CipherOpenSSL;
use KeePassPHP\Contracts\Cipher;
use KeePassPHP\Contracts\Key;
use KeePassPHP\Contracts\OpenedKdbxFile;
use KeePassPHP\Contracts\RandomStream;
use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\Readers\HmacBlockReader;
use KeePassPHP\Readers\Reader;
use KeePassPHP\Readers\StringReader;
use KeePassPHP\Streams\ChaCha20RandomStream;
use KeePassPHP\Streams\Salsa20RandomStream;

final class Kdbx4File implements OpenedKdbxFile
{
    private const int INNER_HEADER_END = 0;
    private const int INNER_RANDOM_STREAM_ID = 1;
    private const int INNER_RANDOM_STREAM_KEY = 2;

    private const int INNER_RANDOM_STREAM_NONE = 0;
    private const int INNER_RANDOM_STREAM_SALSA20 = 2;
    private const int INNER_RANDOM_STREAM_CHACHA20 = 3;

    private ?string $content = null;
    private ?RandomStream $randomStream = null;
    private ?string $headerHash = null;

    public function __construct(private readonly Kdbx4Header $header) {}

    public function getMajorVersion(): int
    {
        return 4;
    }

    public function getHeader(): Kdbx4Header
    {
        return $this->header;
    }

    public function getHeaderHash(): ?string
    {
        return $this->headerHash;
    }

    public function getContent(): ?string
    {
        return $this->content;
    }

    public function getRandomStream(): ?RandomStream
    {
        return $this->randomStream;
    }

    public static function decrypt(Reader $reader, Key $key): self
    {
        $header = Kdbx4Header::fromReader($reader);
        if (!$header->check()) {
            throw new KeePassPHPException('Kdbx4 file decrypt: header check failed.');
        }

        $headerHash = self::readExact($reader, 32, 'Kdbx4 file decrypt: header hash is missing.');
        if (!hash_equals($headerHash, hash(KdbxFile::HASH, $header->getBinary(), true))) {
            throw new KeePassPHPException('Kdbx4 file decrypt: header hash is not correct.');
        }

        $derivedKeys = Kdbx4KeyDerivation::derive($key, $header);

        $headerHmac = self::readExact($reader, 32, 'Kdbx4 file decrypt: header HMAC is missing.');
        $expectedHeaderHmac = hash_hmac('sha256', $header->getBinary(), $derivedKeys->getHeaderHmacKey(), true);
        if (!hash_equals($headerHmac, $expectedHeaderHmac)) {
            throw new KeePassPHPException('Kdbx4 file decrypt: header HMAC is not correct.');
        }

        $hmacReader = new HmacBlockReader($reader, $derivedKeys);
        $encryptedPayload = $hmacReader->readToTheEnd();
        $isCorrupted = $hmacReader->isCorrupted();
        $hmacReader->close();

        if ($encryptedPayload === null || $isCorrupted) {
            throw new KeePassPHPException('Kdbx4 file decrypt: block HMAC verification failed.');
        }

        $cipher = new CipherOpenSSL(
            self::resolveCipherMethod($header),
            $derivedKeys->encryptionKey,
            (string) $header->encryptionIV,
            Cipher::PADDING_PKCS7,
        );

        $decryptedPayload = $cipher->decrypt($encryptedPayload);
        if ($decryptedPayload === null) {
            throw new KeePassPHPException('Kdbx4 file decrypt: decryption failed.');
        }

        if ($header->compression === Kdbx4Header::COMPRESSION_GZIP) {
            $decryptedPayload = gzdecode($decryptedPayload);
            if ($decryptedPayload === false) {
                throw new KeePassPHPException('Kdbx4 file decrypt: ungzip error.');
            }
        }

        [$randomStream, $xml] = self::parseInnerHeader($decryptedPayload);

        $file = new self($header);
        $file->content = $xml;
        $file->randomStream = $randomStream;
        $file->headerHash = $headerHash;

        return $file;
    }

    /**
     * @return array{?RandomStream, string}
     */
    private static function parseInnerHeader(string $payload): array
    {
        $reader = new StringReader($payload);
        $randomStreamId = null;
        $randomStreamKey = null;

        while (true) {
            $fieldId = $reader->readByte();
            $fieldLength = $reader->readNumber(4);
            $fieldValue = $fieldLength > 0 ? $reader->read($fieldLength) : '';

            if ($fieldValue === null || strlen($fieldValue) !== $fieldLength) {
                throw new KeePassPHPException('Kdbx4 file decrypt: incomplete inner header field.');
            }

            if ($fieldId === self::INNER_HEADER_END) {
                break;
            }

            if ($fieldId === self::INNER_RANDOM_STREAM_ID) {
                $streamId = unpack('V', $fieldValue);
                if ($streamId === false || !isset($streamId[1]) || !is_int($streamId[1])) {
                    throw new KeePassPHPException('Kdbx4 file decrypt: invalid inner random stream ID.');
                }

                $randomStreamId = $streamId[1];
            } elseif ($fieldId === self::INNER_RANDOM_STREAM_KEY) {
                $randomStreamKey = $fieldValue;
            }
        }

        $xml = $reader->readToTheEnd();
        if ($xml === null || $xml === '') {
            throw new KeePassPHPException('Kdbx4 file decrypt: decrypted content is empty.');
        }

        return [self::createInnerRandomStream($randomStreamId, $randomStreamKey), $xml];
    }

    private static function createInnerRandomStream(?int $streamId, ?string $streamKey): ?RandomStream
    {
        if ($streamId === null || $streamId === self::INNER_RANDOM_STREAM_NONE) {
            return null;
        }

        if ($streamKey === null || $streamKey === '') {
            throw new KeePassPHPException('Kdbx4 file decrypt: missing inner random stream key.');
        }

        return match ($streamId) {
            self::INNER_RANDOM_STREAM_SALSA20 => self::createSalsa20Stream($streamKey),
            self::INNER_RANDOM_STREAM_CHACHA20 => self::createChaCha20Stream($streamKey),
            default => throw new KeePassPHPException('Kdbx4 file decrypt: unsupported inner random stream.'),
        };
    }

    private static function createSalsa20Stream(string $streamKey): RandomStream
    {
        $stream = Salsa20RandomStream::create(hash(KdbxFile::HASH, $streamKey, true), Kdbx3File::SALSA20_IV);
        if ($stream === null) {
            throw new KeePassPHPException('Kdbx4 file decrypt: random stream parameters error.');
        }

        return $stream;
    }

    private static function createChaCha20Stream(string $streamKey): RandomStream
    {
        $stream = ChaCha20RandomStream::fromInnerKey($streamKey);
        if ($stream === null) {
            throw new KeePassPHPException('Kdbx4 file decrypt: random stream parameters error.');
        }

        return $stream;
    }

    private static function resolveCipherMethod(Kdbx4Header $header): string
    {
        return match ($header->cipher) {
            Kdbx4Header::CIPHER_AES => 'aes-256-cbc',
            default => throw new KeePassPHPException('Kdbx4 file decrypt: unsupported outer cipher.'),
        };
    }

    private static function readExact(Reader $reader, int $length, string $error): string
    {
        $bytes = $reader->read($length);
        if ($bytes === null || strlen($bytes) !== $length) {
            throw new KeePassPHPException($error);
        }

        return $bytes;
    }
}
