<?php

declare(strict_types=1);

namespace KeePassPHP\Tests\Fixtures;

use KeePassPHP\Kdbx4Header;
use KeePassPHP\KdbxKeyHash;
use KeePassPHP\Keys\KeyFromPassword;
use KeePassPHP\Streams\ChaCha20RandomStream;
use RuntimeException;

final class Kdbx4FixtureBuilder
{
    /**
     * @return array{
     *     payload:string,
     *     key:KeyFromPassword,
     *     database_name:string,
     *     entry_password:string
     * }
     */
    public static function buildAesKdfDatabase(
        string $password = 'secret',
        string $databaseName = 'Demo',
        string $entryPassword = 'pass',
    ): array {
        return self::buildDatabase(
            password: $password,
            databaseName: $databaseName,
            entryPassword: $entryPassword,
            kdfUuid: Kdbx4Header::KDF_AES,
        );
    }

    /**
     * @return array{
     *     payload:string,
     *     key:KeyFromPassword,
     *     database_name:string,
     *     entry_password:string
     * }
     */
    public static function buildArgon2idDatabase(
        string $password = 'secret',
        string $databaseName = 'Demo',
        string $entryPassword = 'pass',
    ): array {
        return self::buildDatabase(
            password: $password,
            databaseName: $databaseName,
            entryPassword: $entryPassword,
            kdfUuid: Kdbx4Header::KDF_ARGON2ID,
        );
    }

    /**
     * @return array{
     *     payload:string,
     *     key:KeyFromPassword,
     *     database_name:string,
     *     entry_password:string
     * }
     */
    private static function buildDatabase(
        string $password,
        string $databaseName,
        string $entryPassword,
        string $kdfUuid,
    ): array {
        $key = new KeyFromPassword($password, 'SHA256');

        $masterSeed = self::hex('00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF');
        $kdfSeed = self::hex('FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100');
        $encryptionIV = self::hex('112233445566778899AABBCCDDEEFF00');
        $innerKey = self::hex(
            '0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210'
            . '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
        );
        $rounds = 2;

        $protectedPassword = self::protectValue($entryPassword, $innerKey);
        $xml = self::buildXml($databaseName, $protectedPassword);
        $innerHeader = self::buildInnerHeader($innerKey);
        $plaintext = $innerHeader . $xml;

        $transformed = self::transformAesKdf(KdbxKeyHash::resolveCompositeHash($key), $kdfSeed, $rounds);
        $encryptionKey = hash('sha256', $masterSeed . $transformed, true);
        $hmacBaseKey = hash('sha512', $masterSeed . $transformed . "\x01", true);

        $header = self::buildHeader($masterSeed, $encryptionIV, $kdfSeed, $rounds, $kdfUuid);
        $headerHash = hash('sha256', $header, true);
        $headerHmac = hash_hmac('sha256', $header, hash('sha512', str_repeat("\xFF", 8) . $hmacBaseKey, true), true);

        $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $encryptionKey, OPENSSL_RAW_DATA, $encryptionIV);
        if ($ciphertext === false) {
            throw new RuntimeException('Unable to encrypt KDBX 4 fixture payload.');
        }

        $payload = $header
            . $headerHash
            . $headerHmac
            . self::buildHmacBlock(0, $ciphertext, $hmacBaseKey)
            . self::buildHmacBlock(1, '', $hmacBaseKey);

        return [
            'payload' => $payload,
            'key' => $key,
            'database_name' => $databaseName,
            'entry_password' => $entryPassword,
        ];
    }

    private static function buildXml(string $databaseName, string $protectedPassword): string
    {
        return <<<XML
            <?xml version="1.0" encoding="UTF-8"?>
            <KeePassFile>
              <Meta>
                <DatabaseName>{$databaseName}</DatabaseName>
              </Meta>
              <Root>
                <Group>
                  <UUID>group-1</UUID>
                  <Name>Root</Name>
                  <Entry>
                    <UUID>entry-1</UUID>
                    <String>
                      <Key>Title</Key>
                      <Value>Example</Value>
                    </String>
                    <String>
                      <Key>Password</Key>
                      <Value Protected="True">{$protectedPassword}</Value>
                    </String>
                  </Entry>
                </Group>
              </Root>
            </KeePassFile>
            XML;
    }

    private static function buildInnerHeader(string $innerKey): string
    {
        return chr(1)
            . pack('V', 4)
            . pack('V', 3)
            . chr(2)
            . pack('V', strlen($innerKey))
            . $innerKey
            . chr(0)
            . pack('V', 0);
    }

    private static function buildHeader(
        string $masterSeed,
        string $encryptionIV,
        string $kdfSeed,
        int $rounds,
        string $kdfUuid,
    ): string {
        return Kdbx4Header::SIGNATURE1
            . Kdbx4Header::SIGNATURE2
            . pack('V', 0x00040001)
            . self::buildHeaderField(2, Kdbx4Header::CIPHER_AES)
            . self::buildHeaderField(3, pack('V', 0))
            . self::buildHeaderField(4, $masterSeed)
            . self::buildHeaderField(7, $encryptionIV)
            . self::buildHeaderField(11, self::buildVariantDictionary([
                '$UUID' => ['type' => 0x42, 'value' => $kdfUuid],
                'R' => ['type' => 0x05, 'value' => self::packUInt64($rounds)],
                'S' => ['type' => 0x42, 'value' => $kdfSeed],
            ]))
            . self::buildHeaderField(0, Kdbx4Header::HEADER_END);
    }

    private static function buildHeaderField(int $id, string $value): string
    {
        return chr($id) . pack('V', strlen($value)) . $value;
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

    private static function protectValue(string $value, string $innerKey): string
    {
        $stream = ChaCha20RandomStream::fromInnerKey($innerKey);
        if ($stream === null) {
            throw new RuntimeException('Unable to create fixture ChaCha20 stream.');
        }

        return base64_encode($value ^ $stream->getNextBytes(strlen($value)));
    }

    private static function transformAesKdf(string $keyHash, string $seed, int $rounds): string
    {
        $value = $keyHash;
        for ($i = 0; $i < $rounds; $i++) {
            $encrypted = openssl_encrypt(
                $value,
                'aes-256-ecb',
                $seed,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            );
            if ($encrypted === false) {
                throw new RuntimeException('Unable to transform AES-KDF fixture key.');
            }

            $value = $encrypted;
        }

        return hash('sha256', $value, true);
    }

    private static function buildHmacBlock(int $index, string $data, string $hmacBaseKey): string
    {
        $sizeBytes = pack('V', strlen($data));
        $blockKey = hash('sha512', self::packUInt64($index) . $hmacBaseKey, true);
        $hmac = hash_hmac('sha256', self::packUInt64($index) . $sizeBytes . $data, $blockKey, true);

        return $hmac . $sizeBytes . $data;
    }

    private static function packUInt64(int $value): string
    {
        return pack('V2', $value & 0xFFFFFFFF, ($value >> 32) & 0xFFFFFFFF);
    }

    private static function hex(string $value): string
    {
        $decoded = hex2bin($value);
        if ($decoded === false) {
            throw new RuntimeException(sprintf('Invalid fixture hex value: %s', $value));
        }

        return $decoded;
    }
}
