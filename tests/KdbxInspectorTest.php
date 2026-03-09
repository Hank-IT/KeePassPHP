<?php

declare(strict_types=1);

namespace KeePassPHP\Tests;

use KeePassPHP\Exceptions\KeePassPHPException;
use KeePassPHP\KdbxFile;
use KeePassPHP\KdbxInspector;
use KeePassPHP\Keys\KeyFromPassword;
use KeePassPHP\Readers\StringReader;
use PHPUnit\Framework\TestCase;

final class KdbxInspectorTest extends TestCase
{
    public function testInspectsKdbx31Headers(): void
    {
        $file = KdbxFile::forEncryption(1);

        $payload = $file->encrypt('<xml/>', new KeyFromPassword('secret', KdbxFile::HASH));

        $metadata = KdbxInspector::inspect(new StringReader($payload));

        self::assertSame(3, $metadata->majorVersion);
        self::assertSame(1, $metadata->minorVersion);
        self::assertSame('KDBX 3.1', $metadata->formatLabel);
        self::assertTrue($metadata->isDecryptableByCurrentLibrary);
        self::assertSame('AES-256', $metadata->cipherName);
        self::assertSame('AES-KDF', $metadata->kdfName);
    }

    public function testInspectsKdbx41Headers(): void
    {
        $header = self::buildV41Header(
            cipherUuidHex: 'D6038A2B8B6F4CB5A524339A31DBB59A',
            compressed: true,
            kdfUuidHex: '9E298B1956DB4773B23DFC3EC6F0A1E6',
        );

        $metadata = KdbxInspector::inspect(new StringReader($header));

        self::assertSame(4, $metadata->majorVersion);
        self::assertSame(1, $metadata->minorVersion);
        self::assertSame('KDBX 4.1', $metadata->formatLabel);
        self::assertFalse($metadata->isDecryptableByCurrentLibrary);
        self::assertSame('ChaCha20', $metadata->cipherName);
        self::assertTrue($metadata->isCompressed);
        self::assertSame('Argon2id', $metadata->kdfName);
        self::assertNull($metadata->databaseName);
    }

    public function testRejectsInvalidSignature(): void
    {
        $this->expectException(KeePassPHPException::class);
        $this->expectExceptionMessage('signature not correct');

        KdbxInspector::inspect(new StringReader('not-a-kdbx'));
    }

    private static function buildV41Header(string $cipherUuidHex, bool $compressed, string $kdfUuidHex): string
    {
        return self::hex('03D9A29A')
            . self::hex('67FB4BB5')
            . pack('V', 0x00040001)
            . self::buildV4Field(2, self::hex($cipherUuidHex))
            . self::buildV4Field(3, pack('V', $compressed ? 1 : 0))
            . self::buildV4Field(4, random_bytes(32))
            . self::buildV4Field(7, random_bytes(12))
            . self::buildV4Field(11, self::buildVariantDictionary([
                '$UUID' => ['type' => 0x42, 'value' => self::hex($kdfUuidHex)],
                'I' => ['type' => 0x05, 'value' => self::packUInt64(2)],
                'M' => ['type' => 0x05, 'value' => self::packUInt64(65536)],
                'P' => ['type' => 0x04, 'value' => pack('V', 2)],
                'S' => ['type' => 0x42, 'value' => random_bytes(32)],
                'V' => ['type' => 0x04, 'value' => pack('V', 0x13)],
            ]))
            . self::buildV4Field(0, "\x0D\x0A\x0D\x0A");
    }

    private static function buildV4Field(int $id, string $value): string
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

    private static function packUInt64(int $value): string
    {
        return pack('V2', $value & 0xFFFFFFFF, ($value >> 32) & 0xFFFFFFFF);
    }

    private static function hex(string $value): string
    {
        $decoded = hex2bin($value);
        if ($decoded === false) {
            throw new KeePassPHPException(sprintf('Invalid test hex value: %s', $value));
        }

        return $decoded;
    }
}
