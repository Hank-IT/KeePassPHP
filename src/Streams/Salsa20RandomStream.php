<?php

declare(strict_types=1);

namespace KeePassPHP\Streams;

use KeePassPHP\Contracts\RandomStream;

final class Salsa20RandomStream implements RandomStream
{
    /** @var array<int, int> */
    private array $state;
    private string $output = '';
    private int $outputPos = self::OUTPUT_LEN;

    public const int STATE_LEN = 32;
    public const int KEY_LEN = 32;
    public const int OUTPUT_LEN = 64;
    public const int IV_LEN = 8;

    /**
     * Creates a new Salsa20Stream instance.
     *
     * @param string $key The 32-byte-long string to use as key.
     * @param string $iv  The 8-byte-long string to use as initialization vector.
     *
     * @return self|null A new Salsa20Stream instance, of null if $key or $iv do not have a suitable length.
     */
    public static function create(string $key, string $iv): ?self
    {
        if (strlen($key) !== self::KEY_LEN || strlen($iv) !== self::IV_LEN) {
            return null;
        }

        return new self($key, $iv);
    }

    private function __construct(string $key, string $iv)
    {
        $this->state = array_fill(0, self::STATE_LEN, 0);
        $this->keySetup(self::unpackWords($key, self::KEY_LEN / 2));
        $this->ivSetup(self::unpackWords($iv, self::IV_LEN / 2));
    }

    /**
     * @param list<int> $key
     */
    private function keySetup(array $key): void
    {
        for ($i = 0; $i < 4; $i++) {
            $j = 2 * $i;
            $this->state[2 * $i + 2] = $key[$j];
            $this->state[2 * $i + 3] = $key[$j + 1];
            $this->state[2 * $i + 22] = $key[$j + 8];
            $this->state[2 * $i + 23] = $key[$j + 9];
        }
        $this->state[0] = 0x7865;
        $this->state[1] = 0x6170;
        $this->state[10] = 0x646E;
        $this->state[11] = 0x3320;
        $this->state[20] = 0x2D32;
        $this->state[21] = 0x7962;
        $this->state[30] = 0x6574;
        $this->state[31] = 0x6B20;
    }

    /**
     * @param list<int> $iv
     */
    private function ivSetup(array $iv): void
    {
        $this->state[12] = $iv[0];
        $this->state[13] = $iv[1];
        $this->state[14] = $iv[2];
        $this->state[15] = $iv[3];
        $this->state[16] = 0;
        $this->state[17] = 0;
        $this->state[18] = 0;
        $this->state[19] = 0;
    }

    /**
     * @param array<int, int> $x
     */
    private static function addRotXor(array &$x, int $i, int $j, int $b, int $target): void
    {
        $s = $x[2 * $i] + $x[2 * $j];
        $r = $s >> 16;
        $s = $s & 0xFFFF;
        $t = ($x[2 * $i + 1] + $x[2 * $j + 1] + $r) & 0xFFFF;

        $m = $b < 16 ? 0 : 1;
        $b = $b % 16;
        $nt = (($t << $b) & 0xFFFF) | ($s >> (16 - $b));
        $ns = (($s << $b) & 0xFFFF) | ($t >> (16 - $b));
        $x[2 * $target + $m] ^= $ns;
        $x[2 * $target + 1 - $m] ^= $nt;
    }

    private function nextOutput(): void
    {
        $x = $this->state;

        for ($i = 0; $i < 10; $i++) {
            self::addRotXor($x, 0, 12, 7, 4);
            self::addRotXor($x, 4, 0, 9, 8);
            self::addRotXor($x, 8, 4, 13, 12);
            self::addRotXor($x, 12, 8, 18, 0);
            self::addRotXor($x, 5, 1, 7, 9);
            self::addRotXor($x, 9, 5, 9, 13);
            self::addRotXor($x, 13, 9, 13, 1);
            self::addRotXor($x, 1, 13, 18, 5);
            self::addRotXor($x, 10, 6, 7, 14);
            self::addRotXor($x, 14, 10, 9, 2);
            self::addRotXor($x, 2, 14, 13, 6);
            self::addRotXor($x, 6, 2, 18, 10);
            self::addRotXor($x, 15, 11, 7, 3);
            self::addRotXor($x, 3, 15, 9, 7);
            self::addRotXor($x, 7, 3, 13, 11);
            self::addRotXor($x, 11, 7, 18, 15);
            self::addRotXor($x, 0, 3, 7, 1);
            self::addRotXor($x, 1, 0, 9, 2);
            self::addRotXor($x, 2, 1, 13, 3);
            self::addRotXor($x, 3, 2, 18, 0);
            self::addRotXor($x, 5, 4, 7, 6);
            self::addRotXor($x, 6, 5, 9, 7);
            self::addRotXor($x, 7, 6, 13, 4);
            self::addRotXor($x, 4, 7, 18, 5);
            self::addRotXor($x, 10, 9, 7, 11);
            self::addRotXor($x, 11, 10, 9, 8);
            self::addRotXor($x, 8, 11, 13, 9);
            self::addRotXor($x, 9, 8, 18, 10);
            self::addRotXor($x, 15, 14, 7, 12);
            self::addRotXor($x, 12, 15, 9, 13);
            self::addRotXor($x, 13, 12, 13, 14);
            self::addRotXor($x, 14, 13, 18, 15);
        }

        for ($i = 0; $i < self::STATE_LEN; $i += 2) {
            $s = $x[$i] + $this->state[$i];
            $x[$i] = $s & 0xFFFF;
            $x[$i + 1] = ($x[$i + 1] + $this->state[$i + 1] + ($s >> 16)) & 0xFFFF;
        }

        $out = '';
        for ($i = 0; $i < self::STATE_LEN; $i++) {
            $out .= pack('v', $x[$i]);
        }

        $this->output = $out;
        $this->outputPos = 0;
        $this->incrementCounter();
    }

    /**
     * Generates $n random bytes and returns them as a string.
     *
     * @param int $n The number of bytes to generate.
     *
     * @return string A $n-long string.
     */
    public function getNextBytes(int $n): string
    {
        if ($n < 1) {
            return '';
        }

        $bytes = '';
        $remaining = $n;
        while ($remaining > 0) {
            if ($this->outputPos === self::OUTPUT_LEN) {
                $this->nextOutput();
            }
            $copyLength = min(self::OUTPUT_LEN - $this->outputPos, $remaining);
            $bytes .= substr($this->output, $this->outputPos, $copyLength);

            $remaining -= $copyLength;
            $this->outputPos += $copyLength;
        }

        return $bytes;
    }

    /**
     * @return list<int>
     */
    private static function unpackWords(string $bytes, int $wordCount): array
    {
        $words = unpack("v{$wordCount}", $bytes);
        if ($words === false) {
            throw new \RuntimeException('Unable to initialize Salsa20 state.');
        }

        $values = [];
        foreach (array_values($words) as $value) {
            if (!is_int($value)) {
                throw new \RuntimeException('Unable to initialize Salsa20 state.');
            }

            $values[] = $value;
        }

        return $values;
    }

    private function incrementCounter(): void
    {
        for ($i = 16; $i <= 19; $i++) {
            $this->state[$i]++;
            if ($this->state[$i] <= 0xFFFF) {
                return;
            }

            $this->state[$i] = 0;
        }
    }
}
