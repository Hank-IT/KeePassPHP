<?php

declare(strict_types=1);

namespace KeePassPHP\Cipher;

use KeePassPHP\Contracts\Cipher;

/**
 * A Cipher implementation based on the OpenSSL PHP extension. This class
 * should be preferred over CipherMcrypt if the OpenSSL extension is available,
 * as OpenSSL is faster and more reliable than libmcrypt.
 */
class CipherOpenSSL implements Cipher
{
    public function __construct(
        private readonly string $method,
        private readonly ?string $key,
        private readonly string $iv,
        private readonly int $padding,
    ) {}

    public function encrypt(string $string): ?string
    {
        if ($this->method === '' || $this->key === null || $this->key === '') {
            return null;
        }

        $options = OPENSSL_RAW_DATA;
        if ($this->padding === self::PADDING_NONE) {
            $options = $options | OPENSSL_NO_PADDING;
        }

        $encrypted = openssl_encrypt(
            $string,
            $this->method,
            $this->key,
            $options,
            $this->iv
        );

        return $encrypted === false ? null : $encrypted;
    }

    public function encryptManyTimes(string $string, int $rounds): ?string
    {
        if ($this->method === '' || $this->key === null || $this->key === '') {
            return null;
        }

        $options = OPENSSL_RAW_DATA | OPENSSL_NO_PADDING;
        for ($i = 0; $i < $rounds; $i++) {
            $encrypted = openssl_encrypt(
                $string,
                $this->method,
                $this->key,
                $options,
                $this->iv
            );

            if ($encrypted === false) {
                return null;
            }

            $string = $encrypted;
        }

        return $string;
    }

    public function decrypt(string $string): ?string
    {
        if ($this->method === '' || $this->key === null || $this->key === '') {
            return null;
        }

        $options = OPENSSL_RAW_DATA;
        if ($this->padding === self::PADDING_NONE) {
            $options = $options | OPENSSL_NO_PADDING;
        }

        $status = openssl_decrypt(
            $string,
            $this->method,
            $this->key,
            $options,
            $this->iv
        );

        return $status === false ? null : $status;
    }
}
