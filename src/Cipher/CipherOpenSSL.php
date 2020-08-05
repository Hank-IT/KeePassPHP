<?php

declare(strict_types=1);

namespace KeePassPHP\Cipher;

/**
 * A Cipher implementation based on the OpenSSL PHP extension. This class
 * should be preferred over CipherMcrypt if the OpenSSL extension is available,
 * as OpenSSL is faster and more reliable than libmcrypt.
 */
class CipherOpenSSL extends Cipher
{
    /**
     * Constructs a new CipherOpenSSL instance. Calling code should check
     * before creating this instance that the OpenSSL extension is loaded.
     * @param string $method The OpenSSL method to use.
     * @param string $key The key, used for decryption as well as encryption.
     * @param string $iv The initialization vector, or "" if none are needed.
     * @param int $padding The type of padding to use. Must be one of the constants parent::PADDING_*.
     */
    public function __construct($method, $key = null, $iv = "",
                                $padding = self::PADDING_PKCS7)
    {
        parent::__construct($method, $key, $iv, $padding);
    }

    /**
     * Encrypts $s with this cipher instance method and key.
     * @param string $s A raw string to encrypt.
     * @return string The result as a raw string, or null in case of error.
     */
    public function encrypt($s)
    {
        if(strlen($this->_method) == 0 || strlen($this->_key) == 0)
            return null;
        $options = OPENSSL_RAW_DATA;
        if($this->_padding == parent::PADDING_NONE)
            $options = $options | OPENSSL_NO_PADDING;
        return openssl_encrypt($s, $this->_method, $this->_key, $options,
            $this->_iv);
    }

    /**
     * Performs $r rounds of encryption on $s with this cipher instance.
     * @param string $s A raw string, that must have a correct length to be encrypted with no padding.
     * @param int $r The number of encryption rounds to perform.
     * @return string|null The result as a raw string, or null in case of error.
     */
    public function encryptManyTimes($s, $r)
    {
        if(strlen($this->_method) == 0 || strlen($this->_key) == 0)
            return null;
        $options = OPENSSL_RAW_DATA | OPENSSL_NO_PADDING;
        for($i = 0; $i < $r; $i++)
            $s = openssl_encrypt($s, $this->_method, $this->_key, $options,
                $this->_iv);
        return $s;
    }

    /**
     * Decrypts $s with this cipher instance method and key.
     * @param string $s A raw string to decrypt.
     * @return string|null The result as a raw string, or null in case of error.
     */
    public function decrypt($s)
    {
        if(strlen($this->_method) == 0 || strlen($this->_key) == 0)
            return null;
        $options = OPENSSL_RAW_DATA;
        if($this->_padding == parent::PADDING_NONE)
            $options = $options | OPENSSL_NO_PADDING;
        return openssl_decrypt($s, $this->_method, $this->_key, $options,
            $this->_iv);
    }
}
