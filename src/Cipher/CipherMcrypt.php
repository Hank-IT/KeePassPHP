<?php

declare(strict_types=1);

namespace KeePassPHP\Cipher;

/**
 * A Cipher implementation based on the mcrypt PHP extension.
 */
class CipherMcrypt extends Cipher
{
    private $_type;
    private $_mode;

    // 0 = unloaded, 1 = loaded,
    // 2 = encrypting, 3 = decrypting
    // private $_state = 0;

    /**
     * Constructs a new CipherMcrypt instance.
     *
     * @param string $method  The OpenSSL method to use (will be translated to mcrypt corresponding cipher type and mode).
     * @param string $key     The key, used for decryption as well as encryption.
     * @param string $iv      The initialization vector, or "" if none are needed.
     * @param int    $padding The type of padding to use. Must be one of the constants parent::PADDING_*.
     */
    public function __construct(
        $method,
        $key = null,
        $iv = '',
        $padding = self::PADDING_PKCS7
    )
    {
        $this->_type = null;
        $this->_mode = null;
        parent::__construct($method, $key, $iv, $padding);
    }

    /**
     * Sets the cipher method to use.
     *
     * @param string $method One of the OpenSSL ciphers constants.
     */
    public function setMethod($method)
    {
        parent::setMethod($method);
        $method = strtolower($method);
        if ($method == 'aes-256-ecb') {
            $this->_type = MCRYPT_RIJNDAEL_128;
            $this->_mode = 'ecb';
        } elseif ($method == 'aes-256-cbc') {
            $this->_type = MCRYPT_RIJNDAEL_128;
            $this->_mode = 'cbc';
        }
    }

    /**
     * Encrypts $s with this cipher instance method and key.
     *
     * @param string $s A raw string to encrypt.
     *
     * @return string|null The result as a raw string, or null in case of error.
     */
    public function encrypt($s)
    {
        $m = $this->load();
        if ($m === null) {
            return null;
        }
        $r = mcrypt_generic($m, $this->_padding == parent::PADDING_PKCS7
            ? self::addPKCS7Padding(
                $s,
                mcrypt_enc_get_block_size($m)
            )
            : $s);
        $this->unload($m);

        return $r;
    }

    /**
     * Performs $r rounds of encryption on $s with this cipher instance.
     *
     * @param string $s A raw string, that must have a correct length to be encrypted with no padding.
     * @param int    $r The number of encryption rounds to perform.
     *
     * @return string|null The result as a raw string, or null in case of error.
     */
    public function encryptManyTimes($s, $r)
    {
        $m = $this->load();
        if ($m === null) {
            return null;
        }
        for ($i = 0; $i < $r; $i++) {
            $s = mcrypt_generic($m, $s);
        }
        $this->unload($m);

        return $s;
    }

    /**
     * Decrypts $s with this cipher instance method and key.
     *
     * @param string $s A raw string to decrypt.
     *
     * @return string|null The result as a raw string, or null in case of error.
     */
    public function decrypt($s)
    {
        $m = $this->load();
        if ($m === null) {
            return null;
        }
        $padded = mdecrypt_generic($m, $s);
        $r = $this->_padding == parent::PADDING_PKCS7
            ? self::removePKCS7Padding(
                $padded,
                mcrypt_enc_get_block_size($m)
            )
            : $padded;
        $this->unload($m);

        return $r;
    }

    /*******************
     * Private methods *
     *******************/

    /**
     * Opens a mcrypt module.
     *
     * @return mixed A mcrypt module resource, or null if an error occurred.
     */
    private function load()
    {
        if (strlen($this->_method) == 0 || strlen($this->_key) == 0) {
            return null;
        }
        $m = mcrypt_module_open($this->_type, '', $this->_mode, '');
        if ($m === false) {
            return null;
        }
        // This check is performed by mcrypt_generic_init, but it's better
        // to do it now, because mcrypt_generic_init does not return a
        // negative or false value if it fails.
        $ivsize = mcrypt_enc_get_iv_size($m);
        if (strlen($this->_iv) != $ivsize) {
            // In ECB (and some other modes), the IV is not used but still
            // required to have the this size by mcrypt_generic_init, so
            // let's make a fake one.
            if (strtolower($this->_mode) == 'ecb') {
                $ivsize = str_repeat("\0", $ivsize);
            } else {
                return null;
            }
        }
        $r = @mcrypt_generic_init($m, $this->_key, $this->_iv);
        if ($r < 0 || $r === false) {
            return null;
        }

        return $m;
    }

    /**
     * Closes a mcrypt module.
     *
     * @param mixed $m A mcrypt module.
     */
    private function unload($m)
    {
        mcrypt_generic_deinit($m);
        mcrypt_module_close($m);
    }

    /**
     * Pads the given string $str with the PKCS7 padding scheme, so that its
     * length shall be a multiple of $blocksize.
     *
     * @param string $str       A string to pad.
     * @param int    $blocksize The block size.
     *
     * @return string The resulting padded string.
     */
    private static function addPKCS7Padding($str, $blocksize)
    {
        $len = strlen($str);
        $pad = $blocksize - ($len % $blocksize);

        return $str.str_repeat(chr($pad), $pad);
    }

    /**
     * Tries to unpad the PKCS7-padded string $string.
     *
     * @param string $string The string to unpad.
     *
     * @return string The unpadded string, or null in case of error.
     */
    private static function removePKCS7Padding($string, $blocksize)
    {
        $len = strlen($string);
        $padlen = ord($string[$len - 1]);
        $padding = substr($string, -$padlen);
        if ($padlen > $blocksize || $padlen == 0 ||
            substr_count($padding, chr($padlen)) != $padlen) {
            return null;
        }

        return substr($string, 0, $len - $padlen);
    }
}
