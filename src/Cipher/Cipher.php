<?php

declare(strict_types=1);

namespace KeePassPHP\Cipher;

/**
 * An abstract cipher class that can be backed by various cryptographic
 * libraries - currently OpenSSL (if possible) and Mcrypt (otherwise).
 *
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 *
 * @link       https://github.com/shkdee/KeePassPHP
 */
abstract class Cipher
{
    protected $_method;
    protected $_key;
    protected $_iv;
    protected $_padding;

    /** Add no padding (the data must be of correct length). */
    const PADDING_NONE = 0;

    /** Add PKCS7 padding. */
    const PADDING_PKCS7 = 1;

    /**
     * Constructs a new Cipher instance.
     *
     * @param string $method  One of the OpenSSL ciphers constants.
     * @param string $key     A binary string used as key (must be of correct length).
     * @param string $iv      A binary string used as initialization vector (must be of correct length), or "" if none are needed.
     * @param int    $padding The type of padding to use. Must be one of the constants self::PADDING_*.
     */
    protected function __construct($method, $key, $iv, $padding)
    {
        $this->setKey($key);
        $this->setIV($iv);
        $this->setPadding($padding);
        $this->setMethod($method);
    }

    /**
     * Sets the cipher method to use.
     *
     * @param string $method One of the OpenSSL ciphers constants.
     */
    public function setMethod($method)
    {
        $this->_method = $method;
    }

    /**
     * Sets the encryption or decryption key to use.
     *
     * @param string $key A binary string (must be of correct length).
     */
    public function setKey($k)
    {
        $this->_key = $k;
    }

    /**
     * Sets the initialization vector to use.
     *
     * @param string $iv A binary string (must be of correct length), or "" if none
     *                   are needed.
     */
    public function setIV($iv)
    {
        $this->_iv = $iv;
    }

    /**
     * Sets the padding mode to use.
     *
     * @param int $padding A padding type. Must be one of the constants
     *                     self::PADDING_*.
     */
    public function setPadding($padding)
    {
        $this->_padding = $padding;
    }

    /**
     * Encrypts $s with this cipher instance method and key.
     *
     * @param string $s A raw string to encrypt.
     *
     * @return string The result as a raw string, or null in case of error.
     */
    abstract public function encrypt($s);

    /**
     * Performs $r rounds of encryption on $s with this cipher instance.
     *
     * @param string $s A raw string, that must have a correct length to be encrypted with no padding.
     * @param int    $r The number of encryption rounds to perform.
     *
     * @return string|null The result as a raw string, or null in case of error.
     */
    abstract public function encryptManyTimes($s, $r);

    /**
     * Decrypts $s with this cipher instance method and key.
     *
     * @param string $s A raw string to decrypt.
     *
     * @return string|null The result as a raw string, or null in case of error.
     */
    abstract public function decrypt($s);

    /**
     * Creates a new Cipher instance of one of the implementing classes,
     * depending on the available extensions, or returns null if no extension
     * is available.
     * If $method and $key are null and are not set in some way before
     * encrypting or decrypting, the operation will fail miserably.
     *
     * @param string $method  The OpenSSL method to use.
     * @param string $key     The key, used for decryption as well as encryption.
     * @param string $iv      The initialization vector, or "" if none are needed.
     * @param int    $padding The type of padding to use. Must be one of the constants elf::PADDING_*.
     *
     * @return static|null A Cipher instance, or null if no suitable crypto library is loaded.
     */
    public static function Create($method, $key = null, $iv = '', $padding = self::PADDING_PKCS7)
    {
        return new CipherOpenSSL($method, $key, $iv, $padding);
    }
}
