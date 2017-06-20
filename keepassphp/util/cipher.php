<?php

namespace KeePassPHP;

/**
 * An abstract cipher class that can be backed by various cryptographic
 * libraries - use OpenSSL only.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
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
	 * @param $method One of the OpenSSL ciphers constants.
	 * @param $key A binary string used as key (must be of correct length).
	 * @param $iv A binary string used as initialization vector (must be of
	 *        correct length), or "" if none are needed.
	 * @param $padding The type of padding to use. Must be one of the constants
	 *        self::PADDING_*.
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
	 * @param $method One of the OpenSSL ciphers constants.
	 */
	public function setMethod($method)
	{
		$this->_method = $method;
	}

	/**
	 * Sets the encryption or decryption key to use.
	 * @param $key A binary string (must be of correct length).
	 */
	public function setKey($k)
	{
		$this->_key = $k;
	}

	/**
	 * Sets the initialization vector to use.
	 * @param $iv A binary string (must be of correct length), or "" if none
	 *        are needed.
	 */
	public function setIV($iv)
	{
		$this->_iv = $iv;
	}

	/**
	 * Sets the padding mode to use.
	 * @param $padding A padding type. Must be one of the constants
	 *        self::PADDING_*.
	 */
	public function setPadding($padding)
	{
		$this->_padding = $padding;
	}

	/**
	 * Encrypts $s with this cipher instance method and key.
	 * @param $s A raw string to encrypt.
	 * @return The result as a raw string, or null in case of error.
	 */
	abstract public function encrypt($s);

	/**
	 * Performs $r rounds of encryption on $s with this cipher instance.
	 * @param $s A raw string, that must have a correct length to be encrypted
	 *        with no padding.
	 * @param $r The number of encryption rounds to perform.
	 * @return The result as a raw string, or null in case of error.
	 */
	abstract public function encryptManyTimes($s, $r);

	/**
	 * Decrypts $s with this cipher instance method and key.
	 * @param $s A raw string to decrypt.
	 * @return The result as a raw string, or null in case of error.
	 */
	abstract public function decrypt($s);

	/**
	 * Creates a new Cipher instance of CipherOpenSSL extensions.
	 * If $method and $key are null and are not set in some way before
	 * encrypting or decrypting, the operation will fail miserably.
	 * @param $method The OpenSSL method to use.
	 * @param $key The key, used for decryption as well as encryption.
	 * @param $iv The initialization vector, or "" if none are needed.
	 * @param $padding The type of padding to use. Must be one of the constants
	 *        self::PADDING_*.
	 */
	public static function Create($method, $key = null, $iv = "",
		$padding = self::PADDING_PKCS7)
	{
		return (PHP_VERSION_ID >= 50400 && extension_loaded("openssl"))
			? new CipherOpenSSL($method, $key, $iv, $padding)
			: false;
	}
}

/**
 * A Cipher implementation based on the OpenSSL PHP extension.
 */
class CipherOpenSSL extends Cipher
{
	/**
	 * Constructs a new CipherOpenSSL instance. Calling code should check
	 * before creating this instance that the OpenSSL extension is loaded.
	 * @param $method The OpenSSL method to use.
	 * @param $key The key, used for decryption as well as encryption.
	 * @param $iv The initialization vector, or "" if none are needed.
	 * @param $padding The type of padding to use. Must be one of the constants
	 *        parent::PADDING_*.
	 */
	public function __construct($method, $key = null, $iv = "",
		$padding = self::PADDING_PKCS7)
	{
		parent::__construct($method, $key, $iv, $padding);
	}

	/**
	 * Encrypts $s with this cipher instance method and key.
	 * @param $s A raw string to encrypt.
	 * @return The result as a raw string, or null in case of error.
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
	 * @param $s A raw string, that must have a correct length to be encrypted
	 *        with no padding.
	 * @param $r The number of encryption rounds to perform.
	 * @return The result as a raw string, or null in case of error.
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
	 * @param $s A raw string to decrypt.
	 * @return The result as a raw string, or null in case of error.
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
