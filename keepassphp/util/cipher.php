<?php

namespace KeePassPHP;

/**
 * An abstract cipher class that can be backed by various cryptographic
 * libraries - currently OpenSSL (if possible) and Mcrypt (otherwise).
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
	 *            correct length), or "" if none are needed.
	 * @param $padding The type of padding to use. Must be one of the constants
	 *                 self::PADDING_*.
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
	 *            are needed.
	 */
	public function setIV($iv)
	{
		$this->_iv = $iv;
	}

	/**
	 * Sets the padding mode to use.
	 * @param $padding A padding type. Must be one of the constants
	 *                 self::PADDING_*.
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
	 *           with no padding.
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
	 * Creates a new Cipher instance of one of the implementing classes,
	 * depending on the available extensions, or returns null if no extension
	 * is available.
	 * If $method and $key are null and are not set in some way before
	 * encrypting or decrypting, the operation will fail miserably.
	 * @param $method The OpenSSL method to use.
	 * @param $key The key, used for decryption as well as encryption.
	 * @param $iv The initialization vector, or "" if none are needed.
	 * @param $padding The type of padding to use. Must be one of the constants
	 *                 self::PADDING_*.
	 * @return A Cipher instance, or null if no suitable crypto library is
	 *         loaded.
	 */
	public static function Create($method, $key = null, $iv = "",
		$padding = self::PADDING_PKCS7)
	{
		return (PHP_VERSION_ID >= 50400 && extension_loaded("openssl"))
			? new CipherOpenSSL($method, $key, $iv, $padding)
			: (extension_loaded("mcrypt") && defined("MCRYPT_RIJNDAEL_128")
				? new CipherMcrypt($method, $key, $iv, $padding)
				: null);
	}
}

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
	 * @param $method The OpenSSL method to use.
	 * @param $key The key, used for decryption as well as encryption.
	 * @param $iv The initialization vector, or "" if none are needed.
	 * @param $padding The type of padding to use. Must be one of the constants
	 *                 parent::PADDING_*.
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
	 *           with no padding.
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
	 * @param $method The OpenSSL method to use (will be translated to mcrypt
	 *                corresponding cipher type and mode).
	 * @param $key The key, used for decryption as well as encryption.
	 * @param $iv The initialization vector, or "" if none are needed.
	 * @param $padding The type of padding to use. Must be one of the constants
	 *                 parent::PADDING_*.
	 */
	public function __construct($method, $key = null, $iv = "",
		$padding = self::PADDING_PKCS7)
	{
		$this->_type = null;
		$this->_mode = null;
		parent::__construct($method, $key, $iv, $padding);
	}

	/**
	 * Sets the cipher method to use.
	 * @param $method One of the OpenSSL ciphers constants.
	 */
	public function setMethod($method)
	{
		parent::setMethod($method);
		$method = strtolower($method);
		if($method == "aes-256-ecb")
		{
			$this->_type = MCRYPT_RIJNDAEL_128;
			$this->_mode = "ecb";
		}
		elseif($method == "aes-256-cbc")
		{
			$this->_type = MCRYPT_RIJNDAEL_128;
			$this->_mode = "cbc";
		}
	}

	/**
	 * Encrypts $s with this cipher instance method and key.
	 * @param $s A raw string to encrypt.
	 * @return The result as a raw string, or null in case of error.
	 */
	public function encrypt($s)
	{
		$m = $this->load();
		if($m === null)
			return null;
		$r = mcrypt_generic($m, $this->_padding == parent::PADDING_PKCS7
				? self::addPKCS7Padding($s,
					mcrypt_enc_get_block_size($m))
				: $s);
		$this->unload($m);
		return $r;
	}

	/**
	 * Performs $r rounds of encryption on $s with this cipher instance.
	 * @param $s A raw string, that must have a correct length to be encrypted
	 *           with no padding.
	 * @param $r The number of encryption rounds to perform.
	 * @return The result as a raw string, or null in case of error.
	 */
	public function encryptManyTimes($s, $r)
	{
		$m = $this->load();
		if($m === null)
			return null;
		for($i = 0; $i < $r; $i++)
			$s = mcrypt_generic($m, $s);
		$this->unload($m);
		return $s;
	}

	/**
	 * Decrypts $s with this cipher instance method and key.
	 * @param $s A raw string to decrypt.
	 * @return The result as a raw string, or null in case of error.
	 */
	public function decrypt($s)
	{
		$m = $this->load();
		if($m === null)
			return null;
		$padded = mdecrypt_generic($m, $s);
		$r = $this->_padding == parent::PADDING_PKCS7
			? self::removePKCS7Padding($padded,
				mcrypt_enc_get_block_size($m))
			: $padded;
		$this->unload($m);
		return $r;
	}

	/*******************
	 * Private methods *
	 *******************/

	/**
	 * Opens a mcrypt module.
	 * @return A mcrypt module resource, or null if an error occurred.
	 */
	private function load()
	{
		if(strlen($this->_method) == 0 || strlen($this->_key) == 0)
			return null;
		$m = mcrypt_module_open($this->_type, '', $this->_mode, '');
		if($m === false)
			return null;
		// This check is performed by mcrypt_generic_init, but it's better
		// to do it now, because mcrypt_generic_init does not return a
		// negative or false value if it fails.
		$ivsize = mcrypt_enc_get_iv_size($m);
		if(strlen($this->_iv) != $ivsize)
		{
			// In ECB (and some other modes), the IV is not used but still
			// required to have the this size by mcrypt_generic_init, so
			// let's make a fake one.
			if(strtolower($this->_mode) == "ecb")
				$ivsize = str_repeat("\0", $ivsize);
			else
				return null;
		}
		$r = @mcrypt_generic_init($m, $this->_key, $this->_iv);
		if($r < 0 || $r === false)
			return null;
		return $m;
	}

	/**
	 * Closes a mcrypt module.
	 * @param $m A mcrypt module.
	 */
	private function unload($m)
	{
		mcrypt_generic_deinit($m);
		mcrypt_module_close($m);
	}

	/**
	 * Pads the given string $str with the PKCS7 padding scheme, so that its
	 * length shall be a multiple of $blocksize.
	 * @param $str A string to pad.
	 * @param $blocksize The block size.
	 * @return The resulting padded string.
	 */
	private static function addPKCS7Padding($str, $blocksize)
	{
		$len = strlen($str);
		$pad = $blocksize - ($len % $blocksize);
		return $str . str_repeat(chr($pad), $pad);
	}

	/**
	 * Tries to unpad the PKCS7-padded string $string.
	 * @param $string The string to unpad.
	 * @return The unpadded string, or null in case of error.
	 */
	private static function removePKCS7Padding($string, $blocksize)
	{
		$len = strlen($string);
		$padlen = ord($string[$len - 1]);
		$padding = substr($string, -$padlen);
		if($padlen > $blocksize || $padlen == 0 ||
			substr_count($padding, chr($padlen)) != $padlen)
			return null;
		return substr($string, 0, $len - $padlen);
	}
}

?>
