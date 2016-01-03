<?php

namespace KeePassPHP;

/**
 * A wrapper around the PHP mcrypt module. It makes it easier to control
 * arguments and automatically manages calls to mcrypt_module_open/init/deinit,
 * etc. Finally, it adds a support of the PK7 padding method.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class CipherMcrypt
{
	private $_type;
	private $_module;
	private $_mode;
	private $_key;
	private $_iv;
	private $_padding;

	// 0 = unloaded, 1 = loaded,
	// 2 = encrypting, 3 = decrypting
	private $_state = 0;

	const PK7_PADDING = "pk7";

	/**
	 * Constructs a CipherMcrypt from the mcrypt cipher $cipherType, the mcrypt
	 * mode $mode, the key $key, the initialization vector $iv and the padding
	 * mode $padding. If $mode and $key are both null and are not set in some
	 * way before calling the method load, it will fail miserably.
	 * @param $cipherType The mcrypt module to use.
	 * @param $mode The mcrypt encryption mode to use.
	 * @param $key The key, used for decryption as well as encryption.
	 * @param $iv The initialization vector.
	 * @param $padding The type of padding to use.
	 */
	public function __construct($cipherType, $mode = null,
			$key = null, $iv = null, $padding = null)
	{
		$this->_type = $cipherType;
		$this->_mode = $mode;
		$this->_key = $key;
		$this->_iv = $iv;
		$this->_padding = $padding;
		$this->_module = null;
		$this->_state = 0;
	}

	/******************
	 * Public methods *
	 ******************/

	/**
	 * Sets the mcrypt mode to use.
	 * @param $m A mcrypt mode.
	 */
	public function setMode($m)
	{
		$this->_mode = $m;
	}

	/**
	 * Sets the decryption key to use.
	 * @param $k A binary string used as key (must be of correct length).
	 */
	public function setKey($k)
	{
		$this->_key = $k;
	}

	/**
	 * Sets the initialization vector to use.
	 * @param $iv A binary string used as IV (must be of correct length).
	 */
	public function setIV($iv)
	{
		$this->_iv = $iv;
	}

	/**
	 * Sets the padding mode to use.
	 * @param $p A padding method.
	 */
	public function setPadding($p)
	{
		$this->_padding = $p;
	}

	/**
	 * Gets the current initilization vector.
	 * @return The current initialization vector (may be null if it has not
	 * been set yet).
	 */
	public function getIV()
	{
		return $this->_iv;
	}

	/****************************
	 * Interface implementation *
	 ****************************/

	/**
	 * Loads the cipher in mcrypt (must be done before starting to decrypt!).
	 * If it was already opened, tries to close it and re-open it (!) because
	 * that should happen only between an encrypt and a decrypt operation (in
	 * which case it is indeed needed).
	 * @return true if loading was successful, false otherwise.
	 */
	public function load()
	{
		if($this->_state != 0)
			return true;
		if($this->_module !== null)
			$this->unload();
		if($this->_mode == null || $this->_key === null)
			return false; // we could almot raise an error...
		$this->_module = mcrypt_module_open($this->_type, '',
			$this->_mode, '');
		if($this->_iv === null)
			$this->_iv = mcrypt_create_iv(mcrypt_get_iv_size($this->_type,
				$this->_mode), MCRYPT_RAND);
		mcrypt_generic_init($this->_module, $this->_key, $this->_iv);
		$this->_state = 1;
		return true;
	}

	/**
	 * Closes the mcrypt cipher.
	 */
	public function unload()
	{
		mcrypt_generic_deinit($this->_module);
		mcrypt_module_close($this->_module);
		$this->_module = null;
		$this->_state = 0;
	}

	/**
	 * Encrypts the given string $s.
	 * @param $s A string to encrypt.
	 * @return The encrypted string, or null in case of error.
	 */
	public function encrypt($s)
	{
		if($this->_state == 0)
			if(!$this->load())
				return null;
		if($this->_state == 3)
		{
			mcrypt_generic_deinit($this->_module);
			mcrypt_generic_init($this->_module, $this->_key, $this->_iv);
		}
		$this->_state = 2;
		$padded = $this->_padding == self::PK7_PADDING ?
				self::addPK7Padding($s,
					mcrypt_get_block_size($this->_type, $this->_mode)) : $s;
		return mcrypt_generic($this->_module, $padded);
	}

	/**
	 * Decrypts the string $s.
	 * @param $s An encrypted string.
	 * @return The decrypted string, or null in case of error.
	 */
	public function decrypt($s)
	{
		if($this->_state == 0)
			if(!$this->load())
				return null;
		if($this->_state == 2)
		{
			mcrypt_generic_deinit($this->_module);
			mcrypt_generic_init($this->_module, $this->_key, $this->_iv);
		}
		$this->_state = 3;
		$padded = mdecrypt_generic($this->_module, $s);
		if($this->_padding == self::PK7_PADDING)
			return self::removePK7Padding($padded,
				mcrypt_get_block_size($this->_type, $this->_mode));
		return $padded;
	}

	/*******************
	 * Private methods *
	 *******************/

	/**
	 * Pads the given string $str with the PK7 padding scheme, so that its
	 * length shall be a multiple of $blocksize.
	 * @param $str A string to pad.
	 * @param $blocksize The block size.
	 * @return The resulting padded string.
	 */
	private static function addPK7Padding($str, $blocksize)
	{
		$len = strlen($str);
		$pad = $blocksize - ($len % $blocksize);
		return $str . str_repeat(chr($pad), $pad);
	}

	/**
	 * Tries to unpad the PK7-padded string $string.
	 * @param $string The string to unpad.
	 * @return The unpadded string, or null in case of error.
	 */
	private static function removePK7Padding($string, $blocksize)
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