<?php

namespace KeePassPHP;

/**
 * Implementation of protected strings, id est strings that may be stored in a
 * different form in memory, and whose real value is computed on demand.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */

/**
 * An object that can yield a string.
 */
interface iBoxedString
{
	/**
	 * Gets the boxed string.
	 * @return a string.
	 */
	public function getPlainString();
}

/**
 * A boxed plain string.
 */
class UnprotectedString implements iBoxedString
{
	private $_string;

	public function __construct($string)
	{
		$this->_string = $string;
	}

	/**
	 * Gets the boxed string.
	 * @return a string.
	 */
	public function getPlainString()
	{
		return $this->_string;
	}
}

/**
 * A string protected by a mask to xor.
 */
class ProtectedString implements iBoxedString
{
	private $_string;
	private $_random;

	public function __construct($string, $random)
	{
		$this->_string = $string;
		$this->_random = $random;
	}

	/**
	 * Gets the real content of the protected string.
	 * @return a string.
	 */
	public function getPlainString()
	{
		return $this->_string ^ $this->_random;
	}
}


?>