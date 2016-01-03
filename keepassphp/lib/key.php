<?php

namespace KeePassPHP;

/**
 * Implementation of keys, which are object that can yield hashes.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */

/**
 * An object that contains a secret in the form of a hash.
 */
interface iKey
{
	/**
	 * Gets this instance hash.
	 * @return A raw hash string.
	 */
	public function getHash();
}

/**
 * A KeePass composite key, used in the decryption of a kdbx file. It takes
 * several iKeys and hashes all of them toghether to build the composite key.
 */
class CompositeKey implements iKey
{
	private $_keys;
	private $_hashAlgo;

	/**
	 * Constructs a new CompositeKey instance using $hashAlgo to hash all
	 * keys all together.
	 * @param $hashAlgo A hash algorithm name.
	 */
	public function __construct($hashAlgo)
	{
		$this->_keys = array();
		$this->_hashAlgo = $hashAlgo;
	}

	/**
	 * Adds the given key $key to this CompositeKey.
	 * @param $key An iKey instance to add.
	 */
	public function addKey(iKey $key)
	{
		array_push($this->_keys, $key->getHash());
	}

	/**
	 * Computes the hash of all the keys of this CompositeKey.
	 * @return A raw hash string.
	 */
	public function getHash()
	{
		$h = hash_init($this->_hashAlgo);
		foreach($this->_keys as &$v)
			hash_update($h, $v);
		$r = hash_final($h, true);
		unset($h);
		return $r;
	}
}

/**
 * An iKey built from something already hashed.
 */
class KeyFromHash implements iKey
{
	protected $hash;

	/**
	 * Stores the given hash string.
	 * @param $h A raw hash string.
	 */
	public function __construct($h)
	{
		$this->hash = $h;
	}

	/**
	 * Retrieves the stored hash.
	 * @return A raw hash string.
	 */
	public function getHash()
	{
		return $this->hash;
	}
}

/**
 * An iKey built from a string password.
 */
class KeyFromPassword extends KeyFromHash
{
	/**
	 * Constructs a KeyFromPassword instance from the password $pwd.
	 * @param $pwd A string.
	 * @param $hashAlgo A hash algorithm name.
	 */
	public function __construct($pwd, $hashAlgo)
	{
		parent::__construct(hash($hashAlgo, $pwd, true));
	}
}

/**
 * An iKey built from a KeePass key file. Supports XML, binary and hex files.
 * If the parsing of the file is successful, the property $isParsed is set to
 * true, and false otherwise; its value must then be checked when a new
 * KeyFromFile object is created, to see whether something went wrong or not:
 * if it false, the hash that this object may return will probably mean
 * nothing.
 */
class KeyFromFile extends KeyFromHash
{
	const XML_ROOT = "KeyFile";
	const XML_KEY = "Key";
	const XML_DATA = "Data";

	public $isParsed = false;

	/**
	 * Tries to parse $content to find the hash inside. If the parsing is
	 * successfully, the property $this->isParsed is set to true.
	 * @param $content A key file content.
	 */
	public function __construct($content)
	{
		$this->isParsed = $this->tryParseXML($content) ||
			$this->tryParse($content);
	}

	/**
	 * Tries to parse $content as a binary or a hex key file.
	 * @param $content A key file content.
	 * @return true in case of success, false otherwise.
	 */
	private function tryParse($content)
	{
		if(strlen($content) == 32)
		{
			$this->hash = $content;
			return true;
		}
		if(strlen($content) == 64)
		{
			$this->hash = hex2bin($content);
			return true;
		}
		return false;
	}

	/**
	 * Tries to parse $content as a KeePass XML key file.
	 * @param $content A key file content.
	 * @return true in case of success, false otherwise.
	 */
	private function tryParseXML($content)
	{
		$xml = new ProtectedXMLReader(null);
		if(!$xml->XML($content) || !$xml->read(-1))
			return false;
		if($xml->isElement(self::XML_ROOT))
		{
			$d = $xml->depth();
			while($xml->read($d))
			{
				if($xml->isElement(self::XML_KEY))
				{
					$keyD = $xml->depth();
					while($xml->read($keyD))
					{
						if($xml->isElement(self::XML_DATA))
						{
							$value = $xml->readTextInside();
							$this->hash = base64_decode($value);
							$xml->close();
							return true;
						}
					}
				}
			}
		}
		$xml->close();
		return false;
	}
}

?>