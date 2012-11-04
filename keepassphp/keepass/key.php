<?php
/**
 * A KeePass composite key, used in the decryption
 * of a database file. It takes several Keys (see
 * below) and hashes all of them toghether to build
 * the composite key.
 *
 * @author Louis
 */
class CompositeKey
{
	private $keys;

	public function __construct()
	{
		$this->keys = array();
	}

	public function addKey(Key $key)
	{
		array_push($this->keys, $key->getHash());
	}

	public function getHash()
	{
		return HashHouse::hashArray($this->keys);
	}
}

/**
 * An abstract KeePass key, which basically is just in
 * charge of providing a hash.
 */
abstract class Key
{
	public abstract function getHash();
}

/**
 * A Key build from something already hashed.
 */
class KeyFromHash extends Key
{
	protected $hash;

	public function __construct($h)
	{
		$this->hash = $h;
	}

	public function getHash()
	{
		return $this->hash;
	}
}

/**
 * A Key build from a passwod, i.e a string.
 */
class KeyFromPassword extends KeyFromHash
{
	public function __construct($pwd)
	{
		$this->hash = HashHouse::hash($pwd);
	}
}

/**
 * A Key build from a KeePass key file. Supports
 * XML, binary and hex files.
 */
class KeyFromFile extends KeyFromHash
{
	const XML_ROOT = "KeyFile";
	const XML_KEY = "Key";
	const XML_DATA = "Data";
	
	public function __construct($filename)
	{
		if(!$this->tryParseXML($filename))
			if(!$this->tryParse($filename))
				KeePassPHP::raiseError("Key file parsing failure !");
	}

	private function tryParse($filename)
	{
		$reader = RessourceReader::openFile($filename);
		if($reader == null)
			return false;
		$key = $reader->readToTheEnd();
		if(strlen($key) == 32)
		{
			$this->hash = $key;
			return true;
		}
		if(strlen($key) == 64)
		{
			$this->hash = hex2bin($key);
			return true;
		}
		return false;
	}

	private function tryParseXML($filename)
	{
		$xml = new XMLStackReader();
		if(!$xml->open($filename))
			return false;

		$parents = array(self::XML_ROOT, self::XML_KEY, self::XML_DATA);
		if($xml->readUntilParentsBe($parents))
		{
			if($xml->isTextInside())
			{
				$this->hash = base64_decode($xml->r->value);
				$xml->close();
				return true;
			}
		}
		$xml->close();
		return false;
	}
}

?>