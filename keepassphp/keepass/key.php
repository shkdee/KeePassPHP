<?php
/**
 * An interface for a KeePass key, which is basically just in charge of
 * providing a hash (as a binary string).
 */
interface iKey
{
	public function getHash();
}

/**
 * A KeePass composite key, used in the decryption of a database file. It takes
 * several iKeys and hashes all of them toghether to build the composite key.
 */
class CompositeKey implements iKey
{
	private $keys;

	public function __construct()
	{
		$this->keys = array();
	}

	/**
	 * Adds the given key $key to this CompositeKey.
	 * @param iKey $key The key to add.
	 */
	public function addKey(iKey $key)
	{
		array_push($this->keys, $key->getHash());
	}

	/**
	 * Returns the hash of all the keys of this CompositeKey.
	 * @return string Returns the hash as a binary string.
	 */
	public function getHash()
	{
		return HashHouse::hashArray($this->keys);
	}
}

/**
 * An iKey build from something already hashed.
 */
class KeyFromHash implements iKey
{
	protected $hash;

	/**
	 * Stores the given hash, that should be a binary string.
	 * @param string $h
	 */
	public function __construct($h)
	{
		$this->hash = $h;
	}

	/**
	 * Retrieve the hash of this key.
	 * @return string Returns the hash as a binary string.
	 */
	public function getHash()
	{
		return $this->hash;
	}
}

/**
 * An iKey build from a password, i.e a string.
 */
class KeyFromPassword extends KeyFromHash
{
	/**
	 * Stores the hash of the given password.
	 * @param string $pwd The string to hash.
	 */
	public function __construct($pwd)
	{
		$this->hash = HashHouse::hash($pwd);
	}
}

/**
 * An iKey built from a KeePass key file. Supports XML, binary and hex files.
 * If the parsing of the file is successful, the property $isParsed is set to
 * true, and false otherwise ; its value must then be checked when a new
 * KeyFromFile object is created, to see whether something went wrong or not :
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
	 * Tries to parse the given file, to find the hash inside. If the parsing
	 * went successfully, the property $this->isParsed is set to true, and to
	 * false otherwise.
	 * @param string $filename The name of the file to parse.
	 */
	public function __construct($filename)
	{
		if(!($this->isParsed = $this->tryParseXML($filename)))
			$this->isParsed = $this->tryParse($filename);
	}

	/**
	 * Tries to parse the given file as a binary or a hex file.
	 * @param string $filename The name of the file to parse.
	 * @return boolean Returns true in case of success, false otherwise.
	 */
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

	/**
	 * Tries to parse the given file as a KeePass XML key file.
	 * @param string $filename The name of the file to parse.
	 * @return boolean Returns true in case of success, false otherwise.
	 */
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