<?php

namespace KeePassPHP;

/**
 * A class that manages a KeePass 2.x password database.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class Database
{
	const XML_KEEPASSFILE = "KeePassFile";
	const XML_META = "Meta";
	const XML_HEADERHASH = "HeaderHash";
	const XML_DATABASENAME = "DatabaseName";
	const XML_CUSTOMICONS = "CustomIcons";
	const XML_ICON = "Icon";
	const XML_UUID = "UUID";
	const XML_DATA = "Data";
	const XML_ROOT = "Root";
	const XML_GROUP = "Group";
	const XML_ENTRY = "Entry";
	const XML_NAME = "Name";
	const XML_ICONID = "IconID";
	const XML_CUSTOMICONUUID = "CustomIconUUID";
	const XML_STRING = "String";
	const XML_STRING_KEY = "Key";
	const XML_STRING_VALUE = "Value";
	const XML_HISTORY = "History";
	const XML_TAGS = "Tags";

	const KEY_PASSWORD = "Password";
	const KEY_STRINGFIELDS = "StringFields";
	const KEY_TITLE = "Title";
	const KEY_USERNAME = "UserName";
	const KEY_URL = "URL";

	const GROUPS = "Groups";
	const ENTRIES = "Entries";

	private $_name;
	private $_groups;
	/** Associative array (icon uuid in base64 => icon data in base64) keeping
	 * the data of all custom icons. */
	private $_customIcons;
	/** Header hash registered in this database. */
	private $_headerHash;

	private function __construct()
	{
		$this->_name = null;
		$this->_groups = null;
		$this->_customIcons = null;
		$this->_headerHash = null;
	}

	/**
	 * Gets the name of this database.
	 * @return This database name.
	 */
	public function getName()
	{
		return $this->_name;
	}

	/**
	 * Gets the groups of this database.
	 * @return An array of Group instances.
	 */
	public function getGroups()
	{
		return $this->_groups;
	}

	/**
	 * Gets the data of the custom icon whose uuid is $uuid.
	 * @param $uuid A custom icon uuid in base64.
	 * @return A custom icon data in base64 if it exists, null otherwise.
	 */
	public function getCustomIcon($uuid)
	{
		return $this->_customIcons == null ? null 
			: "data:image/png;base64," . $this->_customIcons[$uuid];
	}

	/**
	 * Gets the password of the entry whose uuid is $uuid.
	 * @param $uuid An entry uuid in base64.
	 * @return The decrypted password if the entry exists, null otherwise.
	 */
	public function getPassword($uuid)
	{
		if($this->_groups != null)
		{
			foreach($this->_groups as &$group)
			{
				$value = $group->getPassword($uuid);
				if($value != null)
					return $value->getPlainString();
			}
		}
		return null;
	}

	/**
	 * Parses a custom icon XML element node, and adds the result to the
	 * $customIcons array.
	 * @param $reader A ProtectedXMLReader instance located at a custom icon
	 *                element node.
	 */
	private function parseCustomIcon(ProtectedXMLReader $reader)
	{
		$uuid = null;
		$data = null;
		$d = $reader->depth();
		while($reader->read($d))
		{
			if($reader->isElement(self::XML_UUID))
				$uuid = $reader->readTextInside();
			elseif($reader->isElement(self::XML_DATA))
				$data = $reader->readTextInside();
		}
		if(!empty($uuid) && !empty($data))
		{
			if($this->_customIcons == null)
				$this->_customIcons = array();
			$this->_customIcons[$uuid] = $data;
		}
	}

	/**
	 * Adds a Group instance to this Database.
	 * @param $entry A Group instance, possibly null (it is then ignored).
	 */
	private function addGroup($group)
	{
		if($group != null)
		{
			if($this->_groups == null)
				$this->_groups = array();
			$this->_groups[] = $group;
		}
	}

	/**
	 * Loads the content of a Database from a ProtectedXMLReader instance
	 * reading a KeePass 2.x database and located at a KeePass file element
	 * node.
	 * @param $reader A XML reader.
	 */
	private function parseXML(ProtectedXMLReader $reader)
	{
		$d = $reader->depth();
		while($reader->read($d))
		{
			if($reader->isElement(self::XML_META))
			{
				$metaD = $reader->depth();
				while($reader->read($metaD))
				{
					if($reader->isElement(self::XML_HEADERHASH))
						$this->_headerHash = base64_decode($reader->readTextInside());
					elseif($reader->isElement(self::XML_DATABASENAME))
						$this->_name = $reader->readTextInside();
					elseif($reader->isElement(self::XML_CUSTOMICONS))
					{
						$iconsD = $reader->depth();
						while($reader->read($iconsD))
						{
							if($reader->isElement(self::XML_ICON))
								$this->parseCustomIcon($reader);
						}
					}
				}
			}
			elseif($reader->isElement(self::XML_ROOT))
			{
				$rootD = $reader->depth();
				while($reader->read($rootD))
				{
					if($reader->isElement(self::XML_GROUP))
						$this->addGroup(Group::loadFromXML($reader));
				}
			}
		}
	}

	/**
	 * Creates an array describing this database (with respect to the filter).
	 * This array can be safely serialized to json after.
	 * @param $filter A filter to select the data that is actually copied to
	 *                the array (if null, it will serialize everything except
	 *                from passowrds).
	 * @return An array containing this database (except passwords).
	 */
	public function toArray(iFilter $filter = null)
	{
		if($filter == null)
			$filter = new AllExceptFromPasswordsFilter();
		$result = array();
		if($this->_name != null)
			$result[self::XML_DATABASENAME] = $this->_name;
		if($this->_customIcons != null && $filter->acceptIcons())
			$result[self::XML_CUSTOMICONS] = $this->_customIcons;
		if($this->_groups != null)
		{
			$groups = array();
			foreach($this->_groups as &$group)
			{
				if($filter->acceptGroup($group))
					$groups[] = $group->toArray($filter);
			}
			if(!empty($groups))
				$result[self::GROUPS] = $groups;
		}
		return $result;
	}

	/**
	 * Creates a new Database instance from an array created by the method
	 * toArray() of another Database instance.
	 * @param $array An array created by the method toArray().
	 * @param $version The version of the array format.
	 * @param &$error A string that will receive a message in case of error.
	 * @return A Database instance if the parsing went okay, null otherwise.
	 */
	public static function loadFromArray(array $array, $version, &$error)
	{
		if($array == null)
		{
			$error = "Database array load: array is empty.";
			return null;
		}
		$db = new Database();
		$db->_name = self::getIfSet($array, self::XML_DATABASENAME);
		$db->_customIcons = self::getIfSet($array, self::XML_CUSTOMICONS);
		$groups = self::getIfSet($array, self::GROUPS);
		if(!empty($groups))
		{
			foreach($groups as &$group)
				$db->addGroup(Group::loadFromArray($group, $version));
		}
		if($db->_name == null && $db->_groups == null)
		{
			$error = "Database array load: empty database.";
			return null;
		}
		$error = null;
		return $db;
	}

	/**
	 * Creates a new Database instance from an XML string with the format of
	 * a KeePass 2.x database.
	 * @param $xml An XML string.
	 * @param $randomStream A iRandomStream instance to decrypt protected data.
	 * @param &$error A string that will receive a message in case of error.
	 * @return A Database instance if the parsing went okay, null otherwise.
	 */
	public static function loadFromXML($xml, iRandomStream $randomStream,
		&$error)
	{
		$reader = new ProtectedXMLReader($randomStream);
		if(!$reader->XML($xml) || !$reader->read(-1))
		{
			$error = "Database XML load: cannot parse the XML string.";
			$reader->close();
			return null;
		}
		if(!$reader->isElement(self::XML_KEEPASSFILE))
		{
			$error = "Database XML load: the root element is not '" . self::XML_KEEPASSFILE . "'.";
			$reader->close();
			return null;
		}
		$db = new Database();
		$db->parseXML($reader);
		$reader->close();
		if($db->_name == null && $db->_groups == null)
		{
			$error = "Database XML load: empty database.";
			return null;
		}
		$error = null;
		return $db;
	}

	/**
	 * Creates a new Database instance from a .kdbx (KeePass 2.x) file.
	 * @param $reader A Reader instance that reads a .kdbx file.
	 * @param $key A iKey instance to use to decrypt the .kdbx file.
	 * @param &$error A string that will receive a message in case of error.
	 * @return A Database instance if the parsing went okay, null otherwise.
	 */
	public static function loadFromKdbx(Reader $reader, iKey $key, &$error)
	{
		$kdbx = KdbxFile::decrypt($reader, $key, $error);
		if($kdbx == null)
			return null;
		$db = self::loadFromXML($kdbx->getContent(), $kdbx->getRandomStream(),
			$error);
		if($db == null)
			return null;
		if($db->_headerHash !== $kdbx->getHeaderHash())
		{
			$error = "Database Kdbx load: header hash is not correct.";
			return null;
		}
		return $db;
	}

	/**
	 * Returns $array[$key] if it exists, null otherwise.
	 * @param $array An array.
	 * @param $key An array key.
	 * @return $array[$key] if it exists, null otherwise.
	 */
	public static function getIfSet(array $array, $key)
	{
		return isset($array[$key]) ? $array[$key] : null;
	}
}

?>