<?php

namespace KeePassPHP;

/**
 * A class that manages an entry of a KeePass 2.x password database.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class Entry
{
	/**
	 * uuid of this entry in base64.
	 */
	public $uuid;
	/**
	 * ID of the KeePass icon of this entry (if non null).
	 */
	public $icon;
	/**
	 * uuid in base64 of the custom icon of this entry (if non null).
	 */
	public $customIcon;
	/**
	 * tags of this entry (if non null).
	 */
	public $tags;
	/**
	 * iBoxedString instance containing the password of this entry (if non null).
	 */
	public $password;
	/**
	 * string fields of this entry as a map (key => value as an iBoxedString
	 * instance). It contains all the standard string fields of KeePass except
	 * password (notes, title, url, username), and all custom user-defined
	 * string fields.
	 */
	public $stringFields;
	/**
	 * Array of entries of this entry's history (if non null).
	 */
	public $history;

	public function __construct()
	{
		$this->uuid = null;
		$this->icon = null;
		$this->customIcon = null;
		$this->tags = null;
		$this->password = null;
		$this->stringFields = array();
		$this->history = null;
	}

	/**
	 * Gets the string value of this Entry string field corresponding to the
	 * given key, or an empty string of no field with that key exists.
	 * @param $key A key.
	 * @return A non-null string, containing the value of the field.
	 */
	function getStringField($key)
	{
		return isset($this->stringFields[$key])
			? $this->stringFields[$key]->getPlainString()
			: "";
	}

	/**
	 * Adds an Entry instance to the history of this entry.
	 * @param $entry An Entry instance, possibly null (it is then ignored).
	 */
	private function addHistoryEntry($entry)
	{
		if($entry != null)
		{
			if($this->history == null)
				$this->history = array();
			$this->history[] = $entry;
		}
	}

	/**
	 * Parses a string XML element node.
	 * @param $reader A XML reader located at a string element node.
	 */
	private function readString(ProtectedXMLReader $reader)
	{
		$d = $reader->depth();
		$key = null;
		$value = null;
		while($reader->read($d))
		{
			if($reader->isElement(Database::XML_STRING_KEY))
				$key = $reader->readTextInside();
			elseif($reader->isElement(Database::XML_STRING_VALUE))
				$value = $reader->readTextInside(true);
		}
		if(empty($key) || $value == null)
			return;
		if(\strcasecmp($key, Database::KEY_PASSWORD) == 0)
			$this->password = $value;
		else
			$this->stringFields[$key] = $value;
	}

	/**
	 * Creates an array describing this entry (with respect to the filter).
	 * This array can be safely serialized to json after.
	 * @param $filter A filter to select the data that is actually copied to
	 *                the array.
	 * @return An array containing this entry.
	 */
	public function toArray(iFilter $filter)
	{
		$result = array();
		if($this->uuid != null)
			$result[Database::XML_UUID] = $this->uuid;
		if($this->icon != null && $filter->acceptIcons())
			$result[Database::XML_ICONID] = $this->icon;
		if($this->customIcon != null && $filter->acceptIcons())
			$result[Database::XML_CUSTOMICONUUID] = $this->customIcon;
		if($this->tags != null && $filter->acceptTags())
			$result[Database::XML_TAGS] = $this->tags;
		$stringFields = array();
		if($this->password != null && $filter->acceptPasswords())
			$stringFields[Database::KEY_PASSWORD] = $this->password->getPlainString();
		if(!empty($this->stringFields))
		{
			foreach($this->stringFields as $key => &$value)
			{
				if($filter->acceptStrings($key))
					$stringFields[$key] = $value->getPlainString();
			}
		}
		if(!empty($stringFields))
			$result[Database::KEY_STRINGFIELDS] = $stringFields;
		if($this->history != null)
		{
			$history = array();
			foreach($this->history as &$entry)
			{
				if($filter->acceptHistoryEntry($entry))
					$history[] = $entry->toArray($filter);
			}
			if(!empty($history))
				$result[Database::XML_HISTORY] = $history;
		}
		return $result;
	}

	/**
	 * Creates a new Entry instance from an array created by the method
	 * toArray() of another Entry instance.
	 * @param $array An array created by the method toArray().
	 * @param $version The version of the array format.
	 * @return A Entry instance if the parsing went okay, null otherwise.
	 */
	public static function loadFromArray(array $array, $version)
	{
		if($array == null)
			return null;
		$entry = new Entry();
		$entry->uuid = Database::getIfSet($array, Database::XML_UUID);
		$entry->icon = Database::getIfSet($array, Database::XML_ICONID);
		$entry->customIcon = Database::getIfSet($array, Database::XML_CUSTOMICONUUID);
		$entry->tags = Database::getIfSet($array, Database::XML_TAGS);
		if($version <= KphpDB::VERSION_0)
		{
			$keys = array(Database::KEY_TITLE, Database::KEY_USERNAME,
				Database::KEY_URL);
			foreach($keys as $key)
			{
				$value = Database::getIfSet($array, $key);
				if($value != null)
					$entry->stringFields[$key] = new UnprotectedString($value);
			}
		}
		else
		{
			$stringFields = Database::getIfSet($array, Database::KEY_STRINGFIELDS);
			if(!empty($stringFields))
			{
				foreach($stringFields as $key => $value)
					$entry->stringFields[$key] = new UnprotectedString($value);
			}
		}
		$history = Database::getIfSet($array, Database::XML_HISTORY);
		if(!empty($history))
		{
			foreach($history as &$e)
				$entry->addHistoryEntry(self::loadFromArray($e, $version));
		}
		return $entry;
	}

	/**
	 * Creates a new Entry instance from a ProtectedXMLReader instance reading
	 * a KeePass 2.x database and located at an Entry element node.
	 * @param $reader A XML reader.
	 * @return A Entry instance if the parsing went okay, null otherwise.
	 */
	public static function loadFromXML(ProtectedXMLReader $reader)
	{
		if($reader == null)
			return null;
		$entry = new Entry();
		$d = $reader->depth();
		while($reader->read($d))
		{
			if($reader->isElement(Database::XML_UUID))
				$entry->uuid = $reader->readTextInside();
			elseif($reader->isElement(Database::XML_ICONID))
				$entry->icon = $reader->readTextInside();
			elseif($reader->isElement(Database::XML_CUSTOMICONUUID))
				$entry->customIcon = $reader->readTextInside();
			else if($reader->isElement(Database::XML_TAGS))
				$entry->tags = $reader->readTextInside();
			elseif($reader->isElement(Database::XML_STRING))
				$entry->readString($reader);
			elseif($reader->isElement(Database::XML_HISTORY))
			{
				$historyD = $reader->depth();
				while($reader->read($historyD))
				{
					if($reader->isElement(Database::XML_ENTRY))
						$entry->addHistoryEntry(self::loadFromXML($reader));
				}
			}
		}
		return $entry;
	}
}


?>