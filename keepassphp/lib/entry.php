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
	 * title of this entry (if non null).
	 */
	public $title;
	/**
	 * tags of this entry (if non null).
	 */
	public $tags;
	/**
	 * url of this entry (if non null).
	 */
	public $url;
	/**
	 * username of this entry (if non null).
	 */
	public $username;
	/**
	 * iBoxedString instance containing the password of this entry (if non null).
	 */
	public $password;
	/**
	 * Array of entries of this entry's history (if non null).
	 */
	public $history;
	
	/** Array of additional data fields */
	public $extra;

	public function __construct()
	{
		$this->uuid = null;
		$this->icon = null;
		$this->customIcon = null;
		$this->title = null;
		$this->tags = null;
		$this->url = null;
		$this->username = null;
		$this->password = null;
		$this->history = null;
		$this->extra = null;
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
     *
     * @param ProtectedXMLReader $reader       A XML reader located at a string element node.
     * @param bool|string        $extra_fields [optional] A string with a regular expression for the include extra fields
     */
	private function readString(ProtectedXMLReader $reader, $extra_fields = false)
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
		elseif(\strcasecmp($key, Database::KEY_URL) == 0)
			$this->url = $value->getPlainString();
		elseif(\strcasecmp($key, Database::KEY_USERNAME) == 0)
			$this->username = $value->getPlainString();
		elseif(\strcasecmp($key, Database::KEY_TITLE) == 0)
			$this->title = $value->getPlainString();
	    elseif ($extra_fields !== false && @preg_match($extra_fields, $key))
	        $this->extra[$key] = $value->getPlainString();
	}

	/**
	 * Creates an array describing this entry, containing everything except
	 * password. This array can be serialized to json safely.
	 * @return An array containing this entry (except password).
	 */
	public function toArray()
	{
		$result = array();
		if($this->uuid != null)
			$result[Database::XML_UUID] = $this->uuid;
		if($this->icon != null)
			$result[Database::XML_ICONID] = $this->icon;
		if($this->customIcon != null)
			$result[Database::XML_CUSTOMICONUUID] = $this->customIcon;
		if($this->tags != null)
			$result[Database::XML_TAGS] = $this->tags;
		if($this->url != null)
			$result[Database::KEY_URL] = $this->url;
		if($this->username != null)
			$result[Database::KEY_USERNAME] = $this->username;
		if($this->title != null)
			$result[Database::KEY_TITLE] = $this->title;
		if($this->history != null)
		{
			$history = array();
			foreach($this->history as &$entry)
				$history[] = $entry->toArray();
			$result[Database::XML_HISTORY] = $history;
		}
		if($this->extra != null)
			$result[Database::KEY_EXTRA] = $this->extra;
		return $result;
	}

	/**
	 * Creates a new Entry instance from an array created by the method
	 * toArray() of another Entry instance.
	 * @param $array An array created by the method toArray().
	 * @return A Entry instance if the parsing went okay, null otherwise.
	 */
	public static function loadFromArray(array $array)
	{
		if($array == null)
			return null;
		$entry = new Entry();
		$entry->uuid = Database::getIfSet($array, Database::XML_UUID);
		$entry->icon = Database::getIfSet($array, Database::XML_ICONID);
		$entry->customIcon = Database::getIfSet($array, Database::XML_CUSTOMICONUUID);
		$entry->tags = Database::getIfSet($array, Database::XML_TAGS);
		$entry->url = Database::getIfSet($array, Database::KEY_URL);
		$entry->username = Database::getIfSet($array, Database::KEY_USERNAME);
		$entry->title = Database::getIfSet($array, Database::KEY_TITLE);
		$entry->extra = Database::getIfSet($array, Database::KEY_EXTRA);
		$history = Database::getIfSet($array, Database::XML_HISTORY);
		if(!empty($history))
		{
			foreach($history as &$e)
				$entry->addHistoryEntry(self::loadFromArray($e));
		}
		return $entry;
	}
    
    /**
     * Creates a new Entry instance from a ProtectedXMLReader instance reading
     * a KeePass 2.x database and located at an Entry element node.
     *
     * @param ProtectedXMLReader $reader       A XML reader.
     * @param bool|string        $extra_fields [optional] A string with a regular expression for the include extra fields
     *
     * @return Entry A Entry instance if the parsing went okay, null otherwise.
     */
	public static function loadFromXML(ProtectedXMLReader $reader, $extra_fields = false)
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
				$entry->readString($reader, $extra_fields);
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
