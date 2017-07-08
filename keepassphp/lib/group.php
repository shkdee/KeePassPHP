<?php

namespace KeePassPHP;

/**
 * A class that manages a group of a KeePass 2.x password database.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class Group
{
	/**
	 * uuid of this group in base64.
	 */
	public $uuid;
	/**
	 * Name of the group (if non null).
	 */
	public $name;
	/**
	 * ID of the KeePass icon of this group (if non null).
	 */
	public $icon;
	/**
	 * uuid in base64 of the custom icon of this group (if non null).
	 */
	public $customIcon;
	/**
	 * Array of sub-groups of this group (if non null).
	 */
	public $groups;
	/**
	 * Array of entries of this group (if non null).
	 */
	public $entries;

	private function __construct()
	{
		$this->uuid = null;
		$this->name = null;
		$this->icon = null;
		$this->customIcon = null;
		$this->groups = null;
		$this->entries = null;
	}

	/**
	 * Gets the password of the entry of this group or of a sub-group whose
	 * uuid is $uuid.
	 * @param $uuid An entry uuid in base64.
	 * @return The decrypted password if the entry exists inside this group or
	 *         a sub-group, null otherwise.
	 */
	public function getPassword($uuid)
	{
		if($this->entries != null)
		{
			foreach($this->entries as &$entry)
			{
				if($entry->uuid === $uuid)
					return $entry->password;
			}
		}
		if($this->groups != null)
		{
			foreach($this->groups as &$group)
			{
				$value = $group->getPassword($uuid);
				if($value != null)
					return $value;
			}
		}
		return null;
	}

	/**
	 * Adds a Group instance as a sub-group of this group.
	 * @param $entry A Group instance, possibly null (it is then ignored).
	 */
	private function addGroup($group)
	{
		if($group != null)
		{
			if($this->groups == null)
				$this->groups = array();
			$this->groups[] = $group;
		}
	}

	/**
	 * Adds an Entry instance to this group.
	 * @param $entry An Entry instance, possibly null (it is then ignored).
	 */
	private function addEntry($entry)
	{
		if($entry != null)
		{
			if($this->entries == null)
				$this->entries = array();
			$this->entries[] = $entry;
		}
	}

	/**
	 * Creates an array describing this group, containing everything except
	 * passwords. This array can be serialized to json safely.
	 * @return An array containing this group (except passwords).
	 */
	public function toArray()
	{
		$result = array();
		if($this->uuid != null)
			$result[Database::XML_UUID] = $this->uuid;
		if($this->name != null)
			$result[Database::XML_NAME] = $this->name;
		if($this->icon != null)
			$result[Database::XML_ICONID] = $this->icon;
		if($this->customIcon != null)
			$result[Database::XML_CUSTOMICONUUID] = $this->customIcon;
		if($this->groups != null)
		{
			$groups = array();
			foreach($this->groups as &$group)
				$groups[] = $group->toArray();
			$result[Database::GROUPS] = $groups;
		}
		if($this->entries != null)
		{
			$entries = array();
			foreach($this->entries as &$entry)
				$entries[] = $entry->toArray();
			$result[Database::ENTRIES] = $entries;
		}
		return $result;
	}

	/**
	 * Creates a new Group instance from an array created by the method
	 * toArray() of another Group instance.
	 * @param $array An array created by the method toArray().
	 * @return A Group instance if the parsing went okay, null otherwise.
	 */
	public static function loadFromArray(array $array)
	{
		if($array == null)
			return null;
		$group = new Group();
		$group->uuid = Database::getIfSet($array, Database::XML_UUID);
		$group->name = Database::getIfSet($array, Database::XML_NAME);
		$group->icon = Database::getIfSet($array, Database::XML_ICONID);
		$group->customIcon = Database::getIfSet($array, Database::XML_CUSTOMICONUUID);
		$groups = Database::getIfSet($array, Database::GROUPS);
		if(!empty($groups))
		{
			foreach($groups as &$subgroup)
				$group->addGroup(self::loadFromArray($subgroup));
		}
		$entries = Database::getIfSet($array, Database::ENTRIES);
		if(!empty($entries))
		{
			foreach($entries as &$entry)
				$group->addEntry(Entry::loadFromArray($entry));
		}
		return $group;
	}
    
    /**
     * Creates a new Group instance from a ProtectedXMLReader instance reading
     * a KeePass 2.x database and located at a Group element node.
     *
     * @param ProtectedXMLReader $reader       A XML reader.
     * @param bool|string        $extra_fields [optional] A string with a regular expression for the include extra fields
     *
     * @return Group A Group instance if the parsing went okay, null otherwise.
     */
	public static function loadFromXML(ProtectedXMLReader $reader, $extra_fields = false)
	{
		if($reader == null)
			return null;
		$group = new Group();
		$d = $reader->depth();
		while($reader->read($d))
		{
			if($reader->isElement(Database::XML_GROUP))
				$group->addGroup(Group::loadFromXML($reader, $extra_fields));
			elseif($reader->isElement(Database::XML_ENTRY))
				$group->addEntry(Entry::loadFromXML($reader, $extra_fields));
			elseif($reader->isElement(Database::XML_UUID))
				$group->uuid = $reader->readTextInside();
			elseif($reader->isElement(Database::XML_NAME))
				$group->name = $reader->readTextInside();
			elseif($reader->isElement(Database::XML_ICONID))
				$group->icon = $reader->readTextInside();
			elseif($reader->isElement(Database::XML_CUSTOMICONUUID))
				$group->customIcon = $reader->readTextInside();
		}
		return $group;
	}
}

?>
