<?php

/**
 * An abstract class in charge of managing a KeePass database: loading it,
 * and extracting entries, icons and passwords from it, with an unified way
 * (because several sources could exist : keepass 1.x file, keepass 2.x file,
 * file not stored locally, etc.).
 *
 * @author Louis
 */
abstract class Database
{
	const DEFAULT_TITLE = "[NoTitle]";

	const KEY_UUID = "UUID";
	const KEY_CUSTOMICON = "CustomIcon";
	const KEY_TAGS = "Tags";
	const KEY_TITLE = "Title";
	const KEY_USERNAME = "UserName";
	const KEY_URL = "URL";
	
	private $entries;    
	protected $icons;

	public function __construct()
	{
		$this->entries = null;
		$this->icons = new IconRepository();
	}

	public function getEntries()
	{
		if($this->entries == null)
			$this->entries = $this->parseEntries();
		return $this->entries;
	}

	public function useEntries($entries)
	{
		$this->entries = $entries;
	}

	/**
	 * Returns the src of the icon identified by the UUID $iconuuid, id est
	 * the string that must be put in <img src="<here>" />.
	 * @param string $iconuuid
	 * @return string
	 */
	public function getIconSrc($iconuuid)
	{
		return $this->icons->getIconForDisplay($iconuuid);
	}

	/******************
	 * Abstract stuff *
	 ******************/
	
	public abstract function load();
	public abstract function getPassword($uuid);
	public abstract function parseEntries();

	/***************************
	 * Static useful functions *
	 ***************************/

	/**
	 * Returns $a[$i] if it exsists, or $d otherwise.
	 * @param array $a
	 * @param index (numerical or string) $i
	 * @param type $d
	 * @return type
	 */
	public static function getIfSet($a, $i, $d = null)
	{
		if(isset($a[$i]))
			return $a[$i];
		return $d;
	}
}

?>
