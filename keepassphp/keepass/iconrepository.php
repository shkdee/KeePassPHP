<?php

/**
 * Extensions of FileManager, implementing the required processing
 * of icons data (let them in base64 if not written on a file).
 *
 * @author Louis
 */

class IconManager extends FileManager
{
	protected function processForFile($value)
	{
		return base64_decode($value);
	}

	protected function processForMem($value)
	{
		return $value;
	}
}

/**
 * Class wrapping an IconManager (see just above), used to store and
 * retrieve custom icons of entries, identifying them with their uuid. Store
 * them as a file if possible, or as data URI if not.
 */
class IconRepository
{
	const DEFAULT_EXT = "png";

	private $writeable;
	
	public function __construct($canBeWritten = true)
	{
		$this->writeable = $canBeWritten;
	}

	public function addIcon($uuid, $data, $writeable = true)
	{
		KeePassPHP::$iconmanager->addWithKey($uuid, $data, self::DEFAULT_EXT,
			$writeable && $this->writeable);
	}

	public function getIconForDisplay($uuid)
	{
		$res = KeePassPHP::$iconmanager->getRawElementFromKey($uuid);
		if($res != null && is_array($res) && count($res) > 1)
		{
			list($type, $ext, $content) = $res;
			if($type == FileManager::TYPE_FILE)
				return KeePassPHP::$iconmanager->prependDir($content);
			else
				return "data:image/" . $ext . ";base64," . $content;
		}
		return null;
	}
}

?>