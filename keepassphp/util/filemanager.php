<?php

namespace KeePassPHP;

/**
 * This class manages a collection of binary strings, indexed by hashs (by
 * default, SHA-1) of these strings or of specific keys. This class tries to
 * be persistent by writing these strings as files in a defined directory,
 * unless required to not write them (either globally or on a per-file policy).
 * In that case, it keeps them in memory but will not be persistent.
 * That class is meant to be extended to better match other, specific purposes,
 * so everything is protected and not private.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class FileManager
{
	protected $prefix;
	protected $elements;
	protected $dir;
	protected $acceptFiles;
	protected $acceptMem;
	protected $load;

	const DEFAULT_EXT = "bin";
	const TYPE_FILE = 1;
	const TYPE_MEM = 2;

	/**
	 * Creates a new FileManager, storing files (if possible) in the directory
	 * $dir, and using the prefix $prefix for filenames. If $filesonly is true,
	 * all the data will be stored with files (and thus be persistent), and if
	 * $memonly is true, no files will be used (the data will thus not be
	 * persistent). If both are true, $memonly takes precedence. If both are
	 * false, the data will be stored in a file if possible, and in memory
	 * otherwise.
	 *
	 * @param $dir The directory where to store files.
	 * @param $prefix The prefix for filenames.
	 * @param $filesonly Whether only files must be used.
	 * @param $memonly Whether only memory must be used.
	 */
	public function __construct($dir, $prefix, $filesonly, $memonly = false)
	{
		$this->elements = array();
		$this->acceptMem = !$filesonly;
		$this->acceptFiles = !$memonly;
		$this->loaded = false;

		$this->dir = rtrim($dir, '/') . '/';
		$this->prefix = $prefix;
	}

	/******************
	 * Public methods *
	 ******************/

	/**
	 * Adds $value to the collection, associating it with they key $key. Gives
	 * the extension $ext to the storing file (if any). If $writeable is false,
	 * the string will not be stored in a file, only kept in memory. If
	 * $override is true, and if the $key already exists in the collection, the
	 * value will be overriden.
	 * @param $key A string key.
	 * @param $value A string to store.
	 * @param $ext The storing file extension.
	 * @param $writeable Whether this value can be written on disk.
	 * @param $override Whether to override an already existing file.
	 * @return The hash of $key, or null in case of error.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	public function addWithKey($key, $value, $ext = self::DEFAULT_EXT,
			$writeable = true, $override = false)
	{
		$h = $this->hash($key);
		return $this->addElement($h, $value, $ext, $writeable, $override) ?
				$h : null;
	}

	/**
	 * Adds $value to the collection, using $value itself as key. Gives the
	 * extension $ext to the storing file (if any). If $writeable is false, the
	 * string will not be stored in a file, only kept in memory. If $override
	 * is true, and if the $key already exists in the collection, the value
	 * will be overriden.
	 * @param $value A string to store using itself as key.
	 * @param $ext The storing file extension.
	 * @param $writeable Whether this value can be written on disk.
	 * @param $override Whether to override an already existing file.
	 * @return The hash of $value, or null in case of error.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	public function add($value, $ext = self::DEFAULT_EXT, $writeable = true,
			$override = false)
	{
		$h = $this->hash($value);
		return $this->addElement($h, $value, $ext, $writeable, $override) ?
				$h : null;
	}

	/**
	 * Checks whether the key $key exists in this collection.
	 * @param $key A string key.
	 * @return true if $key already exists, false otherwise.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	public function existsKey($key)
	{
		return $this->exists($this->hash($key));
	}

	/**
	 * Checks whether the hash $h exists in this collection.
	 * @param $h A string key hash in hexadecimal.
	 * @return true if $h already exists, false otherwise.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	public function exists($h)
	{
		$this->load();
		return array_key_exists($h, $this->elements);
	}

	/**
	 * Gets the string value indexed by the key $h.
	 * @param $key A string key.
	 * @return A string value, or null if $key does not exist.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	public function getContentFromKey($key)
	{
		return $this->getContent($this->hash($key));
	}

	/**
	 * Gets the string value indexed by the hash $h.
	 * @param $h A string key hash in hexadecimal.
	 * @return A string value, or null if $h does not exist.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	public function getContent($h)
	{
		$e = $this->getRawElement($h);
		if($e != null)
		{
			if($e[0] == self::TYPE_FILE)
				return file_get_contents($this->dir . $e[1]);
			elseif($e[0] == self::TYPE_MEM)
				return $e[1];
		}
		return null;
	}

	/**
	 * Gets the filename of the file containing the string indexed by the key
	 * $key.
	 * @param $key A string key.
	 * @return A filename, or null if the value does not exist or is not stored
	 *         in a file.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	public function getFileFromKey($key)
	{
		return $this->getFile($this->hash($key));
	}

	/**
	 * Gets the filename of the file containing the string indexed by the hash
	 * $h.
	 * @param $h A string key hash in hexadecimal.
	 * @return A filename, or null if the value does not exist or is not stored
	 *         in a file.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	public function getFile($h)
	{
		$e = $this->getRawElement($h);
		if($e != null && $e[0] == self::TYPE_FILE)
			return $this->dir . $e[1];
		return null;
	}

	/**
	 * Removes the element indexed by the key $key.
	 * @param $key A string key.
	 * @return true if the element existed and could be removed.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	public function removeFromKey($key)
	{
		return $this->remove($this->hash($key));
	}

	/**
	 * Removes the element indexed by the hash $h.
	 * @param $h A string key hash in hexadecimal.
	 * @return true if the element existed and could be removed.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	public function remove($h)
	{
		$e = $this->getRawElement($h);
		if($e == null)
			return false;
		if($e[0] == self::TYPE_FILE)
			$this->removeFile($e[1]);
		unset($this->elements[$h]);
		return true;
	}

	/**
	 * Prepends the directory of that FileManager to the filename $f, so that
	 * this file may be accessed and used by another application.
	 * @param $f A filename.
	 * @return The filename prepended by this FileManager directory.
	 */
	public function prependDir($f)
	{
		return $this->dir . $f;
	}

	/*********************
	 * Protected methods *
	 *********************/

	/**
	 * Loads already-existing files in this FileManager, by scanning its
	 * directory for matching file names (only if this FileManager accepts
	 * files). If this directory does not exist, it will be created, and if
	 * this creation fails or if the directory cannot be read and open, an
	 * exception is thrown.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	protected function load()
	{
		if($this->loaded)
			return;
		if($this->acceptFiles)
		{
			if((is_dir($this->dir) || mkdir($this->dir, 0700, true)) &&
				$this->prefix != null && is_writable($this->dir) &&
				$dh = opendir($this->dir))
			{
				$pattern = "/^".$this->prefix."_([a-f0-9]+)\.\w+$/i";
				$matches = array();
				while(($file = readdir($dh)) !== false)
					if(preg_match($pattern, $file, $matches))
						$this->elements[strtolower($matches[1])] = array(
							self::TYPE_FILE, $file);
			}
			elseif(!$this->acceptMem)
				throw new Exception("The directory " . $this->dir .
					" does not exist and cannot be created.");
			else
				$this->acceptFiles = false;
		}
		$this->loaded = true;
	}

	/**
	 * Gets the internal raw element indexed by the key $key.
	 * @see $this->getRawElement($h)
	 * @param $key A string key.
	 * @return An array, or null if the key $key does not exist.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	protected function getRawElementFromKey($key)
	{
		return $this->getRawElement($this->hash($key));
	}

	/**
	 * Gets the internal raw element indexed by the hash $h. It is an array
	 * of 3 items:
	 *  * The 0th contains self::TYPE_FILE if the element is stored in a file,
	 *    self::TYPE_MEM otherwise;
	 *  * The 1st contains the extension of the file (even for a
	 *    memory-stored element);
	 *  * The 2nd contains the name of the file storing the string, or the
	 *    string itself if the element is memory-stored.
	 * @param $h A string key hash in hexadecimal.
	 * @return An array, or null if the hash $h does not exist.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	protected function getRawElement($h)
	{
		$this->load();
		if(array_key_exists($h, $this->elements))
			return $this->elements[$h];
		return null;
	}

	/**
	 * If overriden in an extended class, performs an operation on $value
	 * before it is saved to a file.
	 * @param $value A string value that will be stored to a file.
	 * @return The transformed value (by default, same as $value).
	 */
	protected function processForFile($value)
	{
		return $value;
	}

	/**
	 * If overriden in an extended class, performs an operation on $value
	 * before it is saved to memory.
	 * @param $value A string value that will be stored in memory.
	 * @return The transformed value (by default, same as $value).
	 */
	protected function processForMem($value)
	{
		return $value;
	}

	/**
	 * Computes the name of the file whose key hash is $h and extension $ext.
	 * @param $h The value key hash.
	 * @param $ext The value extension.
	 * @return The value filename.
	 */
	protected function filename($h, $ext)
	{
		return $this->prefix . "_" . $h . "." . $ext;
	}

	/**
	 * Computes the hash of $k (by default, SHA-1) in hexadecimal.
	 * @param $k A string.
	 * @return A hash as an hexadecimal string.
	 */
	protected function hash($k)
	{
		return sha1($k, false);
	}

	/**
	 * Adds the string $v, indexed by the hash $h, to the collection. Tries to
	 * save it to a file (if possible, and if $writeable is true) with the
	 * extension $ext, or keeps it in memory if it fails and if the collection
	 * is not file-only. If $h already exists in the collection, the associated
	 * value will be replaced if $override is true.
	 * @param $h A string key hash in hexadecimal.
	 * @param $v A string value.
	 * @param $ext A file extension.
	 * @param $writeable Whether the file can be written on disk.
	 * @param $override Whether to override an already existing file.
	 * @return true if the element was correctly added or already exists, and
	 *         false otherwise.
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	protected function addElement($h, $v, $ext, $writeable, $override)
	{
		$this->load();
		$fileexists = array_key_exists($h, $this->elements);
		if(!$override && $fileexists)
			return true;

		if($writeable && $this->acceptFiles)
		{
			$filename = $this->filename($h, $ext);
			if($this->saveFile($filename, $v))
			{
				if($fileexists && $this->elements[$h][1] != $filename)
					$this->removeFile($this->elements[$h][1]);
				$this->elements[$h] = array(self::TYPE_FILE, $filename);
				return true;
			}
		}
		if($this->acceptMem)
		{
			$this->elements[$h] = array(self::TYPE_MEM,
				$this->processForMem($v));
			return true;
		}
		return false;
	}

	/**
	 * Performs the actual writing of the string $content to the file $f.
	 * @param $filename An element filename.
	 * @param $content A string to write.
	 * @return true in case of success, or false otherwise.
	 */
	protected function saveFile($filename, $content)
	{
		$f = fopen($this->dir . $filename, "wb");
		if($f)
		{
			if(fwrite($f, $this->processForFile($content)))
			{
				fclose($f);
				return true;
			}
			fclose($f);
		}
		return false;
	}

	/**
	 * Deletes (if possible) the file $f of an element.
	 * @param $filename An element filename.
	 * @return true in case of success, false otherwise.
	 */
	protected function removeFile($filename)
	{
		return @unlink($this->dir . $filename);
	}
}

?>