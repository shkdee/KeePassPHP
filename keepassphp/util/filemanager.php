<?php

/**
 * Keeps a (possibly) persitent collection of binary strings, indexed by hashs
 * (by default, SHA-1) of these strings, or of given keys. Tries to write these
 * strings as files with filenames formatted as prefix_sha1.ext in a chosen
 * directory, unless required not to write them (in that case, it will only
 * keep the strings in memory ; but non-written-to-disk data is non-persistent).
 * Can be required to work with files only, or with no files at all, and each
 * file can be required to be non disk-writable.
 * That class is meant to be extended to better match other, specific purposes,
 * so everything is protected and not private.
 *
 * @author Louis
 */
class FileManager
{
    protected $prefix;
    protected $elements;
    protected $dir;
    protected $acceptFiles;
    protected $acceptMem;

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
	 * If files are allowed, the directory $dir will be scanned to try and
	 * retrieve existing data ; if it does not exist, it will be created, and
	 * if this creation fails, or if the directory cannot be read and open, and
	 * $filesonly is true (and $memonly is false), an exception will be thrown.
	 *
	 * @param string $dir The directory to use to store files.
	 * @param string $prefix The prefix for filenames.
	 * @param boolean $filesonly Whether only files must be used.
	 * @param boolean $memonly Whether only memory must be used.
	 * @throws Exception
	 */
    public function __construct($dir, $prefix, $filesonly, $memonly = false)
    {
        $this->elements = array();
        $this->acceptMem = !$filesonly;

		if(!$memonly)
		{
			if((is_dir($dir) || mkdir($dir, 700, true)) && $prefix != null &&
					is_writable($dir) && $dh = opendir($dir))
			{
				$this->dir = $dir . (substr($dir, -1) == "/" ? "" : "/");
				$this->prefix = $prefix;
				$this->acceptFiles = true;

				$pattern = "/^".$this->prefix."_([a-f0-9]+)\.(\w+)$/i";
				$matches = array();
				while(($file = readdir($dh)) !== false)
					if(preg_match($pattern, $file, $matches))
	                    $this->elements[strtolower($matches[1])] = array(
							self::TYPE_FILE, strtolower($matches[2]), $file);
			}
			elseif($filesonly)
				throw new Exception("The directory " . $dir .
					" does not exist and cannot be created.");
			else
				$this->acceptFiles = false;
		}
		else
			$this->acceptFiles = false;
    }

    /******************
     * Public methods *
     ******************/

    /**
     * Adds the new binary string $value to the collection, using $key to identify
     * it (so retrieving it will be able either with $key, or with the used hash
     * of $key (SHA1 by default)). Gives the extension $ext to the storing file
     * (if any). If $writeable is false, the string will not be stored in a file,
     * but only in memory. If $override is true, and if the given key already
     * exists in the collection, the value will be overriden.
     * Returns the used hash, or null in case of error.
     * @param string $key
     * @param string $value
     * @param string $ext
     * @param boolean $writeable
     * @param boolean $override
     * @return string|null
     */
    public function addWithKey($key, $value, $ext = self::DEFAULT_EXT,
            $writeable = true, $override = false)
    {
        $h = $this->hash($key);
        return $this->addElement($h, $value, $ext, $writeable, $override) ?
                $h : null;
    }

    /**
     * Adds the new binary string $value to the collection, using the hash of itself
     * (SHA1 by default) as a key (so retrieving the value will be able only with
     * that hash). Gives the extension $ext to the storing file (if any). If
     * $writeable is false, the string will not be stored in a file, but only in
     * memory. If $override is true, and if the given key already exists in the
     * collection, the value will be overriden.
     * Returns the used hash, or null in case of error.
     * @param string $value
     * @param string $ext
     * @param boolean $writeable
     * @param boolean $override
     * @return string|null
     */
    public function add($value, $ext = self::DEFAULT_EXT, $writeable = true,
            $override = false)
    {
        $h = $this->hash($value);
        return $this->addElement($h, $value, $ext, $writeable, $override) ?
                $h : null;
    }

    /**
     * Returns true if the key $key already exists in the collection (which is
     * to say, if the hash of $key already exists).
     * @param string $key
     * @return boolean
     */
    public function existsKey($key)
    {
        return $this->exists($this->hash($key));
    }

    /**
     * Returns true if the hash $h already exists in the collection.
     * @param string $h
     * @return boolean
     */
    public function exists($h)
    {
        return array_key_exists($h, $this->elements);
    }

    /**
     * Returns the internal raw element indexed by the key $key (i.e by the hash
     * of $key), or null if $key does not exist.
     * @see $this->getRawElement($h)
     * @param string $key
     * @return array|null
     */
    public function getRawElementFromKey($key)
    {
        return $this->getRawElement($this->hash($key));
    }

    /**
     * Returns the internal raw element indexed by the hash $h. It is an array
     * of 3 elements : the first contains self::TYPE_FILE if the element is
     * stored in a file, self::TYPE_MEM otherwise ; the second contains the given
     * extension of the file (even for a memory-stored element) ; the third
     * contains the name of the file storing the binary string, or the binary
     * string itself if the element is memory-stored.
     * Returns null if the hash $h does not exist.
     * @param type $h
     * @return array|null
     */
    public function getRawElement($h)
    {
        if(array_key_exists($h, $this->elements))
            return $this->elements[$h];
        return null;
    }

    /**
     * Returns the binary string indexed by the hash of the key $key, or null if
     * $key does not exist.
     * @param string $key
     * @return string
     */
    public function getContentFromKey($key)
    {
        return $this->getContent($this->hash($key));
    }

    /**
     * Returns the binary string indexed by the hash $h, or null if $h does not
     * exist.
     * @param string $h
     * @return string|null
     */
    public function getContent($h)
    {
        $e = $this->getRawElement($h);
        if($e != null)
        {
            if($e[0] == self::TYPE_FILE)
                return file_get_contents($this->dir . $e[2]);
            elseif($e[0] == self::TYPE_MEM)
                return $e[2];
        }
        return null;
    }

    /**
     * Returns the filename of the file containing the binary string indexed by
     * the hash of the key $key, or null if $key does not exist, or if the
     * corresponding element is not stored with a file.
     * @param string $key
     * @return string|null
     */
    public function getFileFromKey($key)
    {
        return $this->getFile($this->hash($key));
    }

    /**
     * Returns the filename of the file containing the binary string indexed by
     * the hash $h, or null if $h does not exist, or if the corresponding
     * element is not stored with a file.
     * @param string $h
     * @return string|null
     */
    public function getFile($h)
    {
        $e = $this->getRawElement($h);
        if($e != null && $e[0] == self::TYPE_FILE)
            return $this->dir . $e[2];
        return null;
    }

    /**
     * Prepends the directory of that FileManager to the filename $f, so that
     * file may be accessed and used by another application.
     * @param string $f
     * @return string
     */
    public function prependDir($f)
    {
        return $this->dir . $f;
    }

    /*********************
     * Protected methods *
     *********************/

    /**
     * If overriden in an extended class, performs an operation on the binary
     * string $value before it is saved to a file.
     * @param string $value
     * @return string
     */
    protected function processForFile($value)
    {
        return $value;
    }

    /**
     * If overriden in an extended class, performs an operation on the binary
     * string $value before it is saved to memory.
     * @param string $value
     * @return string
     */
    protected function processForMem($value)
    {
        return $value;
    }

    /**
     * Returns the name of the file which is storing the binary string indexed
     * by the hash $h, which has the extension $ext.
     * @param string $h
     * @param string $ext
     * @return string
     */
    protected function filename($h, $ext)
    {
        return $this->prefix . "_" . $h . "." . $ext;
    }

    /**
     * Returns the hash $k (a binary string, or a key). The default hash
     * alrogithm is SHA1.
     * @param string $k
     * @return string
     */
    protected function hash($k)
    {
        return sha1($k);
    }

    /**
     * Adds the binary string $v, indexed by the hash $h, to the collection.
     * Tries to save it to a file (if possible, and if $writeable is true) with
     * the extension $ext, or keeps it in memory if it fails and if the
     * collection is not file-only. If the hash $h already exists in the
     * collection, the associated value will be replaced if $override is true.
     * Returns true if the element was added or already exists, and false
     * otherwise.
     * @param string $h
     * @param string $v
     * @param string $ext
     * @param boolean $writeable
     * @param boolean $override
     * @return boolean
     */
    protected function addElement($h, $v, $ext, $writeable, $override)
    {
        $fileexists = array_key_exists($h, $this->elements);
        if(!$override && $fileexists)
            return true;

        if($writeable && $this->acceptFiles)
            if($this->save($h, $v, $ext))
            {
                $oldext = $fileexists ? $this->elements[$h][1] : $ext;
                if($oldext != $ext)
                    $this->remove($h, $oldext);
                $this->elements[$h] = array(self::TYPE_FILE, $ext,
                    $this->filename($h, $ext));
                return true;
            }
        if($this->acceptMem)
        {
            $this->elements[$h] = array(self::TYPE_MEM, $ext,
                $this->processForMem($v));
            return true;
        }
        return false;
    }

    /**
     * Performs the actual saving of the binary string $content to the file
     * defined by the hash $h and the extension $ext. Returns true in case of
     * success, or false otherwise.
     * @param string $h
     * @param string $content
     * @param string $ext
     * @return boolean
     */
    protected function save($h, $content, $ext)
    {
        $f = fopen($this->dir . $this->filename($h, $ext), "wb");
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
     * Deletes (if possible) the file defined by the hash $h and the extension
     * $ext.
     * @param string $h
     * @param string $ext
     * @return boolean
     */
    protected function remove($h, $ext)
    {
        return @unlink($this->dir . $this->filename($h, $ext));
    }
}

?>
