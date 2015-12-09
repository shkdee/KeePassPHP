<?php

/**
 * An extensions of FileManager wich deals with files uploaded via a PHP form.
 * Binary strings are replaced by temporary filenames of uploaded files (the one
 * given by $_FILE['field_name']['tmp_name']), and thus adding a value means
 * moving the uploaded file from the temporary directory to its new directory,
 * and renaming with the convention used by the FileManager. If no key is
 * specified when a file is added, the sha1 of the file (and not of its name)
 * is computed instead. Nothing else changes from a FileManager. An
 * UploadManager is obviously file-only.
 *
 * Note that no check on the given temporary file names is performed, and is
 * the responsability of the client of that class.
 *
 * @author Louis
 */
class UploadManager extends FileManager
{
	/**
	 * Builds a new UploadManager storing files in the directory $dir, and
	 * using the prefix $prefix for filenames.
	 * @param string $dir
	 * @param string $prefix
	 */
	public function __construct($dir, $prefix)
	{
		parent::__construct($dir, $prefix, true, false);
	}

	/**
	 * Adds the uploaded file whose temporary name is $value to the collection,
	 * using the hash of the file itself as key (so retrieving that file will be
	 * able only with that hash). Gives the extension $ext to the new file.
	 * If $writeable is false, nothing will be done (this is a file-only
	 * collection), and if $override is true, if the given file already exists
	 * in the collection, it will be overriden.
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
		$h = sha1_file($value);
		return $this->addElement($h, $value, $ext, $writeable, $override) ?
				$h : null;
	}

	/**
	 * Moves the given temporary file $v to its new location, defined by the
	 * hash $h and the extension $ext. If $writeable is false, nothing is done
	 * (this is a file-only collection) and if $override is true, if the given
	 * hash already exists, the corresponding file will be overriden.
	 * Returns true if the file was successfully added to the collection or if
	 * it already existed, and false otherwise (if no file corresponding to the
	 * hash $h exists).
	 * @param string $h
	 * @param string $v
	 * @param string $ext
	 * @param boolean $writeable
	 * @param boolean $override
	 * @return boolean
	 */
	protected function addElement($h, $v, $ext, $writeable, $override)
	{
		$this->load();
		$fileexists = array_key_exists($h, $this->elements);
		if((!$override && $fileexists))
			return true;
		 if(!$writeable || !$this->acceptFiles)
			 return false;
		 
		if(!@move_uploaded_file($v, $this->dir . $this->filename($h, $ext)))
			return false;

		$oldext = $fileexists ? $this->elements[$h][1] : $ext;
		if($oldext != $ext)
			$this->remove($h, $oldext);
		$this->elements[$h] = array(self::TYPE_FILE, $ext, $this->filename($h, $ext));
		return true;
	}
}

?>