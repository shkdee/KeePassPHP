<?php

namespace KeePassPHP;

/**
 * An extensions of FileManager wich deals with files uploaded via a PHP form.
 * Binary strings are replaced by temporary filenames of uploaded files (the
 * one given by $_FILE['field_name']['tmp_name']), and thus adding a value
 * means moving the uploaded file from the temporary directory to its new
 * directory, and renaming with the convention used by the FileManager. If no
 * key is specified when a file is added, the sha1 of the file (and not of its
 * name) is computed instead. Nothing else changes from a FileManager. An
 * UploadManager instance is obviously file-only.
 *
 * Note that no check on the given temporary file names is performed, and is
 * the responsability of the client of that class.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class UploadManager extends FileManager
{
	/**
	 * Builds a new UploadManager storing files in the directory $dir, and
	 * using the prefix $prefix for filenames.
	 * @param $dir A directory path.
	 * @param $prefix A filename prefix.
	 */
	public function __construct($dir, $prefix)
	{
		parent::__construct($dir, $prefix, true, false);
	}

	/**
	 * Adds the uploaded file whose temporary name is $value to the collection,
	 * using the hash of the file itself as key (so retrieving that file will
	 * be possible only with that hash). Gives the extension $ext to the new
	 * file. If $writeable is false, nothing will be done (this is a file-only
	 * collection), and if $override is true, if the given file already exists
	 * in the collection, it will be overriden.
	 * @param $value An uploaded file temporary path.
	 * @param $ext The final file extension.
	 * @param $writeable Whether this file can be written on disk.
	 * @param $override Whether to override an already existing file.
	 * @return The hash of the file, or null in case of error.
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
	 * (this is a file-only collection) and if $override is true, the
	 * corresponding file will be overriden if it already exists.
	 * @param $h The file hash.
	 * @param $v The uploaded file temporary path.
	 * @param $ext The final file extension.
	 * @param $writeable Whether the file can be written on disk.
	 * @param $override Whether to override an already existing file.
	 * @return true if the file was successfully added to the collection or if
	 *         it already exists, and false otherwise (if no file corresponding
	 *         to the hash $h exists).
	 * @throws Exception If this FileManager directory is not accessible.
	 */
	protected function addElement($h, $v, $ext, $writeable, $override)
	{
		$this->load();
		$fileexists = array_key_exists($h, $this->elements);
		if((!$override && $fileexists))
			return true;
		 if(!$writeable || !$this->acceptFiles)
			 return false;
		 
		$filename = $this->filename($h, $ext);
		if(!@move_uploaded_file($v, $this->dir . $filename))
			return false;

		if($fileexists && $this->elements[$h][1] != $filename)
			$this->removeFile($this->elements[$h][1]);
		$this->elements[$h] = array(self::TYPE_FILE, $filename);
		return true;
	}
}

?>