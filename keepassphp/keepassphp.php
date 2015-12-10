<?php

/*
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */

/*
 * here we include everything, we could use an autoload in the future but
 * the fact is that from the moment we want to decrypt a KeePass database,
 * we do need almost everything, so there is not much difference. The important
 * point is to include keepassphp.php in client applications only when we are
 * sure we will try to add or get a database file.
 */

/*
 * Not directly KeePass-related stuff (helpers, tools, etc)
 */
require_once "util/binary.php";
require_once "util/cipher.php";
require_once "util/filemanager.php";
require_once "util/gzdecode2.php";
require_once "util/hash.php";
require_once "util/reader.php";
require_once "util/streamcipher.php";
require_once "util/salsa20cipher.php";
require_once "util/uploadmanager.php";
require_once "util/xmlstackreader.php";

/*
 * KeePass-related stuff
 */
require_once "keepass/iconrepository.php";
require_once "keepass/database.php";
require_once "keepass/header.php";
require_once "keepass/key.php";
require_once "keepass/kdbximporter.php";

/**
 * Main class of the KeePassPHP application.
 * Loads and adds databases, check and exploit results. Every kind of
 * interaction with KeePassPHP by a client application should be done through
 * this class, and through the objets yielded by this class (mainly Database
 * objects).
 */
abstract class KeePassPHP
{
	static public $errordump;
	static public $isError;
	static public $iconmanager;
	static public $debug;
	
	static private $started = false;

	static private $dbmanager;
	static private $kdbxmanager;
	static private $keymanager;
	
	const DEFAULT_HASH = "sha256";
	
	const EXT_KPHPDB = "kphpdb";
	const PREFIX_ICON = "icon";
	const PREFIX_DATABASE = "db";
	const PREFEXT_KEY = "key";
	const PREFEXT_KDBX = "kdbx";

	const DIR_DATA = "data/";
	const DIR_ICONS = "icons/";
	const DIR_SECURE = "secure/";
	const DIR_KDBX = "kdbx/";
	const DIR_KPHPDB = "kphpdb/";
	const DIR_KEY = "key/";

	const IV_SIZE = 32;
	const DBTYPE_KDBX = 1;
	const KEY_PWD = 1;
	const KEY_FILE = 2;

	const IDX_DBTYPE = 0;
	const IDX_HASHNAME = 1;
	const IDX_KEYS = 2;
	const IDX_WRITEABLE = 3;
	const IDX_ENTRIES = 4;
	const IDX_COUNT = 5;

	/**
	 * Starts the KeePassPHP application. Must be called before any other method
	 * of KeePassPHP. If $debug is true, debug and error data will be added in
	 * the static variable KeePassPHP::$errordump; if $debug is false,
	 * KeePass::$errordump will be non empty only if an error occurs.
	 * Regardless of the value of $debug, the property KeePassPHP::$isError is
	 * set to true if an error occurs. This way, a client application can check
	 * if KeePassPHP detected an error, and retrieve some information from
	 * KeePassPHP::$errordump (this information will probably not be useful
	 * if $debug is false, though).
	 *
	 * @param string $keepassphpDir The relative path to the KeePassPHP
	 *                              directory from the working directory.
	 * @param boolean $debug True to enable debug mode, false otherwise.
	 */
	public static function init($keepassphpDir, $debug = false)
	{
		if(self::$started)
			return;
		
		self::$isError = false;
		self::$debug = $debug;
		self::$errordump = "";

		if(!extension_loaded("hash"))
		{
			self::raiseError("hash must be loaded to use KeePassPHP");
			return;
		}
		if(!extension_loaded("mcrypt"))
		{
			self::raiseError("mcrypt must be loaded to use KeePassPHP");
			return;
		}
		if(!defined("MCRYPT_RIJNDAEL_128"))
		{
			self::raiseError("Rijndael 128 is not supported by your libmcrypt (it is probably too old)");
			return;
		}

		$keepassphpDir = trim($keepassphpDir, '/') . '/';
		HashHouse::setDefault(self::DEFAULT_HASH);
		self::$iconmanager = new IconManager($keepassphpDir .
			self::DIR_DATA . self::DIR_ICONS, self::PREFIX_ICON, false, false);
		self::$dbmanager = new FileManager($keepassphpDir .
			self::DIR_DATA . self::DIR_SECURE . self::DIR_KPHPDB,
			self::PREFIX_DATABASE, true, false);
		self::$kdbxmanager = new UploadManager($keepassphpDir .
			self::DIR_DATA.self::DIR_SECURE.self::DIR_KDBX, self::PREFEXT_KDBX);
		self::$keymanager = new UploadManager($keepassphpDir .
			self::DIR_DATA.self::DIR_SECURE.self::DIR_KEY, self::PREFEXT_KEY);

		self::$started = true;
		self::printDebug("KeePassPHP application started!");
	}

	/****************************
	 * Debug and error handling *
	 ****************************/

	/**
	 * Sets self::$isError to true, and adds the given error message $msg to
	 * the error dump if debug mode is enabled.
	 * @param string $msg The error message.
	 */
	public static function raiseError($msg)
	{
		self::$isError = true;
		self::$errordump .= "An unexpected error occured" . (self::$debug ?
			": " . self::makePrintable($msg) : ". That's all we know.") . "\n";
		//die();
	}

	/**
	 * Adds the given string to the debug data if debug mode is on.
	 * @param string $msg The string to add to the debug data.
	 */
	public static function printDebug($msg)
	{
		if(self::$debug)
			self::$errordump .= self::makePrintable($msg) . "\n";
	}

	/**
	 * Adds the given debug string $msg, then the given binary string $bin as an
	 * hex string, to the debug data if debug mode is on.
	 * @param string $msg The 'normal' string to add to the debug data.
	 * @param string $bin The binary string to print in hexa.
	 */
	public static function printDebugHexa($msg, $bin)
	{
		if(self::$debug)
			self::$errordump .= self::makePrintable($msg . " :: " .
				Binary::fromString($bin)->asHexString()) . "\n";
	}

	/**
	 * Adds the given debug string $msg, then the given array $array (with
	 * print_r), to the debug data if debug mode is on.
	 * @param string $msg The string to add to the debug data.
	 * @param array $array The array to add to the debug data.
	 */
	public static function printDebugArray($msg, $array)
	{
		if(self::$debug)
		{
			ob_start();
			print_r($array);
			self::$errordump .= self::makePrintable($msg . " :: " .
					ob_get_contents()) . "\n";
			ob_end_clean();
		}
	}

	/**
	 * Returns the string in a html-printable format : encoded in UTF8, and with
	 * some special chars rightly encoded. Every piece of data printed in a web
	 * page and coming from KeePassPHP (either a password, an username, or a
	 * debug stuff, *anything*) should be 'protected' by this method.
	 * @param string $s The string to make html-printable.
	 * @return string A sanitized string.
	 */
	public static function makePrintable($s)
	{
		return htmlspecialchars(utf8_encode($s), ENT_QUOTES, 'UTF-8');
	}

	/***********************************
	 * Databases access and management *
	 ***********************************/

	/**
	 * Tries to get the KeePass database corresponding the the ID $dbid, whose
	 * internal password is $internalpwd and master password is $keypwd.
	 * $internalpwd is the password needed to decrypt the KeePassPHP's internal
	 * database, which contains the name of the KeePass database file, and the
	 * possible key files which are already kept by KeePassPHP ; and $keypwd is
	 * the textual password needed to decrypt the KeePass database file. They
	 * may be the same (this is even recommended for the sake of simplicity).
	 * Note that this method does not usually try to decrypt the KeePass
	 * database file (only the KeePassPHP internal database), except if the
	 * internal database does not contain information about the entries of the
	 * KeePass database, which should happen only the very first time it is get
	 * (and the corresponding data is then stored in the internal database).
	 * @param string $dbid The ID of the database.
	 * @param string $internalpwd The internal password, needed to decrypt the
	 * KeePassPHP internal database.
	 * @param string $keypwd The master password, needed to decrypt the KeePass
	 * database file.
	 * @return null|\KdbxImporter Returns a Databse object able to read the
	 * KeePass database, or null if something went wrong.
	 */
	public static function get($dbid, $internalpwd, $keypwd)
	{
		if(!self::$started)
		{
			self::raiseError("KeepassPHP is not started!");
			return null;
		}

		$bindb = self::$dbmanager->getContentFromKey($dbid);
		if($bindb == null)
		{
			self::printDebug("Database not found or void (ID=".$dbid.")");
			return null;
		}
		$db = self::decryptUnserialize($bindb, $internalpwd);
		if($db == false || !is_array($db) || count($db) < self::IDX_COUNT)
		{
			self::printDebug("Bad format, or wrong password (ID=".$dbid.")");
			return null;
		}
		if($db[self::IDX_DBTYPE] != self::DBTYPE_KDBX)
		{
			self::printDebug("Types other than kbdx not yet supprted (ID=".$dbid.")");
			return null;
		}

		$ckey = new CompositeKey();
		$i = 0;
		foreach($db[self::IDX_KEYS] as $rk)
		{
			if($rk[0] == self::KEY_PWD)
			{
				if($i == 0)
					$ckey->addKey(new KeyFromPassword(utf8_encode($keypwd)));
				else
				{
					self::raiseError("Having more than one textual password" .
						" is not yet possible (ID=".$dbid.")");
					return null;
				}
				$i++;
			}
			elseif($rk[0] == self::KEY_FILE)
			{
				$filekey = new KeyFromFile(self::$keymanager->getFile($rk[1]));
				if(!$filekey->isParsed)
				{
					self::raiseError("Key file parsing failure (ID=".$dbid.")");
					return null;
				}
				$ckey->addKey($filekey);
			}
		}

		$kdbx = new KdbxImporter(
			self::$kdbxmanager->getFile($db[self::IDX_HASHNAME]), $ckey);

		$entries = $db[self::IDX_ENTRIES];
		if(!is_array($entries) || count($entries) == 0)
		{
			if($kdbx->tryLoad())
			{
				$entries = $kdbx->parseEntries();
				self::addInternal($dbid, $internalpwd, $db[self::IDX_HASHNAME],
					$db[self::IDX_KEYS], $entries, $db[self::IDX_WRITEABLE]);
				$kdbx->useEntries($entries);
			}
			else
				self::printDebug("Trying to go on with no entries... (ID=".$dbid.")");
		}
		else
			$kdbx->useEntries($entries);

		return $kdbx;
	}

	/**
	 * Tries to add the database $kdbxfile to KeePassPHP, using the ID $dbid,
	 * the internal password $internalpwd, and the master key composed of the
	 * keys $keys. If the ID already exists, the corresponding database will
	 * be overriden.
	 * $kdbxfile should be the temporary filename of the file, as just uploaded
	 * by PHP. KeePassPHP will perform itself move_uploaded_file. Likewise, the
	 * key filenames in $keys should be the temporary filenames as just uploaded
	 * by PHP, and will be moved by KeePassPHP.
	 * The internal password is used to encrypt the internal data kept by
	 * KeePassPHP, whereas the passwords in $keys are used to build the master
	 * key to decrypt the KeePass database file. The internal password may be
	 * part of the master key (this is even recommended for the sake of
	 * simplicity).
	 * @param string $kdbxfile The temporary filename of the KeePass database.
	 * @param string $dbid The ID to use.
	 * @param string $internalpwd The internal password.
	 * @param array $keys The keys composing the master key of the database.
	 * @return boolean Returns true in case of success, false otherwise.
	 */
	public static function tryAdd($kdbxfile, $dbid, $internalpwd, array $keys)
	{
		if(!self::$started)
		{
			self::raiseError("KeepassPHP is not started!");
			return false;
		}

		$nkeys = array();
		foreach($keys as $k)
		{
			if($k[0] == self::KEY_PWD)
				$nkeys[] = array(self::KEY_PWD);
			elseif($k[0] == self::KEY_FILE)
			{
				$h = KeePassPHP::addKeyFile($k[1]);
				if($h == null)
				{
					self::raiseError("Key file upload failed.");
					return false;
				}
				$nkeys[] = array(KeePassPHP::KEY_FILE, $h);
			}
		}
		$hashname = KeePassPHP::addKdbxFile($kdbxfile);
		if($hashname == null)
		{
			self::raiseError("Database file upload failed.");
			return false;
		}
		if(KeePassPHP::addInternal($dbid, $internalpwd, $hashname, $nkeys,
				array(), true) == null)
		{
			self::raiseError("Internal database write failed.");
			return false;
		}
		return true;
	}

	/**
	 * Returns true if the ID $dbid already exists in KeePassPHP internal
	 * database.
	 * @param string $dbid The ID to check.
	 * @return boolean Returns true if the given ID already exists, false
	 * otherwise.
	 */
	public static function exists($dbid)
	{
		if(!self::$started)
		{
			self::raiseError("KeepassPHP is not started!");
			return false;
		}
		return self::$dbmanager->existsKey($dbid);
	}

	/**
	 * Checks whether the given password $internalpwd can decrypt the KeePassPHP
	 * internal database data corresponding to the ID $dbid. This method does
	 * not try to decrypt the KeePass database file, it only deals with
	 * KeePassPHP internal data.
	 * @param string $dbid The ID of the data to test.
	 * @param string $internalpwd The password to decrypt the internal database
	 * data corresponding to the given ID.
	 * @return boolean Returns true if the decryption was successful, and false
	 * otherwise.
	 */
	public static function checkPassword($dbid, $internalpwd)
	{
		if(!self::$started)
		{
			self::raiseError("KeepassPHP is not started!");
			return false;
		}
		$bindb = self::$dbmanager->getContentFromKey($dbid);
		$result = self::decryptUnserialize($bindb, $internalpwd);
		return $result !== false;
	}

	/**
	 * Checks whether the master key composed of the keys $keys can decrypt the
	 * KeePass file $file. This functions actually tries to perform the
	 * decryption of the KeePass database, and can thus be computationally
	 * intensive. It is the only one that can check whether keys for a KeePass
	 * database file are good or not.
	 * @param string $file The filename of the KeePass database file to check.
	 * @param array $keys The keys composing the master key of the database.
	 * @return boolean Returns true if the decryption was successful, and false
	 * otherwise.
	 */
	public static function checkKeys($file, array $keys)
	{
		$ckey = new CompositeKey();
		foreach($keys as $k)
		{
			if($k[0] == self::KEY_PWD)
				$ckey->addKey(new KeyFromPassword(utf8_encode($k[1])));
			elseif($k[0] == self::KEY_FILE)
			{
				$filekey = new KeyFromFile($k[1]);
				if(!$filekey->isParsed)
				{
					self::raiseError("Key file parsing failure in checkKeys");
					return false;
				}
				$ckey->addKey($filekey);
			}
		}
		$kdbx = new KdbxImporter($file, $ckey);
		return $kdbx->tryLoad();
	}

	/**************************
	 * Specific add functions *
	 **************************
	 * These functions may be made private, but it might serve some specific
	 * client application to be able to use them. Do not try to do so if you
	 * are not sure of what you're doing, though.
	 */

	/**
	 * Adds the uploaded file $file to the repository of KeePass database files.
	 * @param string $file The temporary filename of the KeePass database file
	 * to add (as just uploaded by PHP).
	 * @return string|null Returns null if something went wrong, and the name
	 * of the resulting file otherwise.
	 */
	public static function addKdbxFile($file)
	{
		return self::$kdbxmanager->add($file, self::PREFEXT_KDBX, true, true);
	}

	/**
	 * Adds the key file $file to the repository of key files.
	 * @param string $file The temporary filename of the key file to add (just
	 * as uploaded by PHP).
	 * @return string|null Returns null if something went wrong, and the name of
	 * the resulting file otherwise.
	 */
	public static function addKeyFile($file)
	{
		return self::$keymanager->add($file, self::PREFEXT_KEY, true, true);
	}

	/**
	 * Stores internally the given data of a KeePass database file with the
	 * index $dbid, to make it possible to find it later from that same index.
	 * This methods basically packs all together in an array $hashname (the
	 * filename of the actual KeePass database file), $keys (the description of
	 * the master key: what kinds of keys compose it, in which order, and for
	 * the key from files, the filenames of these files), $entries (the list of
	 * entries of the database, without the passwords ; they are written only if
	 * $writable is true) and $writeable, then serialize it and encrypts it with
	 * the password $internalpwd, and stores the result in a kphpdb file.
	 * If the index $dbid already exists, the corresponding data will be
	 * overriden.
	 * @param string $dbid The ID to use.
	 * @param string $internalpwd The internal password to encrypt the data in
	 * the KeePassPHP internal database with.
	 * @param string $hashname The filename of the KeePass database file.
	 * @param array $keys The type of keys composing the master key, with the
	 * filenames in the case of key files.
	 * @param array $entries The entries of the database to store.
	 * @param boolean $writeable Whether the entries can be written or not (if
	 * not, they will be loaded from the KeePass database file each time).
	 * @return string|null Returns null if something went wrong, and the name
	 * of the kphpdb file created otherwise.
	 */
	public static function addInternal($dbid, $internalpwd, $hashname,
			array $keys, array $entries, $writeable)
	{
		$db = array(
			self::IDX_DBTYPE => self::DBTYPE_KDBX,
			self::IDX_HASHNAME => $hashname,
			self::IDX_KEYS => $keys,
			self::IDX_ENTRIES => $writeable ? $entries : null,
			self::IDX_WRITEABLE => $writeable
		);

		$plaindb = serialize($db);
		$key = hash('SHA256', $internalpwd, true);
		$cipher = new CipherMcrypt(MCRYPT_RIJNDAEL_256, 'cfb', $key, null,
			CipherMcrypt::PK7_PADDING);
		$cipher->load();
		$iv = $cipher->getIV();
		if(strlen($iv) != self::IV_SIZE)
		{
			self::raiseError("Unexpected size of IV : " . strlen($iv));
			$cipher->unload();
			return null;
		}
		$bindb = $iv . $cipher->encrypt($plaindb);
		$cipher->unload();

		return self::$dbmanager->addWithKey($dbid, $bindb, self::EXT_KPHPDB,
			true, true);
	}

	/*********************
	 * private functions *
	 *********************/

	/**
	 * Decrypts and unserialize the given binary string, assumed to be a result
	 * of the addInternal method (i.e the content of a kphpdb file). Returns the
	 * result (an array), or false if something went wrong (bad password, bad
	 * binary string).
	 * @param string $bin The binary string to decrypt and unserialize.
	 * @param string $pwd The internal password to use as key.
	 * @return boolean|array Returns false if something went wrong, an array
	 * with the decrypted and unserialized data otherwise.
	 */
	private static function decryptUnserialize($bin, $pwd)
	{
		if($bin == null || strlen($bin) < self::IV_SIZE)
			return false;
		$iv = substr($bin, 0, self::IV_SIZE);
		$key = hash('SHA256', $pwd, true);
		$cipher = new CipherMcrypt(MCRYPT_RIJNDAEL_256, 'cfb', $key, $iv,
			CipherMcrypt::PK7_PADDING);
		$plain = $cipher->decrypt(substr($bin, self::IV_SIZE));
		$cipher->unload();
		return @unserialize($plain);
	}
}

?>