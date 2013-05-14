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

/**
 * Main class of the KeePassPHP application.
 * Calls all the other classes, loads and adds databases, check and exploit
 * results. Every creation of a database by the "client" application (e.g which
 * is charge of printing the results in a web page) should be done through that
 * class, as well as most of static calls.
 * 
 * @author Louis Traynard
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

require_once "keepass/iconrepository.php";
require_once "keepass/database.php";
require_once "keepass/header.php";
require_once "keepass/key.php";
require_once "keepass/kdbximporter.php";

require_once "display.php";

abstract class KeePassPHP
{
	static private $started = false;
	static private $dbmanager;
	static private $kdbxmanager;
	static private $keymanager;
	static private $debug;
	static private $errorhandler;
	
	const DEBUG = false;
	const DEFAULT_HASH = "sha256";
	
	const EXT_KPHPDB = "kphpdb";
	const PREFIX_ICON = "icon";
	const PREFIX_DATABASE = "db";
	const PREFEXT_KEY = "key";
	const PREFEXT_KDBX = "kdbx";

	const DIR_KEEPASSPHP = "keepassphp/";
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
	 * Starts the KeePassPHP application.
	 * @param iErrorHandler $handler A handler to deal with and print errors.
	 * @return null
	 */
	public static function init(iErrorHandler $handler)
	{
		if(self::$started)
			return null;       
		
		self::$errorhandler = $handler;
		self::$debug = "";
		HashHouse::setDefault(self::DEFAULT_HASH);

		IconRepository::Init(self::DIR_KEEPASSPHP . self::DIR_DATA .
			self::DIR_ICONS, self::PREFIX_ICON);
		self::$dbmanager = new FileManager(self::DIR_KEEPASSPHP .
			self::DIR_DATA . self::DIR_SECURE . self::DIR_KPHPDB,
			self::PREFIX_DATABASE, true, false);
		self::$kdbxmanager = new UploadManager(self::DIR_KEEPASSPHP .
			self::DIR_DATA.self::DIR_SECURE.self::DIR_KDBX, self::PREFEXT_KDBX);
		self::$keymanager = new UploadManager(self::DIR_KEEPASSPHP .
			self::DIR_DATA.self::DIR_SECURE.self::DIR_KEY, self::PREFEXT_KEY);


		self::$started = true;
		self::printDebug("KeePassPHP application started !");
	}

	/**
	 * Tells the error handler to handle the error raised. Using KeePassPHP after
	 * this method is called will result in undefined behavior (but most probably
	 * new errors). The client application should consider that KeePassPHP can
	 * not be used anymore after such an error.
	 * @param string $msg
	 */
	public static function raiseError($msg)
	{
		self::$errorhandler->handleError("An unexpected error occured. " .
			self::DEBUG ? "Here is the debug trace :\n" . $msg . "\n" . self::$debug :
			"That's all we know.");
		//die();
	}

	/**
	 * Adds the given string to the debug data if debug mode is on.
	 * @param string $msg The string to add to the debug data.
	 */
	public static function printDebug($msg)
	{
		if(self::DEBUG)
			self::$debug .= self::makePrintable($msg) . "\n";
	}

	/**
	 * Adds the given debug string $msg, then the given binary string $bin as an
	 * hex string, to the debug data if debug mode is on.
	 * @param string $msg The 'normal' string to add to the debug data.
	 * @param string $bin The binary string to print in hexa.
	 */
	public static function printDebugHexa($msg, $bin)
	{
		if(self::DEBUG)
			self::$debug .= self::makePrintable($msg . " : " .
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
		if(self::DEBUG)
		{
			ob_start();
			print_r($array);
			self::$debug .= self::makePrintable($msg . " :: " .
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

	/**
	 * Tries to get the KeePass database corresponding the the ID $dbid, and to
	 * the passwords $pwd and $passwords. $pwd is the password needed to decrypt
	 * the KeePassPHP's internal database, which contains the name of the
	 * KeePass database, and the possible key files ; if $userPwdInCK, $pwd will
	 * also be used as the first password of the Master Key, otherwise, only
	 * passwords of $passwords will be used.
	 * Returns the database in case of success, null otherwise (the ID may be
	 * wrong, the password(s) may be wrond, etc.)
	 * @param string $dbid
	 * @param string $pwd
	 * @param boolean $usePwdInCK
	 * @param array $passwords
	 * @return null|Database
	 */
	public static function get($dbid, $pwd, $usePwdInCK, array $passwords)
	{
		if(!self::$started)
		{
			self::raiseError("KeepassPHP is not started !");
			return null;
		}

		$bindb = self::$dbmanager->getContentFromKey($dbid);
		if($bindb == null)
		{
			self::printDebug("Database not found or void");
			return null;
		}
		$db = self::decryptUnserialize($bindb, $pwd);
		if($db == false || !is_array($db) || count($db) < self::IDX_COUNT)
		{
			self::printDebug("Bad format, or wrong password");
			return null;
		}
		if($db[self::IDX_DBTYPE] != self::DBTYPE_KDBX)
		{
			self::printDebug("Types other than kbdx not yet supprted");
			return null;
		}

		$ckey = new CompositeKey();
		if($usePwdInCK)
			$ckey->addKey(new KeyFromPassword(utf8_encode($pwd)));
		$i = 0;
		foreach($db[self::IDX_KEYS] as $rk)
		{
			if($rk[0] == self::KEY_PWD && isset($passwords[$i]))
			{
				$ckey->addKey(new KeyFromPassword(utf8_encode($passwords[$i])));
				$i++;
			}
			elseif($rk[0] == self::KEY_FILE)
				$ckey->addKey(new KeyFromFile(self::$keymanager->getFile($rk[1])));
		}

		$kdbx = new KdbxImporter(
			self::$kdbxmanager->getFile($db[self::IDX_HASHNAME]), $ckey);

		$entries = $db[self::IDX_ENTRIES];
		if(!is_array($entries) || count($entries) == 0)
		{
			if($kdbx->load())
			{
				$entries = $kdbx->parseEntries();
				self::add($dbid, $pwd, $db[self::IDX_HASHNAME],
					$db[self::IDX_KEYS], $entries, $db[self::IDX_WRITEABLE]);
				$kdbx->useEntries($entries);
			}
			else
				self::printDebug("Trying to go on with no entries...");
		}
		else
			$kdbx->useEntries($entries);

		return $kdbx;
	}

	/**
	 * Adds the database whose hash key is $hashname to KeePassPHP, with $dbid
	 * as ID, $pwd oas password for the KeePassPHP's internal database, $keys
	 * as a description of the master key, $entries as the array of entries
	 * to keep in the internal database, and $writeable being true if sensitive
	 * that array of entries can be written on the disk, and false otherwise.
	 * @param string $dbid
	 * @param string $pwd
	 * @param string $hashname
	 * @param array $keys
	 * @param array $entries
	 * @param boolean $writeable
	 * @return null|string
	 */
	public static function add($dbid, $pwd, $hashname, array $keys,
			$entries, $writeable)
	{
		$db = array(
			self::IDX_DBTYPE => self::DBTYPE_KDBX,
			self::IDX_HASHNAME => $hashname,
			self::IDX_KEYS => $keys,
			self::IDX_ENTRIES => $writeable ? $entries : null,
			self::IDX_WRITEABLE => $writeable
		);

		$plaindb = serialize($db);
		$key = hash('SHA256', $pwd, true);
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

	public static function exists($dbid)
	{
		if(!self::$started)
		{
			self::raiseError("KeepassPHP is not started !");
			return false;
		}
		return self::$dbmanager->existsKey($dbid);
	}

	public static function checkPassword($dbid, $pwd)
	{
		if(!self::$started)
		{
			self::raiseError("KeepassPHP is not started !");
			return false;
		}
		$bindb = self::$dbmanager->getContentFromKey($dbid);
		$result = self::decryptUnserialize($bindb, $pwd);
		return $result !== false;
	}

	public static function isKdbxLoadable($file, array $keys)
	{
		$ckey = new CompositeKey();
		foreach($keys as $k)
		{
			if($k[0] == self::KEY_PWD)
				$ckey->addKey(new KeyFromPassword(utf8_encode($k[1])));
			elseif($k[0] == self::KEY_FILE)
				$ckey->addKey(new KeyFromFile($k[1]));
		}
		$kdbx = new KdbxImporter($file, $ckey);
		return $kdbx->load();
	}

	public static function addKdbxFile($file)
	{
		return self::$kdbxmanager->add($file, self::PREFEXT_KDBX, true, true);
	}

	public static function addKeyFile($file)
	{
		return self::$keymanager->add($file, self::PREFEXT_KEY, true, true);
	}

	public static function tryAddUploadedKdbx($dbid, $pwd, $kdbxfile, $keys)
	{
		if(!self::$started)
		{
			self::raiseError("KeepassPHP is not started !");
			return false;
		}

		$nkeys = array();
		foreach($keys as $k)
		{
			if($k[0] == self::KEY_PWD)
				$nkeys[] = array(self::KEY_PWD);
			else
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
		if(KeePassPHP::add($dbid, $pwd, $hashname, $nkeys, array(), true) == null)
		{
			self::raiseError("The database file could not be written.");
			return false;
		}
		return true;
	}

	/**
	 * Decrypts and unserialize the given binary string, assumed to be the
	 * content of a kphpdb file. Returns the result (an array), or false
	 * if something went wrong (bad password, bad binary string).
	 * @param string $bin
	 * @param string $pwd
	 * @return boolean|array
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
