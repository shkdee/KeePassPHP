<?php

/**
 * Main class of the KeePassPHP application.
 * Calls all the other classes, loads database,
 * and exploits results.
 * 
 * @author Louis
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
	static private $display;
	
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
	 * @return void
	 */
	public static function init(Display $display)
	{
		if(self::$started)
			return null;       
		
		self::$display = $display;
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
	 * Stops the KeePassPHP application, and prints the
	 * given message $msg if the debug mode is on.
	 * @param string $msg
	 */
	public static function raiseError($msg)
	{
		self::$display->raiseError(self::DEBUG ? $msg :
			"An unexpected error occured.");
		die();
	}

	/**
	 * Prints the given string $msg if the debug mode is on.
	 * @param string $msg
	 */
	public static function printDebug($msg)
	{
		if(self::DEBUG)
			self::$display->addDebug($msg);
	}

	/**
	 * If the debug mode is on, prints the given string $msg, then
	 * the given binary string $bin as an hex string.
	 * @param string $msg
	 * @param string $bin
	 */
	public static function printDebugHexa($msg, $bin)
	{
		if(self::DEBUG)
			self::$display->addDebug($msg . " : " .
				Binary::fromString($bin)->asHexString());
	}

	/**
	 * If the debug mode is on, prints the given string $msg, then
	 * the given array $array with print_r.
	 * @param string $msg
	 * @param array $array
	 */
	public static function printDebugArray($msg, $array)
	{
		if(self::DEBUG)
		{
			ob_start();
			print_r($array);
			self::$display->addDebug($msg . " :: " . ob_get_contents());
			ob_end_clean();
		}
	}

	/**
	 *
	 * @param type $dbkey
	 * @param type $pwd
	 * @param type $usePwdInCK
	 * @param array $passwords
	 * @return null|Database
	 */
	public static function get($dbid, $pwd, $usePwdInCK, array $passwords)
	{
		if(!self::$started)
			self::raiseError("KeepassPHP is not started !");

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
	 *
	 * @param type $dbid
	 * @param type $pwd
	 * @param type $hashname
	 * @param array $keys
	 * @param type $entries
	 * @param type $writeable
	 * @return type
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
			self::raiseError("Unexpected size of IV : " . strlen($iv));
		$bindb = $iv . $cipher->encrypt($plaindb);
		$cipher->unload();

		return self::$dbmanager->addWithKey($dbid, $bindb, self::EXT_KPHPDB,
			true, true);
	}

	public static function exists($dbid)
	{
		return self::$dbmanager->existsKey($dbid);
	}

	public static function checkPassword($dbid, $pwd)
	{
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
		$nkeys = array();
		foreach($keys as $k)
		{
			if($k[0] == self::KEY_PWD)
				$nkeys[] = array(self::KEY_PWD);
			else
			{
				$h = KeePassPHP::addKeyFile($k[1]);
				if($h == null)
					self::raiseError("File upload failed unexpectedly.");
				$nkeys[] = array(KeePassPHP::KEY_FILE, $h);
			}
		}
		$hashname = KeePassPHP::addKdbxFile($kdbxfile);
		if($hashname == null)
			self::raiseError("File upload failed unexpectedly.");
		if(KeePassPHP::add($dbid, $pwd, $hashname, $nkeys, array(), true) == null)
			self::raiseError("Database write failed unexpectedly.");
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
