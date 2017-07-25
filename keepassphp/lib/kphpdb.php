<?php

namespace KeePassPHP;

/**
 * A class managing a KphpDB file, which is a file containing a Database
 * instance plus some metadatas such as a key file location. It never contains
 * passwords, they are stripped from the database. They must always be parsed
 * from the original database file.
 * An instance of this class can be easily serialized to and parsed from a
 * JSon string. It can also be easily embedded in an encrypted .kdbx file.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class KphpDB
{
	private $_dbType;
	private $_db;
	private $_headerHash;
	private $_dbFileHash;
	private $_keyFileHash;

	const KEY_DBTYPE = "type";
	const KEY_DBFILEHASH = "dbfile";
	const KEY_KEYFILEHASH = "keyfile";
	const KEY_HEADERHASH = "headerhash";
	const KEY_DB = "db";
	const KEY_VERSION = "version";

	const DBTYPE_NONE = 1;
	const DBTYPE_KDBX = 2;
	const ROUNDS = 128;

	/** Version 0 of the kphpdb serialization format. */
	const VERSION_0 = 0;
	/** Version 1 of the kphpdb serialization format. */
	const VERSION_1 = 1;
	/** Current version of the kphpdb serialization format. Databases
	 * serialized with the current code have this format. */
	const VERSION_CURRENT = self::VERSION_1;

	/**
	 * Constructs a new KphpDB instance.
	 * @param $dbType The wrapped database type.
	 * @param $db An object that will be wrapped by this KphpDB.
	 * @param $dbFileHash The hexadecimal hash of the original db file.
	 * @param $keyFileHash A possible hexadecimal hash of an additional key
	 *                     file if needed to decrypt the original db file.
	 */
	protected function __construct($dbType, $db, $dbFileHash, $keyFileHash)
	{
		$this->_dbType = $dbType;
		$this->_db = $db;
		$this->_dbFileHash = $dbFileHash;
		$this->_keyFileHash = $keyFileHash;
		$this->_headerHash = null;
	}

	/**
	 * Creates a new KphpDB instance that wraps a Database instance.
	 * @param $db A Database instance.
	 * @param $dbFileHash The hexadecimal hash of the original db file.
	 * @param $keyFileHash A possible hexadecimal hash of an additional key
	 *                     file if needed to decrypt the original db file.
	 * @return A new KphpDB instance.
	 */
	public static function createFromDatabase(Database $db, $dbFileHash,
		$keyFileHash)
	{
		return new KphpDB(self::DBTYPE_KDBX, $db, $dbFileHash, $keyFileHash);
	}

	/**
	 * Creates a new KphpDB instance that wraps nothing.
	 * @param $dbFileHash The hexadecimal hash of the original db file.
	 * @param $keyFileHash A possible hexadecimal hash of an additional key
	 *                     file if needed to decrypt the original db file.
	 * @return A new KphpDB instance.
	 */
	public static function createEmpty($dbFileHash, $keyFileHash)
	{
		return new KphpDB(self::DBTYPE_NONE, null, $dbFileHash, $keyFileHash);
	}

	/**
	 * Gets the type of the database wrapped by this KphpDB file.
	 * @return One of the KphpDB::DBTYPE_* constants.
	 */
	public function getDBType()
	{
		return $this->_dbType;
	}

	/**
	 * Gets the database wrapped by this KphpDB file, whose class depends on
	 * this instance DB type. It does not contain passwords.
	 * @return For now, either null or a Database instance.
	 */
	public function getDB()
	{
		return $this->_db;
	}

	/**
	 * Gets the original DB file hash.
	 * @return A hexadecimal hash.
	 */
	public function getDBFileHash()
	{
		return $this->_dbFileHash;
	}

	/**
	 * Gets the hexadecimal hash of the additional key file associated with the
	 * Database instance, if there is one.
	 * @return A hexadecimal hash, or null if there is none.
	 */
	public function getKeyFileHash()
	{
		return $this->_keyFileHash;
	}

	/**
	 * Serializes this instance to a JSon string.
	 * @param $filter An iFilter instance to select the data of the database
	 *                that must actually be serialized (if null, it will
	 *                serialize everything except from passowrds).
	 * @param &$error A string that will receive a message in case of error.
	 * @return A JSon string in case of success, or null in case of error.
	 */
	public function toJSon($filter, &$error)
	{
		$array = array(
			self::KEY_VERSION => self::VERSION_CURRENT,
			self::KEY_DBTYPE => $this->_dbType,
			self::KEY_DBFILEHASH => $this->_dbFileHash,
			self::KEY_KEYFILEHASH => $this->_keyFileHash,
			self::KEY_HEADERHASH => base64_encode($this->_headerHash),
			self::KEY_DB => $this->_db->toArray($filter));
		$r = json_encode($array);
		if($r === false)
		{
			$error = "KphpDB JSon save: " . json_last_error();
			return null;
		}
		$error = null;
		return $r;
	}

	/**
	 * Serializes this instance to a JSon string and encrypts it in a kdbx
	 * file.
	 * @param $key A iKey instance to use to encrypt the kdbx file.
	 * @param $filter An iFilter instance to select the data of the database
	 *                that must actually be serialized (if null, it will
	 *                serialize everything except from passowrds).
	 * @param &$error A string that will receive a message in case of error.
	 * @return A string containing a kdbx file embbeding this serialized
	 *         instance, or null in case of error.
	 */
	public function toKdbx(iKey $key, $filter, &$error)
	{
		$kdbx = KdbxFile::createForEncrypting(self::ROUNDS, $error);
		if($kdbx == null)
			return null;

		$this->_headerHash = $kdbx->getHeaderHash();

		$json = $this->toJSon($filter, $error);
		if(empty($json))
			return null;

		return $kdbx->encrypt($json, $key, $error);
	}

	/**
	 * Creates a new KphpDB instance from a JSon string, that should have been
	 * created by the method toJSon() of another KphpDB instance.
	 * @param json A JSon string.
	 * @param &$error A string that will receive a message in case of error.
	 * @return A new KphpDB instance, or null in case of error.
	 */
	public static function loadFromJSon($json, &$error)
	{
		$array = json_decode($json, true);
		if($array === null)
		{
			$error = "KphpDB JSon load: cannot parse JSon string: "
				. json_last_error();
			return null;
		}

		if(!array_key_exists(self::KEY_DBTYPE, $array) ||
			!array_key_exists(self::KEY_DBFILEHASH, $array) ||
			!array_key_exists(self::KEY_KEYFILEHASH, $array) ||
			!array_key_exists(self::KEY_HEADERHASH, $array) ||
			!array_key_exists(self::KEY_DB, $array))
		{
			$error = "KphpDB JSon load: incomplete file.";
			return null;
		}
		$version = array_key_exists(self::KEY_VERSION, $array)
			? intval($array[self::KEY_VERSION])
			: self::VERSION_0;

		$dbType = $array[self::KEY_DBTYPE];
		$db = null;
		if($dbType == self::DBTYPE_KDBX)
		{
			$db = Database::loadFromArray($array[self::KEY_DB], $version,
				$error);
			if($db === null)
				return null;
		}
		else if($dbType != self::DBTYPE_NONE)
		{
			$error = "KphpDB JSon load: unkown db type '" + $dbType + '".';
			return null;
		}
		$kdbx = new KphpDB($dbType, $db,
			$array[self::KEY_DBFILEHASH], $array[self::KEY_KEYFILEHASH]);
		$kdbx->_headerHash = base64_decode($array[self::KEY_HEADERHASH]);
		return $kdbx;
	}

	/**
	 * Creates a new KphpDB instance from a kdbx file, that should have been
	 * created by the method toKdbx() of another KphpDB instance.
	 * @param $reader A Reader instance reading a kdbx file.
	 * @param $key A iKey instance to use to decrypt the kdbx file.
	 * @param &$error A string that will receive a message in case of error.
	 * @return A new KphpDB instance, or null in case of error.
	 */
	public static function loadFromKdbx(Reader $reader, iKey $key, &$error)
	{
		$kdbx = KdbxFile::decrypt($reader, $key, $error);
		if($kdbx == null)
			return null;
		$kphpdb = self::loadFromJSon($kdbx->getContent(), $error);
		if($kphpdb == null)
			return null;
		if($kphpdb->_headerHash !== $kdbx->getHeaderHash())
		{
			$error = "KphpDB Kdbx load: header hash is not correct.";
			return null;
		}
		return $kphpdb;
	}
}

?>