<?php

function usageAndDie()
{
	echo "Usage: php keepassphp-cli.php <command> [args...]",
	     "\n\nPossible commands are:",
	     "\n   add <id> <kdbx file> <password> [key file] [kphpdb password]   Adds a database",
	     "\n   get <id> <password> [kphpdb password]                          Shows the content of a database",
	     "\n   pwd <id> <n> <password> [kphpdb password]                      Gets a password",
	     "\n   rem <id> <kphpdb password>                                     Removes a database",
	     "\n   kdbx <kdbx file> <password> [key file]                         Decrypts a database file",
	     "\n   kdbx-pwd <entry uuid> <kdbx file> <password> [key file]        Gets a password from a database file",
	     "\n   encrypt <file> <password> [key file]                           Encrypts a file with the kdbx format",
	     "\n   decrypt <file> <password> [key file]                           Decrypts a file encrypted with encrypt";
	die();
}

function KPHPDebugAndDie($msg)
{
	echo "\nError: $msg\n", "Debug data:\n",
		\KeePassPHP\KeePassPHP::$debugData, "\n";
	die();
}

function errorAndDie($msg)
{
	echo "\nError: $msg\n";
	die();
}

function visitDatabase(\KeePassPHP\Database $db)
{
	echo "Database '", $db->getName(), "'\n";
	$groups = $db->getGroups();
	if($groups == null)
		echo "    (no groups)";
	else
	{
		foreach($groups as &$g)
			visitGroup($g, 4);
	}
}

function visitGroup(\KeePassPHP\Group $group, $indent)
{
	echo str_pad("", $indent, " "), "Group '", $group->name, "'\n";
	if($group->groups != null)
	{
		foreach($group->groups as &$g)
			visitGroup($g, $indent + 4);
	}
	if($group->entries == null)
		echo str_pad("", $indent + 4, " "), "(no entries)\n";
	else
	{
		foreach($group->entries as &$e)
			visitEntry($e, $indent + 4);
	}
}

function visitEntry(\KeePassPHP\Entry $entry, $indent)
{
	echo str_pad("", $indent, " "),
		$entry->uuid, "\t => ", $entry->getStringField(\KeePassPHP\Database::KEY_TITLE),
		"\t", $entry->getStringField(\KeePassPHP\Database::KEY_USERNAME),
		"\t", $entry->getStringField(\KeePassPHP\Database::KEY_URL), "\n";
}

$count = isset($argc) ? intval($argc) : 0;
if($count < 2)
	usageAndDie();

// load classes
require_once "keepassphp/keepassphp.php";
use \KeePassPHP\KeePassPHP as KeePassPHP;

// configuration
$debugMode = true;

// execute command
$command = $argv[1];

if($command == "add")
{
	if($count < 5)
		usageAndDie();

	// initialize KeePassPHP
	if(!KeePassPHP::init(null, $debugMode))
		KPHPDebugAndDie("Initialization failed.");

	$dbid = $argv[2];
	$file = $argv[3];
	$pwd = $argv[4];
	$keyfile = $count >= 6 ? $argv[5] : null;
	$kphpdbPwd = $count >= 7 ? $argv[6] : null;
	if(empty($kphpdbPwd))
		$kphpdbPwd = KeePassPHP::extractHalfPassword($pwd);

	if(KeePassPHP::existsKphpDB($dbid))
	{
		if(!KeePassPHP::removeDatabase($dbid, $kphpdbPwd))
			KPHPDebugAndDie("Database '" . $dbid .
				"' already exists and cannot be deleted.");
	}

	if(!KeePassPHP::addDatabaseFromFiles($dbid, $file, $pwd, $keyfile,
			$kphpdbPwd, true))
		KPHPDebugAndDie("Cannot add database '" . $dbid . "'.");
	echo "Database '", $dbid, "' added successfully.";
}

else if($command == "get" || $command == "pwd")
{
	$offset = $command == "pwd" ? 1 : 0;
	if($count < 4 + $offset)
		usageAndDie();

	// initialize KeePassPHP
	if(!KeePassPHP::init(null, $debugMode))
		KPHPDebugAndDie("Initialization failed.");

	$dbid = $argv[2];
	$pwd = $argv[3 + $offset];
	$kphpdbPwd = $count >= 5 + $offset ? $argv[4 + $offset] : null;
	if(empty($kphpdbPwd))
		$kphpdbPwd = KeePassPHP::extractHalfPassword($pwd);

	$db = KeePassPHP::getDatabase($dbid, $kphpdbPwd, $pwd, $command == "pwd");
	if($db == null)
		KPHPDebugAndDie("Cannot get database '" . $dbid . "'.");

	if($command == "pwd")
	{
		$r = $db->getPassword($argv[3]);
		if($r == null)
			echo "entry '", $argv[3], "' not found!";
		else
			echo $r;
	}
	else
		visitDatabase($db);
}

else if($command == "rem")
{
	if($count < 4)
		usageAndDie();

	// initialize KeePassPHP
	if(!KeePassPHP::init(null, $debugMode))
		KPHPDebugAndDie("Initialization failed.");

	$dbid = $argv[2];
	$pwd = $argv[3];

	if(KeePassPHP::removeDatabase($dbid, $pwd))
		echo "Database '", $dbid, "' successfully removed.";
	else
		KPHPDebugAndDie("Cannot remove database '" . $dbid . "'.");
}

else if($command == "kdbx" || $command == "kdbx-pwd")
{
	// no need to initialize KeePassPHP here, since
	// we're only using low-level API.

	$offset = $command == "kdbx-pwd" ? 1 : 0;
	if($count < 4 + $offset)
		usageAndDie();

	$file = $argv[2 + $offset];
	$pwd = $argv[3 + $offset];
	$keyfile = $count >= 5 + $offset ? $argv[4 + $offset] : null;

	$ckey = KeePassPHP::masterKey();
	KeePassPHP::addPassword($ckey, $pwd);
	if(!KeePassPHP::addKeyFile($ckey, $keyfile))
		errorAndDie("file key parsing error.");

	// The loading may take some time if your database is hard to decrypt.
	$error = null;
	$db = KeePassPHP::openDatabaseFile($file, $ckey, $error);
	if($db == null)
		errorAndDie($error);
	
	if($command == "kdbx-pwd")
	{
		$r = $db->getPassword($argv[2]);
		if($r == null)
			echo "entry '", $argv[2], "' not found!";
		else
			echo $r;
	}
	else
		visitDatabase($db);
}

else if($command == "encrypt" || $command == "decrypt")
{
	if($count < 4)
		usageAndDie();

	$fileContent = file_get_contents($argv[2]);
	if(!$fileContent)
		errrorAndDie("Cannot open file '" . $argv[2] . "'");
	$pwd = $argv[3];
	$keyfile = $count >= 5 ? $argv[4] : null;

	$ckey = KeePassPHP::masterKey();
	KeePassPHP::addPassword($ckey, $pwd);
	if(!KeePassPHP::addKeyFile($ckey, $keyfile))
		errorAndDie("file key parsing error.");

	$error = null;
	$result = $command == "encrypt"
		? KeePassPHP::encryptInKdbx($fileContent, $ckey, 6000, $error)
		: KeePassPHP::decryptFromKdbx($fileContent, $ckey, true, $error);
	if($result === null)
		KPHPDebugAndDie($error);
	echo $result;
}

else
{
	echo "\nUnkown command '", $command, "'.\n";
	usageAndDie();
}
?>