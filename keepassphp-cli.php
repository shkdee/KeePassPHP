<?php

function usageAndDie()
{
	echo "Usage: php keepassphp-cli.php <command> [args...]",
	     "\n\nPossible commands are:",
	     "\n   add <db id> <kdbx file> <password> [key file] [kphpdb password]  Adds a database with a specific id",
	     "\n   get <db id> <password> [kphpdb password]                         Shows the content of a database",
	     "\n   pwd <db id> <entry uuid> <password> [kphpdb password]            Gets a password",
	     "\n   rem <db id> <kphpdb password|password>                           Removes a database",
	     "\n   kdbx <kdbx file> <password> [key file]                           Decrypts a database file",
	     "\n   kdbx-pwd <entry uuid> <kdbx file> <password> [key_file]          Gets a password from a database file",
	     "\n   encrypt <file> <password> [key file]                             Encrypts a file with the kdbx format",
	     "\n   decrypt <file> <password> [key file]                             Decrypts a file encrypted with encrypt",
		 "\n   export <db id> <kphpdb password|password> [kdbx file]            Export database with a specific id to a file",
             "\n\n"
	;
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

function visitEntryValues(\KeePassPHP\Database $db, $uuid)
{
	$title = $db->getStringField($uuid, \KeePassPHP\Database::KEY_TITLE);
	if ($title != null)
	{
		echo $title, "\n";
		echo str_pad('', 20, '-'), "\n";
	}
	$entry_user = $db->getStringField($uuid, \KeePassPHP\Database::KEY_USERNAME);
	if ($entry_user != null)
	{
		echo str_pad(\KeePassPHP\Database::KEY_USERNAME, 20), ': ', $entry_user, "\n";
	}

	$entry_pwd = $db->getPassword($uuid);
	if ($entry_pwd != null)
	{
		echo str_pad(\KeePassPHP\Database::KEY_PASSWORD, 20), ': ', $entry_pwd, "\n";
	}

	$entry_url = $db->getStringField($uuid, \KeePassPHP\Database::KEY_URL);
	if ($entry_url != null)
	{
		echo str_pad(\KeePassPHP\Database::KEY_URL, 20), ': ', $entry_url, "\n";
	}

	$entry_notes = $db->getStringField($uuid, \KeePassPHP\Database::KEY_NOTES);
	if ($entry_notes != null)
	{
		echo str_pad(\KeePassPHP\Database::KEY_NOTES, 20), ': ';
		$entry_notes = preg_split('/\r?\n/', $entry_notes);
		$i=0;
		foreach($entry_notes as $entry_note_line)
		{
			if ($i != 0)
				echo str_pad('', 20), '  ';
			echo $entry_note_line, "\n";
			$i++;
		}
	}

	$entry_extra = $db->listCustomFields($uuid);
	foreach($entry_extra as $var)
	{
			$extra_value = $db->getStringField($uuid, $var);
			if ($extra_value != null)
			{
					echo str_pad($var, 20), ": $extra_value\n";
			}
	}
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
		$title = $db->getStringField($argv[3], \KeePassPHP\Database::KEY_TITLE);
		if($title == null)
			echo "entry '", $argv[3], "' not found!";
		else
			visitEntryValues($db, $argv[3]);
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
	$kphpdbPwd = $argv[3];

	$success = false;
	if(KeePassPHP::removeDatabase($dbid, $kphpdbPwd))
	{
		$success = true;
	}
	else
	{
		$kphpdbPwd = KeePassPHP::extractHalfPassword($pwd);
		if(KeePassPHP::removeDatabase($dbid, $kphpdbPwd))
			$success = true;
	}
	
	if ($success)
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

else if($command == "export")
{
	if($count < 4)
		usageAndDie();
	
	// initialize KeePassPHP
	if(!KeePassPHP::init(null, $debugMode))
		KPHPDebugAndDie("Initialization failed.");
	
	$dbid = $argv[2];
	$kphpdbPwd = $argv[3];

	if($count >= 5)
		$dest = $argv[4];
	else
		$dest = $dbid . '.kdbx';
	
	if (!KeePassPHP::existsKphpDB($dbid))
		KPHPDebugAndDie("Database '" . $dbid . "' not found.");
	
	$source = KeePassPHP::getDatabaseFilename($dbid, $kphpdbPwd);
	if (!$source)
	{
		$kphpdbPwd = KeePassPHP::extractHalfPassword($kphpdbPwd);
		$source = KeePassPHP::getDatabaseFilename($dbid, $kphpdbPwd);
	}
	
	if (!$source)
		KPHPDebugAndDie("Unable to locate file of database '" . $dbid . "'.");
	
	if (!copy($source, $dest))
		KPHPDebugAndDie("Unable to create file '" . $dest . "'.");
	
	echo "Database '" . $dbid . "' successfully exported to '" . $dest . "'\n";
}

else
{
	echo "\nUnkown command '", $command, "'.\n";
	usageAndDie();
}
?>