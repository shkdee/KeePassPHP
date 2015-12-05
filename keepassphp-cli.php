<?php

$count = isset($argc) ? intval($argc) : 0;
if($count < 3)
{
	echo "\nUsage: php keepassphp-cli.php <kdbx file path> <text password> [key file path]";
	die();
}

$file = $argv[1];
$pwd = $argv[2];
$keyfile = $count >= 4 ? $argv[3] : null;

echo "Loading dabatase '", $file, "' (this may take some time)...\n";

// loads classes
require_once "keepassphp/keepassphp.php";

// initialize KeePassPHP ("true" to enable debug mode)
KeePassPHP::init(true);

// create a key with the password and possibly the key file
$ckey = new CompositeKey();
$ckey->addKey(new KeyFromPassword(utf8_encode($pwd))); // utf8_encode may be useless (or even unsuitable?) depending on where $pwd comes from
if(!empty($keyfile))
	$ckey->addKey(new KeyFromFile($keyfile));

// create the dabase, then try to load it (read the file, decrypt it, parse the xml inside)
// The loading may take some time if your database is hard to decrypt.
$db = new KdbxImporter($file, $ckey);
if($db->tryLoad())
{
	echo "... done!\n";

	// get the password entries as a clean array
	$entries = $db->parseEntries();
	// $entries is now an associative array, whose keys are entries uuid,
	// and values are arrays containing entries data. For example, assume
	// that $uuid is a key, and $entry = $entries[$uuid], we have:
	//
	// $entry[Database::KEY_TITLE]      is the entry title
	// $entry[Database::KEY_CUSTOMICON] is the custom icon uuid of this entry
	// $entry[Database::KEY_TAGS]       is the entry tag field
	// $entry[Database::KEY_URL]        is the entry url
	// $entry[Database::KEY_USERNAME]   is the entry username
	// $db->getPassword($uuid)          is the entry password
	//
	// The password was not included in the $entries array by design, but
	// this may change in the future...

	// e.g print "<entry title> => <entry username>" for all entries
	foreach($entries as $entry)
		echo $entry[Database::KEY_TITLE], "\t => ", $entry[Database::KEY_USERNAME], "\n";

	// e.g print "<entry username>: <entry password>" for all entries
	// (! this will print all your passwords, you may not want that, uncomment at your own risk !)
	//foreach($entries as $uuid => $entry)
	//	echo $entry[Database::KEY_USERNAME], ": ", $db->getPassword($uuid), "\n";
}
else
{
	echo "... failed!\n";
}
echo "\nDebug data:\n", KeepassPHP::$errordump;
?>