<?php

namespace KeePassPHP;

/**
 * Implementation of database filters.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */


/**
 * A set of rules to determine which data to write when serializing a database.
 * Implementing this interface makes it possible to write only specific data.
 */
interface iFilter
{
	/**
	 * Returns true if the given entry must be serialized (otherwise it will be
	 * discarded).
	 * @param $entry An entry.
	 */
	public function acceptEntry(Entry $entry);
	/**
	 * Returns true if the given group must be serialized (otherwise it will be
	 * discarded).
	 * @param $entry A group.
	 */
	public function acceptGroup(Group $group);
	/**
	 * Returns true if the given history entry must be serialized (otherwise it
	 * will be discarded).
	 * @param $entry A history entry.
	 */
	public function acceptHistoryEntry(Entry $entry);
	/**
	 * Returns true if tags must be serialized.
	 */
	public function acceptTags();
	/**
	 * Returns true if icons must be serialized.
	 */
	public function acceptIcons();
	/**
	 * Returns true if passwords must be serialized.
	 * WARNING: it is NOT recommanded to return true in implementations of this
	 * method, because passwords should not be copied in most cases.
	 */
	public function acceptPasswords();
	/**
	 * Returns true if string fields with the given key must be serialized.
	 * @param $key A string field key.
	 */
	public function acceptStrings($key);
}

/**
 * A default filter that writes everything except from passwords.
 */
class AllExceptFromPasswordsFilter implements iFilter
{
	public function acceptEntry(Entry $entry)
	{
		return true;
	}

	public function acceptGroup(Group $group)
	{
		return true;
	}

	public function acceptHistoryEntry(Entry $historyEntry)
	{
		return true;
	}

	public function acceptTags()
	{
		return true;
	}

	public function acceptIcons()
	{
		return true;
	}

	public function acceptPasswords()
	{
		return false;
	}

	public function acceptStrings($key)
	{
		return true;
	}
}

?>