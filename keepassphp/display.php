<?php

/**
 * Description of Display
 *
 * @author Louis
 */
abstract class Display
{
	private $debugDump;

	protected function __construct()
	{
		$this->debugDump = "";
	}

	public function addDebug($debug)
	{
		$this->debugDump .= self::makePrintable($debug) . "\n";
	}

	public function dumpDebug()
	{
		return $this->debugDump;
	}

	abstract public function raiseError($error);

	/**
	 * Returns the string in a html-printable format : encoded
	 * in UTF8, and with special chars encoded.
	 * @param string $s
	 * @return string
	 */
	public static function makePrintable($s)
	{
		return htmlspecialchars(utf8_encode($s), ENT_QUOTES, 'UTF-8');
	}
}

?>
