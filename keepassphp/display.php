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
 * That class represents the part which is in charge of displaying the actual
 * web page. It must handle the debug information (possibly ignoring them), and
 * the error raising (which requires it to print everything it has to print to
 * make a complete web page, because PHP will be exited by KeePassPHP just
 * after the call to raiseError()).
 * 
 * @author Louis Traynard
 */
abstract class Display
{
	private $debugDump;

	protected function __construct()
	{
		$this->debugDump = "";
	}

	/**
	 * Should print all the required information to end abruptly the page,
	 * and possibly the given string $error which should contain a description
	 * of the error. KeePassPHP will call die() just after this method.
	 */
	abstract public function raiseError($error);

	/**
	 * Adds the given string to the debug data.
	 * @param string $debug
	 */
	public function addDebug($debug)
	{
		$this->debugDump .= self::makePrintable($debug) . "\n";
	}

	/**
	 * Gets the currently saved debug data.
	 * @return string
	 */
	public function dumpDebug()
	{
		return $this->debugDump;
	}

	/**
	 * Returns the string in a html-printable format : encoded
	 * in UTF8, and with some special chars rightly encoded. Every piece of
	 * data printed in a web page and coming from KeePassPHP (either a password,
	 * an username, or a debug stuff, *anything*) should be 'protected' by this
	 * method.
	 * @param string $s
	 * @return string
	 */
	public static function makePrintable($s)
	{
		return htmlspecialchars(utf8_encode($s), ENT_QUOTES, 'UTF-8');
	}
}

?>
