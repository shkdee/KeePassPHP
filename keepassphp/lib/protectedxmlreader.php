<?php

namespace KeePassPHP;

/**
 * An XML reader with specific methods to ignore non-Element or text nodes,
 * and parse KeePass-style "protected" strings.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class ProtectedXMLReader
{
	const STOP = 0;
	const GO_ON = 1;
	const DO_NOT_READ = 2;

	const XML_ATTR_PROTECTED = "Protected";
	const XML_ATTR_TRUE = "True";

	public $r;
	private $_state;
	private $_randomStream;

	public function __construct(iRandomStream $randomStream = null)
	{
		$this->r = new \XMLReader();
		$this->_state = self::GO_ON;
		$this->_randomStream = $randomStream;
	}

	/**
	 * Opens the UTF-8-encoded file $file with the internal XMLReader.
	 * @param $file A path to an UTF-8-encoded XML file.
	 * @return true in case of success, false otherwise.
	 */
	public function open($file)
	{
		return file_exists($file) && $this->r->open($file, 'UTF-8');
	}

	/**
	 * Sets the UTF-8-encoded $src string as the XML source.
	 * @param $src An UTF-8-encoded XML string.
	 * @return true in case of success, false otherwise.
	 */
	public function XML($src)
	{
		return $this->r->XML($src, 'UTF-8');
	}

	/**
	 * Closes the XMLReader input.
	 * @return Returns true on success or false on failure.
	 */
	public function close()
	{
		return $this->r->close();
	}

	/**
	 * Gets the depth of the current node in the XML tree.
	 * @return The depth of the current node.
	 */
	public function depth()
	{
		return $this->r->depth;
	}

	/**
	 * Checks whether the current element has the given tagname.
	 * @return true if the tag name is $name, false otherwise.
	 */
	public function isElement($name)
	{
		return \strcasecmp($name, $this->r->name) == 0;
	}

	/**
	 * Reads the next Element node of the XML stream if its depth is strictly
	 * higher than $depth.
	 * @param $depth The minimum depth of the Element to read.
	 * @return false if the XML source ended, or if the depth of the next node
	 *         is lower than or equal to $depth.
	 */
	public function read($depth)
	{
		if($this->_state == self::STOP)
			return false;
		if($this->_state == self::GO_ON)
		{
			do
			{
				if(!@$this->r->read())
				{
					$this->_state = self::STOP;
					return false;
				}
			}
			while($this->r->nodeType != \XMLReader::ELEMENT);
		}
		if($this->r->depth > $depth)
		{
			$this->_state = self::GO_ON;
			return true;
		}
		else
		{
			$this->_state = self::DO_NOT_READ;
			return false;
		}
	}

	/**
	 * Reads the text content of the current Element node.
	 * @param $asProtectedString Whether to return an iBoxedString instance
	 *                           rather than a plain string.
	 * @return The text content if it exists, or null.
	 */
	public function readTextInside($asProtectedString = false)
	{
		if($this->_state != self::GO_ON || $this->r->isEmptyElement)
			return null;
		$isProtected = $this->r->hasAttributes &&
			$this->r->getAttribute(self::XML_ATTR_PROTECTED) == self::XML_ATTR_TRUE;
		
		if(!@$this->r->read())
		{
			$this->_state = self::STOP;
			return null;
		}

		if($this->r->nodeType == \XMLReader::TEXT)
		{
			$value = $this->r->value;
			if(!$isProtected || empty($value) || $this->_randomStream == null)
				return $asProtectedString
					? new UnprotectedString($value)
					: $value;
			$value = base64_decode($value);
			$random = $this->_randomStream->getNextBytes(strlen($value));
			return $asProtectedString
				? new ProtectedString($value, $random)
				: $value ^ $random;
		}
		elseif($this->r->nodeType == \XMLReader::ELEMENT)
		{
			$this->_state = self::DO_NOT_READ;
			return null;
		}
	}
}

?>