<?php

/**
 * Wrapper around XMLReader to allow easy searching
 * for a node, with conditions on its parents. It just
 * keeps track of parents with an internal stack
 * (hence its name). It also drops all END_ELEMENT
 * nodes read by the original XMLReader.
 *
 * @author Louis
 */
class XMLStackReader
{
	public $r;
	private $stack;
	private $d;
	private $isCurrentAlreadyRead;

	// constants for the results of the readTextNodesInside method
	const NODENAME = 0;
	const ATTRIBUTES = 1;
	const INNER = 2;

	public function __construct()
	{
		$this->r = new XMLReader();
		$this->stack = array();
		$this->d = -1;
		$this->isCurrentAlreadyRead = true;
	}

	/********************
	 * Stack management *
	 ********************/

	/**
	 * Adds the element $e to the stack.
	 * @param string $e
	 */
	private function push($e)
	{
		array_push($this->stack, strtolower($e));
	}

	/**
	 * Removes and returns the top element of the stack.
	 * @return string
	 */
	private function pop()
	{
		return array_pop($this->stack);
	}

	/**
	 * Returns, without removing it, the top element of the stack.
	 * @return string
	 */
	private function peek()
	{
		return $this->stack[$this->d];
	}

	/******************
	 * Public methods *
	 ******************/

	/**
	 * Opens the file $file with the internal XMLReader ; returns true in
	 * case of success, or false otherwise.
	 * @param string $file
	 * @return boolean
	 */
	public function open($file)
	{
		if(!file_exists($file) || !$this->r->open($file))
			return false;
		return true;
	}

	/**
	 * Sets $src as the XML source of the internal XMLReader ; returns true
	 * in case of success, or false otherwise.
	 * @param string $src
	 * @return boolean
	 */
	public function XML($src)
	{
		if(!$this->r->XML($src))
			return false;
		return true;
	}

	/**
	 * Forwards the internal XMLReader (call its own read() method),
	 * and manages the stack. Returns true if the read was successful,
	 * or false if there is nothing more to read.
	 * @return boolean
	 */
	public function read()
	{
		if(!$this->isCurrentAlreadyRead)
		{
			$this->isCurrentAlreadyRead = true;
			return true;
		}
		do
		{
			if(!@$this->r->read())
				return false;
		}
		while($this->r->nodeType == XMLReader::END_ELEMENT
				|| $this->r->nodeType == XMLReader::SIGNIFICANT_WHITESPACE);

		if($this->r->depth > $this->d)
		{
			if($this->r->nodeType == XMLReader::ELEMENT)
			{
				$this->d++;
				$this->push($this->r->name);
			}
		}
		elseif($this->r->depth == $this->d)
		{
			$this->pop();
			if($this->r->nodeType == XMLReader::ELEMENT)
				$this->push($this->r->name);
			else
				$this->d--;
		}
		elseif($this->r->depth < $this->d)
		{
			while($this->r->depth <= $this->d)
			{
				$this->pop();
				$this->d--;
			}
			if($this->r->nodeType == XMLReader::ELEMENT)
			{
				$this->d++;
				$this->push($this->r->name);
			}
		}
		return true;
	}

	/**
	 * Reads a new element, and returns true if its depth is more than $d
	 * (meaning it is in the subtree of a node whose depth is $d), and false
	 * otherwise.
	 * @param int $depth
	 * @return boolean
	 */
	public function isInSubtree($d)
	{
		if($this->read())
		{
			if($this->r->depth > $d)
				return true;
			$this->isCurrentAlreadyRead = false;
		}
		return false;
	}

	/**
	 * Reads elements and stops at the first found node whose parents
	 * are $parents.
	 * @param array $parents
	 * @return boolean
	 */
	public function readUntilParentsBe($parents)
	{
		while($this->read())
			if($this->areParents($parents))
				return true;
		return false;
	}

	/**
	 * Returns true if $p is the father of the current node.
	 * @param string $p
	 * @return boolean
	 */
	public function isParent($p)
	{
		return $this->peek() == strtolower($p);
	}

	/**
	 * Returns true if $a is an ancestor of the current node.
	 * @param string $a
	 * @return boolean
	 */
	public function isAncestor($a)
	{
		return array_search($a, $this->stack) !== false;
	}

	/**
	 * Returns true if the closest parents of the current node are exactly
	 * the ones given in the array $array (e.g the father of the current node
	 * must be the last element of $array, the father of that father must be
	 * the element before the last element of $array, etc), and false
	 * otherwise.
	 * @param type $array
	 * @return boolean
	 */
	public function areParents($array)
	{
		$t = count($array) - 1;
		if($t > $this->d)
			return false;
		for($i = 0 ; $i <= $t ; $i++)
			if(strtolower($array[$t - $i]) != $this->stack[$this->d - $i])
				return false;
		return true;
	}

	/**
	 * Returns true if the first child of the current node is a text node.
	 * @return boolean
	 */
	public function isTextInside()
	{
		if(!$this->isCurrentAlreadyRead &&
				$this->r->nodeType == XMLReader::TEXT)
		{
			$this->isCurrentAlreadyRead = true;
			return true;
		}
		$d = $this->d;
		if($this->read())
		{
			if($this->r->depth > $d && $this->r->nodeType == XMLReader::TEXT)
				return true;
			$this->isCurrentAlreadyRead = false;
		}
		return false;
	}

	/**
	 * Returns as an array the nodes inside the current subtree of depth $depth.
	 * Each node is described as an array with the following format :
	 * the first element of the array (self::NODENAME) is the name of the node,
	 * the second (self::ATTRIBUTES) is either an associative array containing
	 * the attributes of the current node as keys and their contents as values,
	 * or null if the current node has no attributes ; and the third element
	 * (self::INNER) contains either null if the node has no content, either a
	 * string if it contains text, or another array representing its inner xml
	 * subtree.
	 * @param int $depth
	 * @return array
	 */
	public function readInnerXML($depth)
	{
		$nodes = array();
		while($this->isInSubtree($depth))
		{
			$k = $this->r->name;
			$d = $this->r->depth;
			$a = null;
			if($this->r->hasAttributes)
			{
				$a = array();
				while($this->r->moveToNextAttribute())
					$a[$this->r->name] = $this->r->value;
				$this->r->moveToElement();
			}
			if($this->isTextInside())
				$nodes[] = array($k, $a, $this->r->value);
			else
			{
				$sub = $this->readInnerXML($d);
				$nodes[] = array($k, $a, count($sub) > 0 ? $sub : null);
			}
		}
		return $nodes;
	}

	/**
	 * Closes the internal XMLReader.
	 */
	public function close()
	{
		$this->r->close();
	}

	/**
	 * If debug mode is non, prints the current node and its parents.
	 */
	public function printCurrentNode()
	{
		if(KeePassPHP::$debug)
		{
			$s = "";
			foreach($this->stack as $v)
				$s = $s . $v . ".";
			echo "<pre>", $s, "[", $this->r->depth, "] ",
					$this->r->name, " :: ", $this->r->value, "</pre>";
		}
	}

	/***********************************************************
	 * Static functions to exploit readTextNodesInside results *
	 ***********************************************************/

	/**
	 * Returns true if a node $name has been found in the array $a, assumed
	 * to be a list of sibling nodes as would be returned by the method
	 * readInnerXML(). If a matching node is found, $result (passed by
	 * reference) will contain it (as the representing array !).
	 * @param array $a
	 * @param string $name
	 * @param array|string $result
	 * @return boolean
	 */
	static public function tryGetChild($a, $name, &$result)
	{
		foreach($a as $node)
			if($node[self::NODENAME] == $name)
			{
				$result = $node;
				return true;
			}
		return false;
	}
}

?>