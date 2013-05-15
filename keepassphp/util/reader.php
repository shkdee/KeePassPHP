<?php

/**
 * Abstract Reader, describing a Reader class
 * and adding some useful methods for reading
 * binary numbers.
 */
abstract class Reader
{
	abstract public function canRead();
	abstract public function read($n);
	abstract public function readToTheEnd();
	abstract public function close();
	
	public function readBinary($n)
	{
		$s = $this->read($n);
		return Binary::fromString($s, $n);
	}
	
	public function readInt()
	{
		$s = $this->read(4);
		return Binary::fromString($s, 4);
	}

	public function readShort()
	{
		$s = $this->read(2);
		return Binary::fromString($s, 2);
	}

	public function readByte()
	{
		$s = $this->read(1);
		return Binary::fromString($s, 1);
	}
}

/**
 * An implementation of the Reader class,
 * using a string as read material. The
 * string is expected to be binary.
 */
class StringReader extends Reader
{
	public $str;
	private $n;
	private $pt;

	public function __construct($s)
	{
		$this->str = $s;
		$this->pt = 0;
		$this->n = strlen($s);
	}

	public function read($n)
	{
		if(!$this->canRead())
			return null;

		$t = min($n, $this->n - $this->pt);
		$res = substr($this->str, $this->pt, $t);
		$this->pt += $t;
		return $res;
	}

	public function canRead()
	{
		return $this->pt < $this->n;
	}

	public function readToTheEnd()
	{
		if(!$this->canRead())
			return null;

		$res = substr($this->str, $this->pt);
		$this->pt = $this->n;
		return $res;
	}
	
	public function close()
	{
		$this->str = null;
		$this->n = 0;
		$this->pt = 0;
	}
}

/**
 * A Reader implementation, reading from
 * a PHP resource pointer (like a pointer
 * obtained when opening a file with fopen).
 */
class RessourceReader extends Reader
{
	private $res;

	public function __construct($f)
	{
		$this->res = $f;
	}

	static public function openFile($name)
	{
		if(is_readable($name))
		{
			$f = fopen($name, 'rb');
			if($f !== FALSE)
				return new RessourceReader($f);
		}
		return null;
	}

	public function read($n)
	{
		if($this->canRead())
		{
			$s = fread($this->res, $n);
			if($s !== FALSE)
				return $s;
		}
		return null;
	}

	public function readToTheEnd()
	{
		if(!$this->canRead())
			return null;
		
		ob_start();
		fpassthru($this->res);
		$r = ob_get_contents();
		ob_end_clean();
		return $r;        
	}

	public function canRead()
	{
		return !feof($this->res);
	}
	
	public function close()
	{
		fclose($this->res);
	}
}

/**
 * A Reader implementation, backed by
 * another reader, which keeps all the read
 * data to compute its hash.
 */
class DigestReader extends Reader
{
	private $resource;
	public $base;
	
	public function __construct(Reader $r, $algo = null)
	{
		$this->base = $r;
		$this->resource = hash_init($algo === null ? HashHouse::$algo : $algo);
	}

	public function read($n)
	{
		$s = $this->base->read($n);
		if($s !== null)
		{
			hash_update($this->resource, $s);
			return $s;
		}
		return null;
	}

	public function readToTheEnd()
	{
		$s = $this->base->readToTheEnd();
		if($s !== null)
		{
			hash_update($$this->resource, $s);
			return $s;
		}
		return null;
	}

	public function canRead()
	{
		return $this->base->canRead();
	}
	
	public function close()
	{
		$this->base->close();
	}
	
	public function GetDigest()
	{
		return hash_final($this->resource, true);
	}
}

/**
 * A Reader implementation, backed by another reader,
 * decoding a stream made of hashed blocks (used by
 * KeePass). More precisely, it is a sequence of blocks,
 * with one block containing both its data and a hash of
 * that data, in order to control its integrity. The format
 * of a block is the following :
 * - 4 bytes (integer) : block index (starting from 0)
 * - 32 bytes : hash of the block data
 * - 4 bytes (integer) : length (in bytes) of the block data
 * - n bytes : block data, where n is the number given the line below,
 *             and whose hash should equal the onde read before.
 */
class HashedBlockReader extends Reader
{
	public $base;

	private $h;
	private $verify;    
	private $currentIndex;
	private $currentBlock;
	private $currentSize;
	private $currentPos;

	public function __construct(Reader $r, iHashAlgo $h, $verify = true)
	{
		$this->base = $r;
		$this->h = $h;
		$this->verify = $verify;
		$this->currentIndex = 0;
		$this->currentBlock = null;
		$this->currentSize = 0;
		$this->currentPos = 0;
	}

	public function read($n)
	{
		$s = "";
		$remaining = $n;
		while($remaining > 0)
		{
			if($this->currentPos >= $this->currentSize)
				if(!$this->readBlock())
					return $s;
			$t = min($remaining, $this->currentSize - $this->currentPos);
			$s .= substr($this->currentBlock, $this->currentPos, $t);
			$this->currentPos += $t;
			$remaining -= $t;
		}
		return $s;
	}

	public function readToTheEnd()
	{
		$s = $this->read($this->currentSize - $this->currentPos);
		while($this->readBlock())
			$s .= $this->currentBlock;
		return $s;
	}

	public function canRead()
	{
		return $this->base->canRead();
	}

	public function close()
	{
		$this->base->close();
	}

	private function readBlock()
	{
		if(!$this->canRead())
			return false;

		$bl = $this->base->readInt();
		if(!$bl->equalsInt($this->currentIndex))
			return false;
		$this->currentIndex++;

		$hash = $this->base->read(32);
		if($hash == null || strlen($hash) != 32)
			return false;

		// Won't work if $blockSize is bigger than 2**31
		$blockSize = $this->base->readInt()->asInt();
		if($blockSize <= 0)
			return false;
		
		$block = $this->base->read($blockSize);
		if($block == null || strlen($block) != $blockSize)
			return false;

		if($this->verify && strcmp($hash, $this->h->hash($block)) != 0)
		{
			KeePassPHP::printDebug("Corrupted data !");
			return false;
		}
		
		$this->currentBlock = $block;
		$this->currentSize = $blockSize;
		$this->currentPos = 0;
		return true;
	}
}

?>