<?php

namespace KeePassPHP;

/**
 * Implementation of Readers, id est objects that can read data on demand from
 * a source, in the fashion of a stream in C# or Java.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */

/**
 * Base class for all readers. Instances of this class can read bytes from a
 * source, which produces them one by one until no more can be produced. The
 * end of the stream may not be known in advance. The backing data source can
 * be a string, a file, a network resource, a transformation of another reader,
 * etc.
 */
abstract class Reader
{
	/**
	 * Checks whether more bytes can be read from this instance.
	 * @return true if more bytes can be read, false otherwise.
	 */
	abstract public function canRead();

	/**
	 * Tries to read $n bytes from this instance. This method will read as many
	 * bytes as required, except if the underlying byte stream ends. It means
	 * that if the result does not contain $n bytes, there is no need to call
	 * this method again; this instance can no longer read new bytes.
	 * @return a string containing at most $n bytes, or null if no more bytes
	 *         can be read.
	 */
	abstract public function read($n);

	/**
	 * Reads all remaining bytes from this instance.
	 * @return a string containing all remaining bytes that this Read can read,
	 *         or null if no more bytes can be read.
	 */
	abstract public function readToTheEnd();

	/**
	 * Closes this instance, possibly dismissing the resources it was using.
	 */
	abstract public function close();

	/**
	 * Tries to read $n bytes from this instance, and return them as an
	 * integer (in little-endian).
	 * Note that depending on the platform, PHP may not be able to correctly
	 * handle integers greater than 2**31.
	 * @return at most $n bytes encoded into one integer, or 0 if no more
	 *         bytes can be read.
	 */
	public function readNumber($n)
	{
		$s = $this->read($n);
		$l = strlen($s);
		$r = 0;
		for($i = 0; $i < $l; $i++)
			$r += ord($s[$i]) << (8*$i);
		return $r;
	}

	/**
	 * Tries to read one (1) byte from this instance, and return it as
	 * an integer.
	 * @return one read byte as an integer, or 0 if no more bytes can be read.
	 */
	public function readByte()
	{
		$s = $this->read(1);
		return empty($s) ? 0 : ord($s[0]);
	}
}

/**
 * An implementation of the Reader class, using a string as source.
 */
class StringReader extends Reader
{
	private $_str;
	private $_n;
	private $_pt;

	/**
	 * Constructs a new StringReader instance that reads the string $s.
	 * @param $s A non-null string.
	 */
	public function __construct($s)
	{
		$this->_str = $s;
		$this->_pt = 0;
		$this->_n = strlen($s);
	}

	public function read($n)
	{
		if(!$this->canRead())
			return null;

		$t = min($n, $this->_n - $this->_pt);
		$res = substr($this->_str, $this->_pt, $t);
		$this->_pt += $t;
		return $res;
	}

	public function canRead()
	{
		return $this->_pt < $this->_n;
	}

	public function readToTheEnd()
	{
		if(!$this->canRead())
			return null;

		$res = substr($this->_str, $this->_pt);
		$this->_pt = $this->_n;
		return $res;
	}
	
	public function close()
	{
		$this->_str = null;
		$this->_n = 0;
		$this->_pt = 0;
	}
}

/**
 * A Reader implementation reading from a PHP resource pointer (such as a
 * pointer obtained through the function fopen).
 */
class ResourceReader extends Reader
{
	private $_res;

	/**
	 * Constructs a new ResourceReader instance that reads the PHP resource
	 * pointer $f.
	 * @param $f A PHP resource pointer.
	 */
	public function __construct($f)
	{
		$this->_res = $f;
	}

	/**
	 * Creates a new ResourceReader instance reading the file $path.
	 * @param $path A file path.
	 * @return A new ResourceReader instance if $path could be opened and is
	 *         readable, false otherwise.
	 */
	static public function openFile($path)
	{
		if(is_readable($path))
		{
			$f = fopen($path, 'rb');
			if($f !== false)
				return new ResourceReader($f);
		}
		return null;
	}

	public function read($n)
	{
		if($this->canRead())
		{
			$s = fread($this->_res, $n);
			if($s !== false)
				return $s;
		}
		return null;
	}

	public function readToTheEnd()
	{
		if(!$this->canRead())
			return null;
		
		ob_start();
		fpassthru($this->_res);
		$r = ob_get_contents();
		ob_end_clean();
		return $r;
	}

	public function canRead()
	{
		return !feof($this->_res);
	}
	
	public function close()
	{
		fclose($this->_res);
	}
}

/**
 * A Reader implementation, backed by another reader, which can compute the
 * hash of all the read data.
 */
class DigestReader extends Reader
{
	private $_base;
	private $_resource;
	
	/**
	 * Constructs a new DigestReader implementation, reading from the Reader
	 * $reader and hashing all data with the algorithm $hashAlgo.
	 * @param $reader A Reader instance.
	 * @param $hashAlgo A hash algorithm name.
	 */
	public function __construct(Reader $reader, $hashAlgo)
	{
		$this->_base = $reader;
		$this->_resource = hash_init($hashAlgo);
	}

	public function read($n)
	{
		$s = $this->_base->read($n);
		if($s !== null)
		{
			hash_update($this->_resource, $s);
			return $s;
		}
		return null;
	}

	public function readToTheEnd()
	{
		$s = $this->_base->readToTheEnd();
		if($s !== null)
		{
			hash_update($$this->_resource, $s);
			return $s;
		}
		return null;
	}

	public function canRead()
	{
		return $this->_base->canRead();
	}
	
	public function close()
	{
		$this->_base->close();
	}
	
	/**
	 * Gets the hash of all read data so far.
	 * @return A raw hash string.
	 */
	public function GetDigest()
	{
		return hash_final($this->_resource, true);
	}
}

/**
 * A Reader implementation, backed by another reader, decoding a stream made
 * of hashed blocks (used by KeePass). More precisely, it is a sequence of
 * blocks, each block containing some data and a hash of this data, in order to
 * control its integrity. The format of a block is the following:
 * - 4 bytes (little-endian integer): block index (starting from 0)
 * - 32 bytes: hash of the block data
 * - 4 bytes (little-endian integer): length (in bytes) of the block data
 * - n bytes: block data (where n is the number found previously)
 */
class HashedBlockReader extends Reader
{
	private $_base;
	private $_hashAlgo;
	private $_hasError;
	private $_stopOnError;    
	private $_currentIndex;
	private $_currentBlock;
	private $_currentSize;
	private $_currentPos;

	/**
	 * Default block size used by KeePass.
	 */
	const DEFAULT_BLOCK_SIZE = 1048576; // 1024*1024

	/**
	 * Constructs a new HashedBlockReader instance, reading from the reader
	 * $reader and using the algorithm $hashAlgo to compute block hashs.
	 * @param $reader A Reader instance.
	 * @param $hashAlgo A hash algorithm name.
	 * @param $stopOnError Whether to stop reading immediatly when an integrity
	 *        check fails. If set to false, reading will continue after an
	 *        error but it may well be complete garbage.
	 */
	public function __construct(Reader $reader, $hashAlgo, $stopOnError = true)
	{
		$this->_base = $reader;
		$this->_hashAlgo = $hashAlgo;
		$this->_stopOnError = $stopOnError;
		$this->_hasError = false;
		$this->_currentIndex = 0;
		$this->_currentBlock = null;
		$this->_currentSize = 0;
		$this->_currentPos = 0;
	}

	public function read($n)
	{
		$s = "";
		$remaining = $n;
		while($remaining > 0)
		{
			if($this->_currentPos >= $this->_currentSize)
				if(!$this->readBlock())
					return $s;
			$t = min($remaining, $this->_currentSize - $this->_currentPos);
			$s .= substr($this->_currentBlock, $this->_currentPos, $t);
			$this->_currentPos += $t;
			$remaining -= $t;
		}
		return $s;
	}

	public function readToTheEnd()
	{
		$s = $this->read($this->_currentSize - $this->_currentPos);
		while($this->readBlock())
			$s .= $this->_currentBlock;
		return $s;
	}

	public function canRead()
	{
		return (!$this->_hasError || !$this->_stopOnError) &&
			$this->_base->canRead();
	}

	public function close()
	{
		$this->_base->close();
	}

	/**
	 * Whether this instance data is corrupted.
	 * @return true if the data read so far is corrupted, false otherwise.
	 */
	public function isCorrupted()
	{
		return $this->_hasError;
	}

	private function readBlock()
	{
		if(!$this->canRead())
			return false;

		$bl = $this->_base->read(4);
		if($bl != pack('V', $this->_currentIndex))
		{
			$this->_hasError = true;
			if($this->_stopOnError)
				return false;
		}
		$this->_currentIndex++;

		$hash = $this->_base->read(32);
		if(strlen($hash) != 32)
		{
			$this->_hasError = true;
			return false;
		}

		// May not work on 32 bit platforms if $blockSize is greather
		// than 2**31, but in KeePass implementation it is set at 2**20.
		$blockSize = $this->_base->readNumber(4);
		if($blockSize <= 0)
			return false;
		
		$block = $this->_base->read($blockSize);
		if(strlen($block) != $blockSize)
		{
			$this->_hasError = true;
			return false;
		}

		if($hash !== hash($this->_hashAlgo, $block, true))
		{
			$this->_hasError = true;
			if($this->_stopOnError)
				return false;
		}
		
		$this->_currentBlock = $block;
		$this->_currentSize = $blockSize;
		$this->_currentPos = 0;
		return true;
	}

	/**
	 * Computes the hashed-by-blocks version of the string $source: splits it
	 * in blocks, computes each block hash, and concats everything together in
	 * a string that can be read again with a HashedBlockReader instance.
	 * @param $source The string to hash by blocks.
	 * @param $hashAlgo A hash algorithm name.
	 * @return The hashed-by-blocks version of $source.
	 */
	public static function hashString($source, $hashAlgo)
	{
		$len = strlen($source);
		$blockSize = self::DEFAULT_BLOCK_SIZE;
		$binBlockSize = pack("V", $blockSize);
		$r = "";

		$blockIndex = 0;
		$i = 0;
		while($len >= $i + $blockSize)
		{
			$block = substr($source, $i, $blockSize);
			$r .= pack("V", $blockIndex)
				. hash($hashAlgo, $block, true)
				. $binBlockSize
				. $block;
			$i += $blockSize;
			$blockIndex++;
		}
		$rem = $len - $i;
		if($rem != 0) {
			$block = substr($source, $i);
			$r .= pack("V", $blockIndex)
				. hash($hashAlgo, $block, true)
				. pack("V", strlen($block))
				. $block;
		}
		return $r;
	}
}

?>