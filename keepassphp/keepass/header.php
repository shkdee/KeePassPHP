<?php

/**
 * The Header class is in charge of decoding
 * and checking the correctness of the header
 * of a .kdbx file (KeePass 2.x).
 *
 * @author Louis
 */
class Header
{
	public $cipher;
	public $compression;
	public $masterSeed;
	public $transformSeed;
	public $rounds;
	public $encryptionIV;
	public $randomStreamKey;
	public $startBytes;
	public $innerRandomStream;
	public $headerHash;
	
	const CIPHER_AES = "\x31\xC1\xF2\xE6\xBF\x71\x43\x50\xBE\x58\x05\x21\x6A\xFC\x5A\xFF";
	const COMPRESSION_NONE = 1;
	const COMPRESSION_GZIP = 2;
	const SEED_LEN = 32;
	const STARTBYTES_LEN = 32;
	const SIGNATURE1 = "\x03\xD9\xA2\x9A";
	const SIGNATURE2 = "\x67\xFB\x4B\xB5";
	const MINIMAL_VERSION = 3;
	const INNER_RANDOM_ARC4 = 1;
	const INNER_RANDOM_SALSA20 = 2;
	
	public function __construct()
	{
		$this->cipher = null;
		$this->compression = 0;
		$this->masterSeed = "";
		$this->transformSeed = "";
		$this->rounds = null;
		$this->encryptionIV = "";
		$this->randomStreamKey = "";
		$this->startBytes = "";
		$this->innerRandomStream = 0;
		$this->headerHash = "";
	}
	
	public function parse(Reader $reader)
	{
		$dreader = new DigestReader($reader);
		
		$sig1 = $dreader->readInt();
		$sig2 = $dreader->readInt();
		if(!$sig1->equalsString(self::SIGNATURE1) ||
			!$sig2->equalsString(self::SIGNATURE2))
		{
			KeePassPHP::printDebug("Bad database file !");
			return false;
		}

		$version = $dreader->readInt();
		if($version->lsr(2)->asShort() < self::MINIMAL_VERSION)
		{
			KeePassPHP::printDebug("Database version not supported !");
			return false;
		}

		$ended = false;       
		while(!$ended)
		{
			$headerId = $dreader->readByte()->asByte();
			$headerLen = $dreader->readShort()->asShort();
			$header = $dreader->read($headerLen);
			
			/*
			 * end of header
			 */
			if($headerId == 0)
				$ended = true;

			/*
			 * comment (not sure what to do with)
			 */
			elseif($headerId == 1)
				;

			/*
			 * cipher
			 */
			elseif($headerId == 2)
			{
				if(strcmp($header, self::CIPHER_AES) == 0)
					$this->cipher = new CipherMcrypt(CipherMcrypt::AES128);
			}

			/*
			 * CompressionFlags
			 */
			elseif($headerId == 3)
			{
				$res = Binary::fromString($header)->asInt();
				if($res == 0)
					$this->compression = self::COMPRESSION_NONE;
				elseif($res == 1)
					$this->compression = self::COMPRESSION_GZIP;
			}

			/*
			 *  MasterSeed
			 */
			elseif($headerId == 4)
			{
				if(strlen($header) == self::SEED_LEN)
					$this->masterSeed = $header;
			}

			 /*
			  * TransformSeed
			  */
			elseif($headerId == 5)
			{
				if(strlen($header) == self::SEED_LEN)
					$this->transformSeed = $header;
			}

			/*
			 * Number of rounds
			 */
			elseif($headerId == 6)
				$this->rounds = Binary::fromString($header, $headerLen);

			/*
			 * EncryptionIV
			 */
			elseif($headerId == 7)
				$this->encryptionIV = $header;

			/*
			 * ProtectedStreamKey
			 */
			elseif($headerId == 8)
				$this->randomStreamKey = $header;

			/*
			 * Stream start bytes
			 */
			elseif($headerId == 9)
			{
				if(strlen($header) == self::STARTBYTES_LEN)
					$this->startBytes = $header;
			}

			/*
			 * inner random stream
			 */
			elseif($headerId == 10)
			{
				$res = Binary::fromString($header)->asInt();
				/*if($res == 1) // unsuported
					$this->innerRandomStream= self::INNER_RANDOM_ARC4;
				else*/if($res == 2)
					$this->innerRandomStream = self::INNER_RANDOM_SALSA20;
			}
		}
		$this->headerHash = $dreader->GetDigest();
	}
	
	/**
	 * Returns true if every required information has
	 * been found in the header, and false otherwise.
	 */
	public function check()
	{
		if($this->cipher == null)
			return false;
		if($this->compression == 0)
			return false;
		if($this->masterSeed == "" ||
			strlen($this->masterSeed) != self::SEED_LEN)
			return false;
		if($this->transformSeed == "" ||
			strlen($this->transformSeed) != self::SEED_LEN)
			return false;
		if($this->rounds == null)
			return false;
		if($this->encryptionIV == "")
			return false;
		if($this->startBytes == "")
			return false;
		if($this->headerHash == "")
			return false;
		if($this->randomStreamKey == "")
			return false;
		if($this->innerRandomStream == 0)
			return false;
		return true;
	}

	/**
	 * Prints the header if debug mode is on.
	 */
	public function printHeader()
	{
		if(KeePassPHP::$debug)
		{
			echo "<pre>",
			"cipher := ", ($this->cipher == null ? "null" : CipherMcrypt::AES128),
			"\ncompression := ", $this->compression,
			"\nmasterSeed := ", Binary::fromString($this->masterSeed)->asHexString(),
			"\ntransformSeed := ", Binary::fromString($this->transformSeed)->asHexString(),
			"\nrounds := ", ($this->rounds == null ? "null" : ("0x".$this->rounds->asHexString())),
			"\nencryptionIV := ", Binary::fromString($this->encryptionIV)->asHexString(),
			"\nstreamStartBytes := ", Binary::fromString($this->startBytes)->asHexString(),
			"</pre>";
		}
	}
}   

?>