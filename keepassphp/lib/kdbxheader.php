<?php

namespace KeePassPHP;

/**
 * This class represents the header of a Kdbx file, which is the un-encrypted
 * part of the file containing information on the encrypted content, on
 * how to decrypt it, and some integrity data.
 * This class can write and parse headers, to and from their specific binary
 * format. It is rather loose in what it accepts as a header, to be more
 * generic. The class KdbxFile performs more thorough checks on the header
 * content, to make sure it respects the contraints of a Kdbx file.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class KdbxHeader
{
	/** A binary string identifying the cipher used to encrypt the file. */
	public $cipher;
	/** An integer identifying the algorithm used to compress the file. */
	public $compression;
	/** Master seed for the file encryption key. */
	public $masterSeed;
	/** Specific seed to compute the file encryption key. */
	public $transformSeed;
	/** Number of cipher rounds to perform to compute the file encryption key. */
	public $rounds;
	/** The IV to use to decrypt the file. */
	public $encryptionIV;
	/** The specific initializing key for possible random stream. */
	public $randomStreamKey;
	/** The first bytes of the decrypted file (before un-compressing). */
	public $startBytes;
	/** An integer identifying the random stream generator to use. */
	public $randomStream;
	/** The hash of the binary format of the header. */
	public $headerHash;

	const SIGNATURE1 = "\x03\xD9\xA2\x9A";
	const SIGNATURE2 = "\x67\xFB\x4B\xB5";
	const VERSION = "\x01\x00\x03\x00";
	const MAXIMAL_VERSION = 3;

	const CIPHER_AES = "\x31\xC1\xF2\xE6\xBF\x71\x43\x50\xBE\x58\x05\x21\x6A\xFC\x5A\xFF";
	
	const COMPRESSION_NONE = 1;
	const COMPRESSION_GZIP = 2;
	const RANDOMSTREAM_NONE = 1;
	//const RANDOMSTREAM_ARC4 = 2;
	const RANDOMSTREAM_SALSA20 = 3;

	const INT_0 = "\x00\x00\x00\x00";
	const INT_1 = "\x01\x00\x00\x00";
	const INT_2 = "\x02\x00\x00\x00";

	public function __construct()
	{
		$this->cipher = null;
		$this->compression = 0;
		$this->masterSeed = null;
		$this->transformSeed = null;
		$this->rounds = null;
		$this->encryptionIV = null;
		$this->randomStreamKey = null;
		$this->startBytes = null;
		$this->headerHash = null;
		$this->randomStream = 0;
	}

	/**
	 * Gets the binary format of this Header instance, and computes its hash.
	 * @param $hashAlgo The hash algorithm to use to compute the header hash.
	 * @return A binary string representing this Header instance.
	 */
	public function toBinary($hashAlgo)
	{
		$s = self::SIGNATURE1 . self::SIGNATURE2 . self::VERSION
			. self::fieldToString(2, $this->cipher)
			. self::fieldToString(3,
			$this->compression == self::COMPRESSION_GZIP
				? self::INT_1 : self::INT_0)
			. self::fieldToString(4, $this->masterSeed)
			. self::fieldToString(5, $this->transformSeed)
			. self::fieldToString(6, $this->rounds)
			. self::fieldToString(7, $this->encryptionIV)
			. self::fieldToString(8, $this->randomStreamKey)
			. self::fieldToString(9, $this->startBytes)
			. self::fieldToString(10,
			$this->randomStream == self::RANDOMSTREAM_SALSA20
				? self::INT_2 : self::INT_0)
			. self::fieldToString(0, null);
		$this->headerHash = hash($hashAlgo, $s, true);
		return $s;
	}

	/**
	 * Gets the binary format of the given header field.
	 * @param $id The field id.
	 * @param $value The field value.
	 * @return A binary string representing the header field.
	 */
	private static function fieldToString($id, $value)
	{
		$l = strlen($value);
		return chr($id) . ($l == 0 ? "\x00\x00" : (pack("v", $l) . $value));
	}

	/**
	 * Checks whether all fields are set in this instance.
	 * @return true if all fields are set, false otherwise.
	 */
	public function check()
	{
		if($this->cipher === null)
			return false;
		if($this->compression === 0)
			return false;
		if($this->masterSeed === null)
			return false;
		if($this->transformSeed === null)
			return false;
		if($this->rounds === null)
			return false;
		if($this->encryptionIV === null)
			return false;
		if($this->startBytes === null)
			return false;
		if($this->headerHash === null)
			return false;
		if($this->randomStreamKey === null)
			return false;
		if($this->randomStream === 0)
			return false;
		return true;
	}
	
	/**
	 * Parses the content of a Reader as a KdbxHeader in binary format.
	 * @param $reader A Reader that reads the header.
	 * @param $hashAlgo The hash algorithm to use to compute the header hash.
	 * @param &$error A string that will receive a message in case of error.
	 * @return A new KdbxHeader instance if it could be correctly parsed from
	 *         the reader, and null otherwise.
	 */
	public static function load(Reader $reader, $hashAlgo, &$error)
	{
		$dreader = new DigestReader($reader, $hashAlgo);
		
		$sig1 = $dreader->read(4);
		$sig2 = $dreader->read(4);
		if($sig1 != self::SIGNATURE1 || $sig2 != self::SIGNATURE2)
		{
			$error = "Kdbx header: signature not correct.";
			return null;
		}

		$lowerversion = $dreader->readNumber(2);
		$upperversion = $dreader->readNumber(2);
		if($upperversion > self::MAXIMAL_VERSION)
		{
			$error = "Kdbx header: version not supported.";
			return null;
		}

		$header = new KdbxHeader();
		$ended = false;
		while(!$ended)
		{
			$fieldId = $dreader->readByte();
			$fieldLen = $dreader->readNumber(2);
			$field = null;
			if($fieldLen > 0)
			{
				$field = $dreader->read($fieldLen);
				if($field == null || strlen($field) != $fieldLen)
				{
					$error = "Kdbx header: uncomplete header field.";
					return null;
				}
			}
			
			/*
			 * end of header
			 */
			if($fieldId == 0)
				$ended = true;

			/*
			 * comment (let's ignore)
			 */
			//elseif($fieldId == 1)
			//	;

			/*
			 * Cipher type
			 */
			elseif($fieldId == 2)
				$header->cipher = $field;

			/*
			 * Compression method
			 */
			elseif($fieldId == 3)
			{
				if($field == self::INT_0)
					$header->compression = self::COMPRESSION_NONE;
				elseif($field == self::INT_1)
					$header->compression = self::COMPRESSION_GZIP;
			}

			/*
			 *  MasterSeed
			 */
			elseif($fieldId == 4)
				$header->masterSeed = $field;

			 /*
			  * TransformSeed
			  */
			elseif($fieldId == 5)
				$header->transformSeed = $field;

			/*
			 * Number of rounds
			 */
			elseif($fieldId == 6)
				$header->rounds = $field;

			/*
			 * EncryptionIV
			 */
			elseif($fieldId == 7)
				$header->encryptionIV = $field;

			/*
			 * Random stream key
			 */
			elseif($fieldId == 8)
				$header->randomStreamKey = $field;

			/*
			 * First bytes of result
			 */
			elseif($fieldId == 9)
				$header->startBytes = $field;

			/*
			 * Random stream type
			 */
			elseif($fieldId == 10)
			{
				if($field == self::INT_0)
					$header->randomStream = self::RANDOMSTREAM_NONE;
				elseif($field == self::INT_2)
					$header->randomStream = self::RANDOMSTREAM_SALSA20;
				/*elseif($field == self::INT_1) // unsuported
					$header->randomStream= self::RANDOMSTREAM_ARC4;*/
			}
		}
		$header->headerHash = $dreader->GetDigest();
		$error = null;
		return $header;
	}
}

?>