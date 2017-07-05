<?php

namespace KeePassPHP;

/**
 * A class that manages a Kdbx file, which is mainly an encryptable text
 * content and a KdbxHeader that describes how to encrypt or decrypt that
 * content.
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class KdbxFile
{
	private $_header;
	private $_headerBinary;
	private $_content;
	private $_randomStream;

	const SALSA20_IV = "\xE8\x30\x09\x4B\x97\x20\x5D\x2A";
	const CIPHER_LEN = 16;
	const SEED_LEN = 32;
	const STARTBYTES_LEN = 32;
	const ROUNDS_LEN = 8;

	const HASH = 'SHA256';

	/**
	 * Creates a new KdbxFile instance with the given KdbxHeader instance,
	 * and completely empty otherwise.
	 */
	public function __construct(KdbxHeader $header)
	{
		$this->_header = $header;
		$this->_randomStream = null;
		$this->_content = null;
		$this->_headerBinary = null;
	}

	/**
	 * Gets the header instance.
	 * @return A KdbxHeader instance.
	 */
	public function getHeader()
	{
		return $this->_header;
	}

	/**
	 * Gets the header hash.
	 * @return A 32-byte-long hash.
	 */
	public function getHeaderHash()
	{
		return $this->_header->headerHash;
	}

	/**
	 * Gets the content of this instance, if already set (if encrypt or decrypt
	 * has been called).
	 * @return A string.
	 */
	public function getContent()
	{
		return $this->_content;
	}

	/**
	 * Gets the random stream defined by this instance header.
	 * @return An iRandomStream instance.
	 */
	public function getRandomStream()
	{
		return $this->_randomStream;
	}

	/**
	 * Prepares the encryption of this instance by generating new random
	 * strings for the header, serializing the header and computing its hash.
	 * Non-random header fields must be set before calling this method.
	 * @param &$error A string that will receive a message in case of error.
	 * @return true if everything went well and the encrypt method can be
	 *         called, false otherwise.
	 */
	public function prepareEncrypting(&$error)
	{
		$header = $this->getHeader();
		$header->masterSeed = random_bytes(self::SEED_LEN);
		$header->transformSeed = random_bytes(self::SEED_LEN);
		$header->encryptionIV = random_bytes(16);
		$header->randomStreamKey = random_bytes(self::SEED_LEN);
		$header->startBytes = random_bytes(self::STARTBYTES_LEN);

		if($header->randomStream == KdbxHeader::RANDOMSTREAM_SALSA20)
		{
			$this->_randomStream = Salsa20Stream::create(
				hash(self::HASH, $header->randomStreamKey, true),
				self::SALSA20_IV);
			if($this->_randomStream == null)
			{
				$error = "Kdbx file encrypt: random stream parameters error.";
				return false;
			}
		}

		$result = $header->toBinary(self::HASH);

		if(!self::headerCheck($header))
		{
			$error = "Kdbx file encrypt: header check failed.";
			return false;
		}

		$this->_headerBinary = $result;
		return true;
	}

	/**
	 * Encrypts $content with $key and the header of this KdbxFile instance.
	 * @param $content A string to encrypt.
	 * @param $key A iKey instance to use as encryption key.
	 * @param &$error A string that will receive a message in case of error.
	 * @return A binary string containing the encrypted Kdbx file, or null in
	 *         case of error.
	 */
	public function encrypt($content, iKey $key, &$error)
	{
		if(empty($content))
		{
			$error = "Kdbx file encrypt: empty content.";
			return null;
		}

		if(empty($this->_headerBinary))
		{
			$error = "Kdbx file encrypt: encryption not prepared.";
			return null;
		}

		$header = $this->getHeader();
		if($header->compression == KdbxHeader::COMPRESSION_GZIP)
		{
			$error = "Kdbx file encrypt: gzip compression not yet supported.";
			return null;
		}

		$cipherMethod = $header->cipher === KdbxHeader::CIPHER_AES
			? 'aes-256-cbc' : null;
		if($cipherMethod === null)
		{
			$error = "Kdbx file encrypt: unkown cipher.";
			return null;
		}

		$hashedContent = HashedBlockReader::hashString($content, self::HASH);
		$transformedKey = self::transformKey($key, $header);
		$cipher = Cipher::Create($cipherMethod, $transformedKey,
			$header->encryptionIV);
		if($cipher == null || $transformedKey == null)
		{
			$error = "Kdbx file encrypt: cannot create cipher (no suitable cryptography extension found).";
			return null;
		}
		$encrypted = $cipher->encrypt($header->startBytes . $hashedContent);
		if(empty($encrypted))
		{
			$error = "Kdbx file encrypt: encryption failed.";
			return null;
		}

		$this->_content = $content;
		$r = $this->_headerBinary;
		$this->_headerBinary = null;
		return $r . $encrypted;
	}

	/**
	 * Creates a new KdbxFile instance, sets its header with $rounds rounds of
	 * AES encryption, no compression and no random stream, and prepares the
	 * encryption.
	 * @param &$error A string that will receive a message in case of error.
	 * @return A new KdbxFile instance ready to be encrypted.
	 */
	public static function createForEncrypting($rounds, &$error)
	{
		$rounds = intval($rounds);
		if($rounds <= 0)
		{
			$error = "Kdbx file encrypt: rounds must be strictly positive.";
			return null;
		}

		$header = new KdbxHeader();
		$header->cipher = KdbxHeader::CIPHER_AES;
		$header->compression = KdbxHeader::COMPRESSION_NONE;
		$header->randomStream = KdbxHeader::RANDOMSTREAM_NONE;
		$header->rounds = pack('V', $rounds) . "\x00\x00\x00\x00";
		$file = new KdbxFile($header);
		return $file->prepareEncrypting($rounds, $error) ? $file : null;
	}

	/**
	 * Decrypts an encrypted Kdbx file with $key.
	 * @param $reader A Reader instance that reads a Kdbx file.
	 * @param $key The encryption key of the Kdbx file.
	 * @param &$error A string that will receive a message in case of error.
	 * @return A new KdbxFile instance containing the decrypted content,
	 *         header and random stream (if applicable), or null if something
	 *         went wrong.
	 */
	public static function decrypt(Reader $reader, iKey $key, &$error)
	{
		if($reader == null)
		{
			$error = "Kdbx file decrypt: reader is null.";
			return null;
		}

		$header = KdbxHeader::load($reader, self::HASH, $error);
		if($header == null)
			return null;

		if(!self::headerCheck($header, true))
		{
			$error = "Kdbx file decrypt: header check failed.";
			return null;
		}

		$randomStream = null;
		if($header->randomStream == KdbxHeader::RANDOMSTREAM_SALSA20)
		{
			$randomStream = Salsa20Stream::create(
				hash(self::HASH, $header->randomStreamKey, true),
				self::SALSA20_IV);
			if($randomStream == null)
			{
				$error = "Kdbx file decrypt: random stream parameters error.";
				return null;
			}
		}

		$cipherMethod = $header->cipher === KdbxHeader::CIPHER_AES
			? 'aes-256-cbc' : null;
		if($cipherMethod === null)
		{
			$error = "Kdbx file decrypt: unkown cipher.";
			return null;
		}

		$transformedKey = self::transformKey($key, $header);
		$cipher = Cipher::Create($cipherMethod, $transformedKey,
			$header->encryptionIV);
		if($cipher == null || $transformedKey == null)
		{
			$error = "Kdbx file decrypt: cannot create cipher (no suitable cryptography extension found).";
			return null;
		}
		$decrypted = $cipher->decrypt($reader->readToTheEnd());
		if(empty($decrypted) || substr($decrypted, 0, self::STARTBYTES_LEN)
			!== $header->startBytes)
		{
			$error = "Kdbx file decrypt: decryption failed.";
			return null;
		}

		$hashedReader = new HashedBlockReader(
				new StringReader(substr($decrypted, self::STARTBYTES_LEN)),
				self::HASH);
		$decoded = $hashedReader->readToTheEnd();
		$hashedReader->close();
		if(strlen($decoded) == 0 || $hashedReader->isCorrupted())
		{
			$error = "Kdbx file decrypt: integrity check failed.";
			return null;
		}

		if($header->compression == KdbxHeader::COMPRESSION_GZIP)
		{
			$filename = null;
			$gzerror = null;
			$decoded = gzdecode2($decoded, $filename, $gzerror);
			if(strlen($decoded) == 0)
			{
				$error = "Kdbx file decrypt: ungzip error: " . $gzerror . ".";
				return null;
			}
		}

		$file = new KdbxFile($header);
		$file->_content = $decoded;
		$file->_randomStream = $randomStream; 
		return $file;
	}

	/**
	 * Computes the AES encryption key of a Kdbx file from its keys and header.
	 * @param $key The encryption key.
	 * @param $header The Kdbx file header.
	 * @return A 32-byte-long string that can be used as an AES key, or null
	 *         if no suitable cryptography extension is laoded.
	 */
	private static function transformKey(iKey $key, KdbxHeader $header)
	{
		$keyHash = $key->getHash();
		$cipher = Cipher::Create('aes-256-ecb', $header->transformSeed,
			"", Cipher::PADDING_NONE);
		if($cipher == null)
			return null;
		// We have to do $rounds encryptions, where $rounds is a 64 bit
		// unsigned integer. Since PHP does not handle 64 bit integers in a
		// clear way, nor 32 bit unsigned integers, it is safer to take
		// $rounds as an array of 4 short (16 bit) unsigned integers.
		// Remember that $rounds is encoded in little-endian.
		$rounds = array_values(unpack("v4", $header->rounds));
		// To go even faster, represent $rounds in base 2**30 by only three
		// signed integers, that PHP should handle correctly. $o, $t and $h
		// will respectively be ones, tens and hundrers. $o and $t each take 30
		// bits, $h takes the remaining 4.
		$o = $rounds[0] | (($rounds[1] & 0x3fff) << 16);
		$t = (($rounds[1] & 0xc000) >> 14) | ($rounds[2] << 2) |
			(($rounds[3] & 0x0fff) << 18);
		$h = ($rounds[3] & 0xf000) >> 12;
		// So virtually, the number of rounds is $o + ($t << 30) + ($h << 60).
		$loop = false;
		do
		{
			// Let's do a direct, very fast loop on the ones $o
			if($o > 0)
				$keyHash = $cipher->encryptManyTimes($keyHash, $o);
			// whether there is still some rounds to perform
			$loop = false;
			// then, remove 1 from the number of rounds (that's just a
			// substraction in base 2**30 of a 3-digit number), knowing that
			// $o equals 0.
			if($t > 0)
			{
				$t--;
				// We set $o to (2**30 - 1) + 1 = 2**30 because we still
				// have to do the encryption round that we're currently
				// substracting. So we don't really do a substraction, we
				// just write the number differently. That's also why we
				// chose to represent $rounds in base 2**30 rather than 2**31.
				$o = 0x40000000;
				$loop = true;
			}
			else if($h > 0)
			{
				$h--;
				$t = 0x3fffffff;
				// same as above
				$o = 0x40000000;
				$loop = true;
			}
		} while($loop);

		$finalKey = hash(self::HASH, $keyHash, true);
		return hash(self::HASH, $header->masterSeed . $finalKey, true);
	}

	/**
	 * Checks that the $header is valid for a Kdbx file.
	 * @param $header A KdbxHeader instance.
	 * @return true if the header is valid, false otherwise.
	 */
	private static function headerCheck(KdbxHeader $header)
	{
		return strlen($header->cipher) == self::CIPHER_LEN
			&& $header->compression !== 0
			&& strlen($header->masterSeed) == self::SEED_LEN
			&& strlen($header->transformSeed) == self::SEED_LEN
			&& strlen($header->rounds) == self::ROUNDS_LEN
			&& $header->encryptionIV !== null
			&& strlen($header->startBytes) == self::STARTBYTES_LEN
			&& $header->headerHash !== null
			&& $header->randomStreamKey !== null
			&& $header->randomStream !== 0;
	}
}

?>
