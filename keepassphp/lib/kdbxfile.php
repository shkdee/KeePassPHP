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

		$cipherType = $header->cipher === KdbxHeader::CIPHER_AES
			? MCRYPT_RIJNDAEL_128 : null;
		if($cipherType == null)
		{
			$error = "Kdbx file encrypt: unkown cipher.";
			return null;	
		}

		$hashedContent = HashedBlockReader::hashString($content, self::HASH);
		$transformedKey = self::transformKey($key, $header);
		$cipher = new CipherMcrypt($cipherType, 'cbc', $transformedKey,
			$header->encryptionIV, CipherMcrypt::PK7_PADDING);
		$encrypted = $cipher->encrypt($header->startBytes . $hashedContent);
		$cipher->unload();
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

		$cipherType = $header->cipher === KdbxHeader::CIPHER_AES
			? MCRYPT_RIJNDAEL_128 : null;
		if($cipherType == null)
		{
			$error = "Kdbx file decrypt: unkown cipher.";
			return null;	
		}

		$transformedKey = self::transformKey($key, $header);
		$cipher = new CipherMcrypt($cipherType, 'cbc', $transformedKey,
			$header->encryptionIV, CipherMcrypt::PK7_PADDING);
		$decrypted = $cipher->decrypt($reader->readToTheEnd());
		$cipher->unload();
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
	 * @return A 32-byte-long string that can be used as an AES key.
	 */
	private static function transformKey(iKey $key, KdbxHeader $header)
	{
		$keyHash = $key->getHash();
		$aesCipher = new CipherMcrypt(MCRYPT_RIJNDAEL_128, 'ecb',
			$header->transformSeed);
		// We have to do $rounds encryptions, where $rounds
		// is a 64 bit unsigned integer. Since PHP does not
		// handle 64 bit integers in a clear way, nor 32 bit
		// unsigned integers, it is safer to take $rounds as
		// an array of 4 short (16 bit) unsigned integers.
		$rounds = array_values(unpack("v4", $header->rounds));
		$loop = false;
		do
		{
			// Let's do a direct, very fast loop on the first coordinate
			// of $rounds (remove $rounds[0] from the integer represented by
			// $rounds).
			$l = $rounds[0];
			for($i = 0; $i < $l; $i++)
				$keyHash = $aesCipher->encrypt($keyHash);
			$rounds[0] = 0;
			// whether $rounds represents 0
			$loop = false;
			// Then, maybe remove 1 from the integer represented by $rounds,
			// knowing that $rounds[0] = 0.
			for($i = 1; $i < 4; $i++)
			{
				if($rounds[$i] > 0)
				{
					$rounds[$i]--;
					$keyHash = $aesCipher->encrypt($keyHash);
					for($j = $i - 1; $j >= 0; $j--)
						$rounds[$j] = 0xffff;
					$loop = true;
					break;
				}
			}
		} while($loop);

		$aesCipher->unload();
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