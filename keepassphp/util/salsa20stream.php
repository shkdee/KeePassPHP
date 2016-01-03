<?php

namespace KeePassPHP;

/**
 * An object that can randomly generate bytes.
 */
interface iRandomStream
{
	/**
	 * Generates $n random bytes and returns them as a string.
	 * @param $n The number of bytes to generate.
	 * @return A $n-long string.
	 */
	public function getNextBytes($n);
}

/**
 * Salsa20 stream pure PHP implementation.
 * To avoid weird interaction with PHP's integers, only 16 bit integers are
 * used (that's a bit heavy, but it should work regardless of the platform).
 *
 * @package    KeePassPHP
 * @author     Louis Traynard <louis.traynard@m4x.org>
 * @copyright  Louis Traynard
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       https://github.com/shkdee/KeePassPHP
 */
class Salsa20Stream implements iRandomStream
{
	private $_state;
	private $_output;
	private $_outputPos;

	const STATE_LEN = 32;
	const KEY_LEN = 32;
	const OUTPUT_LEN = 64;
	const IV_LEN = 8;

	/**
	 * Creates a new Salsa20Stream instance.
	 * @param $key The 32-byte-long string to use as key.
	 * @param $iv The 8-byte-long string to use as initialization vector.
	 * @return A new Salsa20Stream instance, of null if $key or $iv do not have
	 *         a suitable length.
	 */
	public static function create($key, $iv)
	{
		if (strlen($key) != self::KEY_LEN || strlen($iv) != self::IV_LEN)
			return null;
		return new Salsa20Stream($key, $iv);
	}

	private function __construct($key, $iv)
	{
		$this->_state = array();
		for ($i = 0; $i < self::STATE_LEN; $i++)
			$this->_state[$i] = 0;

		$this->_output = array();
		for ($i = 0; $i < self::OUTPUT_LEN; $i++)
			$this->_output[$i] = 0;

		$this->_outputPos = self::OUTPUT_LEN;
		$this->keySetup(array_values(unpack("v16", $key)));
		$this->ivSetup(array_values(unpack("v4", $iv)));
	}

	private function keySetup(array $key)
	{
		for ($i = 0; $i < 4; $i++)
		{
			$j = 2 * $i;
			$this->_state[2 * $i + 2] = $key[$j];
			$this->_state[2 * $i + 3] = $key[$j + 1];
			$this->_state[2 * $i + 22] = $key[$j + 8];
			$this->_state[2 * $i + 23] = $key[$j + 9];
		}
		$this->_state[0] = 0x7865;
		$this->_state[1] = 0x6170;
		$this->_state[10] = 0x646E;
		$this->_state[11] = 0x3320;
		$this->_state[20] = 0x2D32;
		$this->_state[21] = 0x7962;
		$this->_state[30] = 0x6574;
		$this->_state[31] = 0x6B20;
	}

	private function ivSetup(array $iv)
	{
		$this->_state[12] = $iv[0];
		$this->_state[13] = $iv[1];
		$this->_state[14] = $iv[2];
		$this->_state[15] = $iv[3];
		$this->_state[16] = 0;
		$this->_state[17] = 0;
		$this->_state[18] = 0;
		$this->_state[19] = 0;
	}

	private static function addRotXor(&$x, $i, $j, $b, $target)
	{
		$s = $x[2 * $i] + $x[2 * $j];
		$r = $s >> 16;
		$s = $s & 0xFFFF;
		$t = ($x[2 * $i + 1] + $x[2 * $j + 1] + $r) & 0xFFFF;

		$m = $b < 16 ? 0 : 1;
		$b = $b % 16;
		$nt = (($t << $b) & 0xFFFF) | ($s >> (16 - $b));
		$ns = (($s << $b) & 0xFFFF) | ($t >> (16 - $b));
		$x[2*$target + $m] = $x[2*$target + $m] ^ $ns;
		$x[2*$target + 1 - $m] = $x[2*$target + 1 - $m] ^ $nt;
	}

	private function nextOutput()
	{
		$x = array();
		for ($i = 0; $i < self::STATE_LEN; $i++)
			$x[$i] = $this->_state[$i];
		
		for ($i = 0; $i < 10; $i++)
		{
			$this->addRotXor($x, 0, 12, 7, 4);
			$this->addRotXor($x, 4, 0, 9, 8);
			$this->addRotXor($x, 8, 4, 13, 12);
			$this->addRotXor($x, 12, 8, 18, 0);
			$this->addRotXor($x, 5, 1, 7, 9);
			$this->addRotXor($x, 9, 5, 9, 13);
			$this->addRotXor($x, 13, 9, 13, 1);
			$this->addRotXor($x, 1, 13, 18, 5);
			$this->addRotXor($x, 10, 6, 7, 14);
			$this->addRotXor($x, 14, 10, 9, 2);
			$this->addRotXor($x, 2, 14, 13, 6);
			$this->addRotXor($x, 6, 2, 18, 10);
			$this->addRotXor($x, 15, 11, 7, 3);
			$this->addRotXor($x, 3, 15, 9, 7);
			$this->addRotXor($x, 7, 3, 13, 11);
			$this->addRotXor($x, 11, 7, 18, 15);
			$this->addRotXor($x, 0, 3, 7, 1);
			$this->addRotXor($x, 1, 0, 9, 2);
			$this->addRotXor($x, 2, 1, 13, 3);
			$this->addRotXor($x, 3, 2, 18, 0);
			$this->addRotXor($x, 5, 4, 7, 6);
			$this->addRotXor($x, 6, 5, 9, 7);
			$this->addRotXor($x, 7, 6, 13, 4);
			$this->addRotXor($x, 4, 7, 18, 5);
			$this->addRotXor($x, 10, 9, 7, 11);
			$this->addRotXor($x, 11, 10, 9, 8);
			$this->addRotXor($x, 8, 11, 13, 9);
			$this->addRotXor($x, 9, 8, 18, 10);
			$this->addRotXor($x, 15, 14, 7, 12);
			$this->addRotXor($x, 12, 15, 9, 13);
			$this->addRotXor($x, 13, 12, 13, 14);
			$this->addRotXor($x, 14, 13, 18, 15);
		}

		for ($i = 0; $i < self::STATE_LEN; $i+= 2)
		{
			$s = $x[$i] + $this->_state[$i];
			$x[$i] = $s & 0xFFFF;
			$x[$i + 1] = ($x[$i + 1] + $this->_state[$i + 1] + ($s >> 16)) & 0xFFFF;
		}

		$out = "";
		for ($i = 0; $i < self::STATE_LEN; $i++)
			$out .= pack("v", $x[$i]);

		$this->_output = $out;
		$this->_outputPos = 0;
		$this->_state[16]++;
		if ($this->_state[16] == 0xFFFF)
		{
			$this->_state[16] = 0;
			$this->_state[17]++;
			if ($this->_state[17] == 0xFFFF)
			{
				$this->_state[17] = 0;
				$this->_state[18]++;
				if ($this->_state[18] == 0xFFFF)
				{
					$this->_state[18] = 0;
					$this->_state[19]++;
				}
			}
		}
	}

	/**
	 * Generates $n random bytes and returns them as a string.
	 * @param $n The number of bytes to generate.
	 * @return A $n-long string.
	 */
	public function getNextBytes($n)
	{
		$s = "";
		$nRem = $n;
		while ($nRem > 0)
		{
			if ($this->_outputPos == 64)
				$this->nextOutput();
			$nCopy = min(64 - $this->_outputPos, $nRem);
			$s .= substr($this->_output, $this->_outputPos, $nCopy);

			$nRem -= $nCopy;
			$this->_outputPos += $nCopy;
		}
		return $s;
	}
}

?>