<?php

/**
 * KeePass2's Salsa20 Cipher, adapted from
 * the C# version. To avoid weird interaction
 * with PHP's integers, 16-bits integers are used
 * (that's a bit heavy, but it should work regardless
 * of the platform).
 *
 * @author Louis
 */
class Salsa20cipher extends StreamCipher
{
	private $state;
	private $output;
	private $outputPos;

	const STATE_LEN = 32;
	const KEY_LEN = 32;
	const OUTPUT_LEN = 64;
	const IV_LEN = 8;

	public function __construct($key, $iv)
	{
		if ($key == null || strlen($key) != self::KEY_LEN)
			return;
		if ($iv == null || strlen($iv) != self::IV_LEN)
			return;

		$this->state = array();
		for ($i = 0; $i < self::STATE_LEN; $i++)
			$this->state[$i] = 0;

		$this->output = array();
		for ($i = 0; $i < self::OUTPUT_LEN; $i++)
			$this->output[$i] = 0;

		$this->outputPos = self::OUTPUT_LEN;
		$this->keySetup(Binary::fromString($key, self::KEY_LEN));
		$this->ivSetup(Binary::fromString($iv, self::IV_LEN));
	}

	private function keySetup(Binary $key)
	{
		for ($i = 0; $i < 4; $i++)
		{
			$j = 4 * $i;
			$this->state[2 * $i + 2] = $key->getByte($j)
					+ ($key->getByte($j + 1) << 8);
			$this->state[2 * $i + 3] = $key->getByte($j + 2)
					+ ($key->getByte($j + 3) << 8);
			$this->state[2 * $i + 22] = $key->getByte($j + 16)
					+ ($key->getByte($j + 17) << 8);
			$this->state[2 * $i + 23] = $key->getByte($j + 18)
					+ ($key->getByte($j + 19) << 8);
		}
		$this->state[0] = 0x7865;
		$this->state[1] = 0x6170;
		$this->state[10] = 0x646E;
		$this->state[11] = 0x3320;
		$this->state[20] = 0x2D32;
		$this->state[21] = 0x7962;
		$this->state[30] = 0x6574;
		$this->state[31] = 0x6B20;
	}

	private function ivSetup(Binary $iv)
	{
		$this->state[12] = $iv->getByte(0) + ($iv->getByte(1) << 8);
		$this->state[13] = $iv->getByte(2) + ($iv->getByte(3) << 8);
		$this->state[14] = $iv->getByte(4) + ($iv->getByte(5) << 8);
		$this->state[15] = $iv->getByte(6) + ($iv->getByte(7) << 8);
		$this->state[16] = 0;
		$this->state[17] = 0;
		$this->state[18] = 0;
		$this->state[19] = 0;
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
			$x[$i] = $this->state[$i];
		
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
			$s = $x[$i] + $this->state[$i];
			$x[$i] = $s & 0xFFFF;
			$x[$i + 1] = ($x[$i + 1] + $this->state[$i + 1] + ($s >> 16)) & 0xFFFF;
		}

		$out = "";
		for ($i = 0; $i < self::STATE_LEN; $i++)
			$out .= pack("CC", $x[$i] & 0xFF, $x[$i] >> 8);

		$this->output = $out;
		$this->outputPos = 0;
		$this->state[16]++;
		if ($this->state[16] == 0xFFFF)
		{
			$this->state[16] = 0;
			$this->state[17]++;
			if ($this->state[17] == 0xFFFF)
			{
				$this->state[17] = 0;
				$this->state[18]++;
				if ($this->state[18] == 0xFFFF)
				{
					$this->state[18] = 0;
					$this->state[19]++;
				}
			}
		}
	}

	public function getNextBytes($n)
	{
		$s = "";
		$nRem = $n;
		while ($nRem > 0)
		{
			if ($this->outputPos == 64)
				$this->nextOutput();
			$nCopy = min(64 - $this->outputPos, $nRem);
			$s .= substr($this->output, $this->outputPos, $nCopy);

			$nRem -= $nCopy;
			$this->outputPos += $nCopy;
		}
		return $s;
	}
}

?>