<?php

/**
 * A basic Stream Cipher abstract class, used with a
 * Salsa20 implementation, and an ARC4 implementation.
 *
 * @author Louis
 */
abstract class StreamCipher
{
	abstract public function getNextBytes($n);

	public function dencrypt($s)
    {
        $x = $this->getNextBytes(strlen($s));
        return $s ^ $x;
    }
}

/*
class ArcFourCipher extends StreamCipher
{
	private $internal;

	public __construct($key)
	{
		$this->internal = new Crypt_RC4();
		$this->internal->setKey($key);
	}
}
*/

?>