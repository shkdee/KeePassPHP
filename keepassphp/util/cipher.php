<?php

/**
 * An abstract cipher enfine.
 */
interface iCipherEngine
{
    public function load();
    public function unload();
    public function encrypt($s);
    public function decrypt($s);
}

/**
 * A CipherEngine based on one of the ciphers implemented by the PHP mcrypt
 * module. The wrapping makes it possible to control the given arguments, to
 * ease the pain of calling mcrypt_generic (since it automatically deals with
 * all mcrypt_generic_init and mcrypt_generic_deinit stuff) ; finally, it adds
 * a support of the PK7 padding method, used in C# and Java but not known by
 * PHP.
 */
class CipherMcrypt implements iCipherEngine
{
    private $type;
    private $module;
    private $mode;
    private $key;
    private $iv;
    private $padding;

    // 0 = unloaded, 1 = loaded,
    // 2 = encrypting, 3 = decrypting
    private $state = 0;

    const AES128 = MCRYPT_RIJNDAEL_128;
    const PK7_PADDING = "pk7";

	/**
	 * Constructs a CipherMcrypt from the mcrypt cipher $cipherType, the mcrypt
	 * mode $mode, the key $key, the initialization vector $iv and the padding
	 * mode $padding. If $mode and $key are both null and are not set in some
	 * way before calling the method load, it will fail miserably.
	 * @param string $cipherType The mcrypt module to use.
	 * @param string|null $mode The mcrypt encryption mode to use.
	 * @param string|null $key The key, used for decryption as well as
	 * encryption.
	 * @param string $iv|null The initialization vector.
	 * @param string $padding|null The type of padding to use.
	 */
    public function __construct($cipherType, $mode = null,
            $key = null, $iv = null, $padding = null)
    {
        $this->type = $cipherType;
        $this->mode = $mode;
        $this->key = $key;
        $this->iv = $iv;
        $this->padding = $padding;
        $this->module = null;
        $this->state = 0;
    }

    /******************
     * Public methods *
     ******************/

	/**
	 * Set the mcrypt mode to use.
	 * @param string $m The mcrypt mode to use.
	 */
    public function setMode($m)
    {
        $this->mode = $m;
    }

	/**
	 * Set the decryption key to use.
	 * @param string $k The key to use.
	 */
    public function setKey($k)
    {
        $this->key = $k;
    }

	/**
	 * Set the initialization vector to use.
	 * @param string $iv The initialization vector to use.
	 */
    public function setIV($iv)
    {
        $this->iv = $iv;
    }

	/**
	 * Set the padding mode to use.
	 * @param string $p The padding mode to use.
	 */
    public function setPadding($p)
    {
        $this->padding = $p;
    }

	/**
	 * Returns the current initilization vector.
	 * @return string|null The current initialization vector (may be null if
	 * it has not been set yet).
	 */
    public function getIV()
    {
        return $this->iv;
    }

    /****************************
     * Interface implementation *
     ****************************/

    /**
     * Loads the cipher in mcrypt (must be done before starting to decrypt !).
     * If it was already opened, tries to close it and re-open it (!) because
     * that should happen only between an encrypt and a decrypt operation (in
     * which case it is needed, but this class takes care of that).
     * @return boolean Returns true if loading was successful, false otherwise.
     */
    public function load()
    {
        if($this->state != 0)
            return true;
        if($this->module !== null)
            $this->unload();
        if($this->mode == null || $this->key === null)
            return false; // we could almot raise an error...
        $this->module = mcrypt_module_open($this->type, '', $this->mode, '');
        if($this->iv === null)
            $this->iv = mcrypt_create_iv(
                    mcrypt_get_iv_size($this->type, $this->mode), MCRYPT_RAND);
        mcrypt_generic_init($this->module, $this->key, $this->iv);
        $this->state = 1;
		return true;
    }

    /**
     * Closes the mcrypt cipher.
     */
    public function unload()
    {
        mcrypt_generic_deinit($this->module);
        mcrypt_module_close($this->module);
        $this->module = null;
        $this->state = 0;
    }

    /**
     * Encrypts the given binary string $s.
     * @param string $s The binary string to be encrypted.
     * @return string|null Returns the encrypted string, or null in case of
	 * error.
     */
    public function encrypt($s)
    {
        if($this->state == 0)
            if(!$this->load())
				return null;
        if($this->state == 3)
        {
            mcrypt_generic_deinit($this->module);
            mcrypt_generic_init($this->module, $this->key, $this->iv);
        }
        $this->state = 2;
        $padded = $this->padding == self::PK7_PADDING ?
                self::addPK7Padding($s) : $s;
        return mcrypt_generic($this->module, $padded);
    }

    /**
     * Decrypts the binary string $s, and returns the result.
     * @param string $s The binary string to be decrypted.
     * @return string|null Returns the decrypted string, or null in case of
	 * error.
     */
    public function decrypt($s)
    {
        if($this->state == 0)
            if(!$this->load())
				return null;
        if($this->state == 2)
        {
            mcrypt_generic_deinit($this->module);
            mcrypt_generic_init($this->module, $this->key, $this->iv);
        }
        $this->state = 3;
        $padded = mdecrypt_generic($this->module, $s);
        if($this->padding == self::PK7_PADDING)
            return self::removePK7Padding ($padded);
        return $padded;
    }

    /*******************
     * Private methods *
     *******************/

    /**
     * Pads the given binary string $str with the PK7 padding scheme, so that
     * its length be a multiple of $blocksize. Returns the padded string.
     * @param string $str The binary string to be padded.
     * @param int $blocksize The block size to pad the string $str with.
     * @return string Returns the resulting padded string.
     */
    private static function addPK7Padding($str, $blocksize = 16)
    {
        $len = strlen($str);
        $pad = $blocksize - ($len % $blocksize);
        return $str . str_repeat(chr($pad), $pad);
    }

    /**
     * Tries to unpad the PK7-padded binary string $string, and returns
     * the result in case of success, or null otherwise.
     * @param string $string The binary string to be unpadded.
     * @return null|string Returns the unpadded string, or null in case of error.
     */
    private static function removePK7Padding($string)
    {
        $lastlen = ord(substr($string, -1));
        $lastcar = chr($lastlen);
        $pcheck = substr($string, -$lastlen);
        if(strspn($pcheck, $lastcar) != $lastlen)
            return null;
        return substr($string, 0, strlen($string)-$lastlen);
    }
}

?>