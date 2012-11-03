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
 * A CipherEngine based on one of the ciphers
 * implemented by the PHP mcrypt module. The wrapping
 * makes it possible to control the given arguments,
 * to ease the pain of calling mcrypt_generic (since
 * it automatically deals with all mcrypt_generic_init
 * and mcrypt_generic_deinit), and finally it adds
 * a support of the PK7 padding method, used in
 * C# and Java but not known by PHP.
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
    
    public function setMode($m)
    {
        $this->mode = $m;
    }
    
    public function setKey($k)
    {
        $this->key = $k;
    }
    
    public function setIV($iv)
    {
        $this->iv = $iv;
    }
    
    public function setPadding($p)
    {
        $this->padding = $p;
    }

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
     * @return null
     */
    public function load()
    {
        if($this->state != 0)
            return;
        if($this->module !== null)
            $this->unload();
        if($this->mode == null || $this->key === null)
        {
            KeePassPHP::raiseError("No mode or no key for the cipher !");
            return;
        }
        $this->module = mcrypt_module_open($this->type, '', $this->mode, '');
        if($this->iv === null)
            $this->iv = mcrypt_create_iv(
                    mcrypt_get_iv_size($this->type, $this->mode), MCRYPT_RAND);
        mcrypt_generic_init($this->module, $this->key, $this->iv);
        $this->state = 1;
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
     * Return as a binary string the encrypting of the given string $s.
     * @param string $s
     * @return string
     */
    public function encrypt($s)
    {
        if($this->state == 0)
            $this->load();
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
     * @param string $s
     * @return string
     */
    public function decrypt($s)
    {
        if($this->state == 0)
            $this->load();
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
     * @param string $str
     * @param int $blocksize
     * @return string
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
     * @param string $string
     * @return null|string
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