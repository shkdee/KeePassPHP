<?php

/**
 * An interface representing a hash algorithm.
 * Might have been useful, but finally not really
 * (see HashHouse below).
 *
 * @author Louis
 */
interface iHashAlgo
{
    public function hash($s);
}

/**
 * The SHA256 implementation of the HashAlgo
 * class.
 * 
 * @author Louis
 */
class HashSHA256 implements iHashAlgo
{
    public function hash($s)
    {
        return hash('SHA256', $s, true);
    }
}

/**
 * A static class used to provide a uniform
 * access to the only used hash function. This
 * is finally simpler this way than with the
 * HashAlgo objects below, which would have made
 * it necessary to create new objects for every
 * new hash, whereas the only function to call
 * is hash("sha256", $string, true). So basically
 * this HashHouse is just a kind of wrapper
 * around the PHP hash function, so that it
 * might be changed easily in the future, if
 * needed.
 *
 * @author Louis
 */
abstract class HashHouse
{
    static public $algo = "";
    
    public static function setDefault($str)
    {
        self::$algo = $str;
    }

    public static function hash($s)
    {
        return hash(self::$algo, $s, true);
    }

    public static function hashArray($a)
    {
        $h = hash_init(self::$algo);
        foreach($a as $v)
            hash_update($h, $v);
        $r = hash_final($h, true);
        unset($h);
        return $r;
    }
}

?>
