<?php

/**
 * Class representing a number as an array of bytes.
 * It allows both to translate easily binary-string
 * encoded numbers into integers (PHP likes binary
 * strings), and to use numbers of an arbitrary,
 * machine-independant size (it may be hard to use
 * unsigned integers greater than 2**31 otherwise).
 *
 * @author Louis
 */
class Binary
{
    private $str;
    private $bytes;
    private $size;
    private $offset;
    
    public function __construct($bytes, $size = null)
    {
        $this->str = null;
        $this->offset = 0;
        if($size !== null)
            $this->size = $size;

        $this->bytes = array();
        $t = $this->size === null ?
            count($bytes) :
            min($this->size, count($bytes));
        for($i = 0 ; $i < $t ; $i++)
            $this->bytes[$i] = $bytes[$i];
        for($i = count($this->bytes) - 1 ; $i > 0 ; $i--)
            if($this->bytes[$i] == 0)
                unset($this->bytes[$i]);
            else
                break;

        if($this->size === null)
            $this->size = count($this->bytes);
    }
    
    public function getBytes()
    {
        return $this->bytes;
    }

    public function getSize()
    {
        return $this->size;
    }

    public function getStr()
    {
        if($this->str === null)
            $this->str = self::toBinString($this->bytes);
        return $this->str;
    }

    public function n()
    {
        return count($this->getBytes()) + $this->offset;
    }

    public function addOffset($n)
    {
        $diff = $n < 0 ? max($n, -$this->offset) : $n;
        $this->offset += $diff;
    }

    public function getByte($i)
    {
        if($i < 0 || $i >= $this->getSize())
            return null;
        if($i < $this->offset)
            return 0;
        if($i >= $this->n())
            return 0;
        return $this->bytes[$i - $this->offset];
    }

    public function asNumeric($n = null)
    {
        $t = ($n === null ?
            min($this->n(), $this->getSize()) :
            min($n, $this->n(), $this->getSize())) - $this->offset;
        $res = 0;
        for($i = 0 ; $i < $t ; $i++)
            $res += ($this->bytes[$i] << (8*($i + $this->offset)));
        return $res;
    }

    public function asInt()
    {
        return $this->asNumeric(4);
    }
    
    public function asShort()
    {
        return $this->asNumeric(2);
    }
    
    public function asByte()
    {
        return $this->asNumeric(1);
    }

    public function asBigEndian()
    {
        $res = 0;
        $t = count($this->getBytes());
        for($i = 0 ; $i < $t ; $i++)
            $res = ($res << (8*$i)) + $this->bytes[$i];
        return $res << $this->offset;
    }

    public function lsl($n)
    {
        $res = new Binary($this->getBytes(), $this->getSize());
        $res->addOffset($n);
        return $res;
    }

    public function lsr($n)
    {
        if($this->offset >= $n)
        {
            $res = new Binary($this->getBytes(), $this->getSize());
            $res->addOffset(-$n);
            return $res;
        }
        $n -= $this->offset;
        if($n >= count($this->getBytes()))
            return new BytesBinary(array(), $this->getSize());
        return new Binary(array_slice($this->getBytes(), $n),
                $this->getSize());
    }

    public function land(Binary $sint)
    {
        $bytes = array();
        $t = min($this->n(), $sint->n());
        for($i = 0 ; $i < $t ; $i++)
            $bytes[$i] = $this->getByte($i) & $sint->getByte($i);
        return new Binary($bytes, min($this->getSize(), $sint->getSize()));
    }

    public function equals(Binary $sint)
    {
        if($this->n() != $sint->n())
            return false;
        for($i = 0 ; $i < $this->n() ; $i++)
            if($this->getByte($i) != $sint->getByte($i))
                return false;
        return true;
    }
    
    public function equalsString($s)
    {
        return $this->equals(self::fromString($s));
    }

    public function equalsInt($i)
    {
        return $this->equals(self::fromInt($i));
    }

    public function equalsShort($sh)
    {
        return $this->equals(self::fromShort($sh));
    }
    
    public function equalsByte($b)
    {
        return $this->equals(self::fromByte($b));
    }

    public function printBytes()
    {
        echo "n = ", $this->n(), " ; size = ", $this->getSize(), "\n";
        print_r($this->getBytes());
    }

    public function asHexString()
    {
        $s = "";
        for($i = 0 ; $i < $this->getSize() ; $i++)
            $s = $s . " " . dechex($this->getByte($i));
        return strtoupper($s);
    }

    public static function fromInt($int)
    {
        return new Binary(self::numToBytes($int, 4), 4);
    }

    public static function fromShort($sh)
    {
        return new Binary(self::numToBytes($sh, 2), 2);
    }

    public static function fromByte($b)
    {
        return new Binary(self::numToBytes($b, 1), 1);
    }
    
    public static function fromString($s, $size = null)
    {
        return new Binary(self::strToBytes($s), $size);
    }
    
    public static function toBinString($bytes)
    {
        $s = "";
        for($i = 0 ; $i < count($bytes) ; $i++)
            $s = $s . pack("C", $bytes[$i]);
        return $s;
    }

    public static function numToBytes($int, $n)
    {
        $bytes = array();
        for($i = 0 ; $i < $n ; $i++)
        {
            $bytes[$i] = $int & 0xFF;
            $int = $int >> 8;
        }
        return $bytes;
    }
    
    public static function strToBytes($s)
    {
        $bytes = array();
        for($i = 0 ; $i < strlen($s) ; $i++)
        {
            list($c) = array_values(unpack("C", $s[$i]));
            $bytes[$i] = $c;
        }
        return $bytes;
    }
}

?>