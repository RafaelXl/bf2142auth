        <?php 
		if(isset($_GET['pid']))
		{
			$pid = $_GET['pid'];  
		}
		else
		{
			$pid = 0;
		}
        ?> 
    <?php 
    $auth = ""; 
    require_once("ea_support.php"); 
     
    $bfcoding  = &new ea_stats(); 
     
    $code = dwh(dechex(time())).dwh(dechex(100)).dwh(dechex($pid))."0000"; 
    $code.= CalcCRC($code); 
    $result = $bfcoding->DefEncryptBlock($bfcoding->hex2str($code)); 
    $auth = $bfcoding->getBase64Encode($result); 
	echo $auth;
    ?> 
    <?php 
     
    function dwh($h) 
    { 
      $s = substr("0000000".$h, -8); 
      return substr($s,6,2).substr($s,4,2).substr($s,2,2).substr($s,0,2); 
    } 
     
    function XOR32 ($a, $b) 
    { 
      $a1 = $a & 0x7FFF0000; 
      $a2 = $a & 0x0000FFFF; 
      $a3 = $a & 0x80000000; 
      $b1 = $b & 0x7FFF0000; 
      $b2 = $b & 0x0000FFFF; 
      $b3 = $b & 0x80000000; 
      $c = ($a3 != $b3) ? 0x80000000 : 0; 
      return (($a1 ^ $b1) |($a2 ^ $b2)) + $c; 
    } 
     
    function SHR32 ($x, $bits) 
    { 
      if ($bits==0) return $x; 
      if ($bits==32) return 0; 
      $y = ($x & 0x7FFFFFFF) >> $bits; 
      if (0x80000000 & $x) { 
        $y |= (1<<(31-$bits));    
      } 
      return $y; 
    } 
     
    function SHL32 ($x, $bits) 
    { 
      if ($bits==0) return $x; 
      if ($bits==32) return 0; 
      $mask = (1<<(32-$bits)) - 1; 
      return (($x & $mask) << $bits) & 0xFFFFFFFF; 
    } 
     
    function SAL32 ($x, $bits) 
    { 
      $s = str_pad(decbin ($x),32,"0",STR_PAD_LEFT); 
      return bindec(substr($s,$bits).substr($s,0,$bits)); 
    } 
     
    function SAR32 ($x, $bits) 
    { 
      $s = str_pad(decbin ($x),32,"0",STR_PAD_LEFT); 
      $r = 32-$bits; 
      return bindec(substr($s,$r,$bits).substr($s,0,$r)); 
    } 
     
    function AND_FF ($x) 
    { 
      return str_pad(decbin ($x & 255),32,"0",STR_PAD_LEFT); 
    } 
     
    function CalcCRC($h) 
    { 
      $eax = 0; 
      for($esi=0; $esi<14; $esi++)  
      { 
        $ecx = $eax; 
        $ecx = SAR32($ecx,8);     
        $ecx&= 255; 
        $eax = SHL32($eax,8);     
        $ecx|= $eax; 
        $eax = hexdec(substr($h,$esi*2,2)); 
        $eax = XOR32($eax,$ecx); 
        $ecx = ($eax&255); 
        $ecx = SHR32($ecx,4);     
        $eax = XOR32($eax,$ecx); 
        $ecx = $eax; 
        $ecx = SHL32($ecx,12);     
        $eax = XOR32($eax,$ecx); 
        $ecx = $eax; 
        $ecx&= 255; 
        $ecx = SHL32($ecx,5);     
        $eax = XOR32($eax,$ecx); 
      } 
      $eax&= 65535; 
      $hex = substr("0000".strtoupper(dechex($eax)), -4); 
      return substr($hex,2,2).substr($hex,0,2); 
    } 
    ?>