<?php
error_reporting(0);
ini_set('memory_limit','512M');
$froms = ['UTF-8','UTF-16','UTF-16BE','UTF-16LE','UTF-32','UTF-32BE','UTF-32LE','UCS-2','UCS-4','wchar','byte2be','byte2le','byte4be','byte4le','UTF-7','UTF7-IMAP','ISO-2022-JP','ISO-2022-JP-2004','ISO-2022-KR','SJIS','EUC-JP','BIG5','GB18030','HTML-ENTITIES','BASE64','Quoted-Printable','7bit','8bit'];
$tos = ['UTF-8','UTF-16','UTF-32','UCS-2','UCS-4','wchar','byte2be','byte4be','HTML-ENTITIES','BASE64','Quoted-Printable','7bit','8bit'];
$lens = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,23,24,25,31,32,33,47,48,49,63,64,65,95,127,128,129,255];
function ptrlike($s) {
    $n = strlen($s);
    for ($i=0; $i+7 < $n; $i++) {
        $v = unpack('P', substr($s, $i, 8))[1];
        if (($v >> 48) === 0) {
            $top = ($v >> 44) & 0xf;
            if (($top === 7 || $top === 5 || $top === 6) && (($v >> 32) & 0xffff) !== 0) {
                return $v;
            }
        }
    }
    return null;
}
function sprayheap() {
    $junk = [];
    for ($i=0; $i<400; $i++) {
        $junk[] = [str_repeat("\xaa", 64 + ($i % 7) * 16), new stdClass(), [$i, str_repeat("B", 32)]];
    }
    unset($junk);
}
$hits = 0;
foreach ($froms as $from) {
  fwrite(STDERR, "FROM $from\n");
  foreach ($tos as $to) {
    if ($from === $to) continue;
    foreach ($lens as $len) {
      $inputs = [str_repeat("\xff",$len), str_repeat("\x80",$len), str_repeat("\x00",$len), str_repeat("\x41",$len)];
      if ($len > 0) $inputs[] = random_bytes($len);
      foreach ($inputs as $in) {
        sprayheap();
        try { $out = @mb_convert_encoding($in, $to, $from); } catch (Throwable $e) { $out = false; }
        if (is_string($out) && ($v = ptrlike($out)) !== null) {
          echo "MB from=$from to=$to len=$len in=".bin2hex($in)." out=".bin2hex($out)." ptr=".dechex($v)."\n";
          if (++$hits >= 10) exit;
        }
        if (function_exists('iconv')) {
          try { $out2 = @iconv($from, $to."//IGNORE", $in); } catch (Throwable $e) { $out2 = false; }
          if (is_string($out2) && ($v = ptrlike($out2)) !== null) {
            echo "IC from=$from to=$to len=$len in=".bin2hex($in)." out=".bin2hex($out2)." ptr=".dechex($v)."\n";
            if (++$hits >= 10) exit;
          }
        }
      }
    }
  }
}
echo "DONE hits=$hits\n";
