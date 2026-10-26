<?php
error_reporting(0);
ini_set('memory_limit','512M');
$froms = ['UTF-8','UTF-16','UTF-16BE','UTF-16LE','UTF-32','UTF-32BE','UTF-32LE','UCS-2','UCS-4','wchar','byte2be','byte2le','byte4be','byte4le','UTF-7','UTF7-IMAP','ISO-2022-JP','SJIS','EUC-JP','BIG5','GB18030','HTML-ENTITIES','BASE64','Quoted-Printable','7bit','8bit'];
$tos = ['UTF-8','UTF-16','UTF-32','UCS-2','UCS-4','wchar','byte2be','byte4be','HTML-ENTITIES','BASE64','Quoted-Printable','7bit','8bit'];
$lens = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,15,16,17,23,24,31,32,33,47,63,64,65];
function ptrlike($s) {
    $n = strlen($s);
    for ($i=0; $i+7 < $n; $i++) {
        $b = ord($s[$i+5]);
        if ($s[$i+6] === "\0" && $s[$i+7] === "\0" && ($b === 0x7f || $b === 0x55 || $b === 0x56) && $s[$i+4] !== "\0") {
            return substr($s, $i, 8);
        }
    }
    return null;
}
$hits = 0;
foreach ($froms as $from) {
  fwrite(STDERR, "FROM $from\n");
  foreach ($tos as $to) {
    if ($from === $to) continue;
    foreach ($lens as $len) {
      $inputs = [];
      $inputs[] = str_repeat("\xff", $len);
      $inputs[] = str_repeat("\x80", $len);
      $inputs[] = str_repeat("\x00", $len);
      $inputs[] = str_repeat("\x41", $len);
      if ($len > 0) { $inputs[] = random_bytes($len); }
      foreach ($inputs as $in) {
        try { $out = @mb_convert_encoding($in, $to, $from); } catch (Throwable $e) { $out = false; }
        if (is_string($out) && ($p = ptrlike($out)) !== null) {
          echo "MB from=$from to=$to len=$len in=".bin2hex($in)." out=".bin2hex($out)." ptr=".bin2hex($p)."\n";
          if (++$hits >= 20) exit;
        }
        if (function_exists('iconv')) {
          try { $out2 = @iconv($from, $to, $in); } catch (Throwable $e) { $out2 = false; }
          if (is_string($out2) && ($p = ptrlike($out2)) !== null) {
            echo "IC from=$from to=$to len=$len in=".bin2hex($in)." out=".bin2hex($out2)." ptr=".bin2hex($p)."\n";
            if (++$hits >= 20) exit;
          }
        }
      }
    }
  }
}
echo "DONE hits=$hits\n";
