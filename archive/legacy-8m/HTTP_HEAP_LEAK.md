# Saf HTTP heap adres sızıntısı: stale `PS(id)` + `Set-Cookie` sınır-dışı okuma

Tarih: 2026-10-21
Hedef: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64, `172.16.0.103`)
Kısıtlar: **tamamen uzaktan, yalnızca HTTP; hedef webroot'a herhangi bir özel PHP dosyası yazılmaz**.
Hedef sayfası yalnızca `<?php echo "OK\n"; ?>` içerir (session çağrısı yok; bu sızıntı script
içeriğine bağlı değildir).
Durum: **heap adresi (Zend MM 2MB chunk base) sızıntısı aşıldı**; libphp/libc **kod işaretçisi**
sızıntısı henüz tamamlanmadı, bir sonraki adım için bkz. bölüm 7.

---

## 1. Sonuç

İki saf HTTP isteğiyle, yanıt başlığı `Set-Cookie`'den **4096 baytlık heap sınır-dışı okuması** elde edildi:

- İstek A: önce 1001 POST alanıyla `max_input_vars` uyarısı tetiklenir (`display_errors=On` iken
  bu uyarı çıktıya verilir, `SG(headers_sent)=1`), ardından değeri tek bayt `\x00` olan bir
  `PHPSESSID` ile `php_session_initialize()`'ın yeni id üretmesi ve `send_cookie=1` yapması
  sağlanır; ardından `php_session_reset_id()`, headers zaten gönderildiği için **cookie gönderimi
  başarısız olur** ve `send_cookie` 1 olarak kalır. A'nın sonunda 12MB alanla OOM yapılır ve sarkan
  `PS(id)` (rastgele id'nin `zend_string`'i) bırakılır.
- İstek B: dosya alanı taşımaz, pre-RINIT upload-progress END cleanup'ı
  `php_session_initialize()`'ı çağırır, `php_session_reset_id()` `send_cookie=1` görür,
  bu isteğin headers'ı henüz gönderilmemiştir, dolayısıyla sarkan `PS(id)` ile
  `Set-Cookie: PHPSESSID=<url_encode(ZSTR_VAL(id), ZSTR_LEN(id))>` kurar.
- B'nin multipart alanları, A'dan kalan `PS(id)` bloğunu sahte bir `zend_string` başlığına çevirir:
  `len=0x1000`, `data` blok içi offset 0x18'e işaret eder. `php_url_encode` len'e göre okur,
  blok kuyruğunu aşıp komşu heap'e girer ve içeriği `Set-Cookie`'ye encode eder.

Fiilî test (no-ASLR kalibrasyon):

```text
Set-Cookie: PHPSESSID=LAAAA...%B2%D0%82f%60h%3F...%F5%FF%7F...
cookie değeri 11548 karakter (URL encode), çözümlendiğinde 4096 bayt
98 adet 0x7f.... işaretçisi, hepsi & ~0x1fffff == 0x7ffff5e00000
```

Yani **Zend MM chunk base doğrudan HTTP yanıt başlığından geri kazanılabilir**;
`/proc/self/maps`'e, hedef-tarafı PHP'ye ya da hedef uygulamanın işbirliğine gerek kalmadan.

> Bu, `NOASLR_REPORT.md`'nin saf HTTP RCE zincirine diktir (orthogonal): sızıntı isteği A,
> `track_init`'ten önce başarısız olur (`reset_id` başarısız), dolayısıyla
> `PS(http_session_vars)` sarkan referansı **bırakmaz**; yalnızca sarkan `PS(id)` ve
> `send_cookie=1` bırakma işini üstlenir.

---

## 2. Mekanizma ve kaynak kod yolu

### 2.1 `send_cookie`'nin 1 kalmasını sağlamak

`ext/session/session.c`:

```c
static zend_result php_session_initialize(void)
{
    ...
    if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {      /* boş id -> yeni id oluştur */
        ...
        PS(id) = PS(mod)->s_create_sid(&PS(mod_data));
        ...
        if (PS(use_cookies)) {
            PS(send_cookie) = 1;
        }
    }
    ...
    if (php_session_reset_id() == FAILURE) {    /* burada başarısız, track_init çalışmaz */
        php_session_abort();
        return FAILURE;
    }
    php_session_track_init();
    ...
}
```

`php_session_send_cookie()`:

```c
if (SG(headers_sent)) {
    php_error_docref(NULL, E_WARNING,
        "Session cookie cannot be sent after headers have already been sent");
    return FAILURE;
}
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
```

Kilit noktalar:

1. **headers_sent mutlaka 1 olmalı**. `max_input_vars` limit aşımı uyarısıyla sağlanır:
   `main/php_variables.c`, değişken sayısı 1000'i aştığında
   `php_error_docref(NULL, E_WARNING, "Input variables exceeded ...")` yapar;
   lab'ın `display_errors=On` olduğu için uyarı yanıta yazılır ve `SG(headers_sent)=1` yapılır.
2. **id'nin ilk baytı 0 olmalı**. multipart'ın `PHPSESSID` değeri tek bayt `\x00` alınır:
   `php_session_rfc1867_callback`'in FORMDATA dalı `value_len != 0` gerektirir,
   bu yüzden `progress->sid` uzunluğu 1, içeriği `\0` olan bir string'e ayarlanır; FILE_START'ta
   `PS(id) = zend_string_init(progress->sid)`'den sonra `!ZSTR_VAL(PS(id))[0]`
   sağlanır, "yeni id oluştur" dalına girilir, `send_cookie=1`.
3. `reset_id` headers_sent nedeniyle başarısız olur → `send_cookie` 1 kalır ve
   `php_session_track_init()` çalışmaz (bu yüzden `$_SESSION` referansı yoktur).
4. A'nın sonunda 12MB'lık sıradan bir alan `memory_limit=8M` OOM tetikler; bailout request
   shutdown'ı atlar, `ps_globals.id` sarkan kalır (rastgele id'nin 32 baytlık `zend_string`'i).

Fiilen A'dan sonra (gdb, setarch -R):

```text
ps_globals.send_cookie = 1
ps_globals.id          = 0x7ffff5ea9000   (len=32, data0=0x35)
ps_globals.http_session_vars.type_info = 0 (UNDEF)
```

Yanıt gövdesinde aynı anda iki kritik uyarı belirir; bu uzak taraf için "ön koşullar sağlandı"
sinyali olarak kullanılabilir:

```html
Warning: PHP Request Startup: Input variables exceeded 1000...
Warning: PHP Request Startup: Session cookie cannot be sent after headers have already been sent
```

### 2.2 B: sarkan `PS(id)` ile `Set-Cookie` göndermek

B dosya alanı taşımaz, bu yüzden FILE_START'ın `php_rinit_session(0)`'ını tetiklemez (o, PS
global'lerini temizlerdi). multipart END olayı → `php_session_rfc1867_cleanup()` →
`php_session_initialize()` → `php_session_reset_id()`:

- `PS(use_cookies)=1` (varsayılan);
- `PS(send_cookie)=1` (A'dan kalan);
- B'nin bu isteğinin headers'ı gönderilmemiş → cookie gerçekten gönderilir;
- `php_url_encode`, uzunluk olarak `ZSTR_LEN(PS(id))`, başlangıç olarak `ZSTR_VAL(PS(id))` ile okur.
  Sarkan blok B'nin alanları tarafından yeniden işgal edildikten sonra, len/data tamamen saldırgan
  kontrolündedir.

### 2.3 Sarkan `PS(id)` bloğunu yeniden işgal etmek

A'nın rastgele id'sinin uzunluğu 32, `zend_string_alloc(32)` = 24+32+1 = 57 → **64 baytlık bin**;
bu lab şeklinde blok adresi `chunk + 0xa9000`'dir (no-ASLR: `0x7ffff5ea9000`).

B'nin multipart parse'ı istek başlangıcında chunk'ı yeniden sayfalar. Kalibrasyon, bu stale
adresinin B'nin yerleşiminde **80 baytlık bin sayfasına** düştüğünü ortaya koydu:

1. Önce değer uzunluğu 48 olan N alan gönderilir (`zend_string` = 24+48+1 = 73 → 80B bin).
   Her alan bir **canlı** 80B string bırakır, free-list sırasına göre blokları işgal eder.
2. Her alan için benzersiz 48 karakterlik değer (`v%04d` + `x`) ile "hangi blok stale adrese
   düşüyor" okunabilir: bu lab'da `N=998` iken `Set-Cookie`'nin değeri `v0892...`'dir, yani
   893. alanın string'i o bloğa düşer.
3. Bunun yerine **892 adet** öncül alan gönderilir, ardından 1 adet **79 baytlık değere** sahip
   forge alanı gönderilir:
   - raw buffer boyutu 79+1 = 80 → 80B bin;
   - onun value `zend_string`'i 24+79+1 = 104 → 112B bin'dir (80B bloğu işgal etmez);
   - raw buffer tam olarak "893. 80B blok"u = stale `PS(id)` bloğunu alır.
   raw buffer içerik yerleşimi (blok başlangıcı S, `PS(id)=S`):

   ```text
   S+0x00: gc (efree edilen free-list next ile üzerine yazılır, etkisiz)
   S+0x08: h (keyfi)
   S+0x10: len = 0x1000 (sahte)
   S+0x18: data[0] = 'L', ardından dolgu
   ```

4. Alan işlendikten sonra raw buffer `efree()` edilir; Zend MM yalnızca free-list işaretçisini blok
   offset 0'a yazar, `+0x10`'daki len korunur. B'nin END cleanup'ı ardından
   `ZSTR_LEN(PS(id)) = 0x1000` okur ve `S+0x18`'den başlayarak URL encode yapar.

`Set-Cookie` gönderildikten sonra, `ps_files_open()`'ın
`php_session_valid_key()`'i id geçersiz bayt içerdiği için başarısız olur ve
`Session ID is too long or contains illegal characters` uyarısı üretir — bu noktada sızıntı
zaten yanıt başlığına yazılmıştır, uyarı sonucu etkilemez.

---

## 3. Çoğaltma adımları

Ortam (`NOASLR_REPORT.md` ile aynı, ek olarak iki noktaya dikkat):

- `display_errors=On` (headers_sent, uyarının fiilen çıktıya verilmesine bağlıdır);
- `session.use_cookies=1` (varsayılan; bu lab bir ara 0'dı, geri değiştirmek gerekir);
- `memory_limit=8M`, `session.use_strict_mode=0`, `session.save_path=/tmp`,
  `max_input_vars=1000` (varsayılan).

```bash
# Hedef makine 172.16.0.103, ASLR açık/kapalı olabilir; aşağıdakiler kalibre edilmiş no-ASLR komutlarıdır
cd ~/php2shell-work

# A: 1001 alan max_input_vars uyarısını tetikler; PHPSESSID tek bayt \x00;
#    dosya alanı FILE_START'ı tetikler; 12MB alan OOM yapar
python3 send_a_leak2.py 1001 12

# B: 892 adet 48 karakterlik sayısal alan 80B bloğu tüketir; son 79 baytlık değer alanının raw buffer'ı
#    sarkan PS(id) bloğuna düşer, sahte len=0x1000
python3 b_numleak2.py 892 1 0x1000
```

B'nin yanıt başlığı örneği (kesilmiş):

```text
Set-Cookie: PHPSESSID=LAAAA...%B2%D0%82f%60h%3F%C3%A0%90%EA%F5%FF%7F...
...
Warning: PHP Request Startup: Session ID is too long or contains illegal characters.
```

Decode ve işaretçi çıkarımı:

```bash
python3 tools/decode_leak.py logs/http_heap_leak_20261021.resp
# decoded=4096, candidate_ptrs=98, chunk_bases=7ffff5e00000:98
```

Ham yanıt arşivi: `logs/http_heap_leak_20261021.resp`; analiz çıktısı:
`logs/http_heap_leak_20261021.txt`.

---

## 4. Kalibrasyon verileri (bu build / bu istek şekli)

| Öğe | Değer |
|---|---|
| A sonrası `PS(id)` (stale `zend_string`) | `0x7ffff5ea9000` = chunk + `0xa9000` |
| id uzunluğu / blok boyutu | 32 / 64B bin |
| B yeniden işgal sonrası bloğun bulunduğu bin | 80B |
| Öncül 48 karakterlik alan sayısı (konumlandırma) | `N=998` iken value `v0892` o bloğa düşer |
| forge öncül alan sayısı | `K=892` |
| forge alan değeri uzunluğu | 79 (raw 80B) |
| sahte len | `0x1000` |
| B yanıt `Set-Cookie` | 11548 karakter (4096B çözümlenir) |
| sızıntı işaretçileri | 98 adet, hepsi `0x7ffff5e…`, chunk base `0x7ffff5e00000` |

Ek (aynı stale adresin yeniden kullanım kanıtı):

- `N=998` ve değer benzersiz 48 karakterlik iken, cookie değeri tam olarak `v0892...`'dir
  (len=48) — bu bloğun canlı bir 80B string tarafından yeniden işgal edildiğini gösterir;
- Sayısal anahtar + kısa değer (`b_numleak.py`) iken cookie hâlâ normal 32 karakterlik id'dir —
  bu bloğun kullanılmadığını gösterir; yalnızca 80B canlı string/raw tahsis dizisi ona isabet eder.

---

## 5. ASLR zinciriyle ilişki

Bu sızıntı **Zend MM chunk base**'i sağlar. Aynı deney turunda dış adresle doğrulandı:

- Kalibre edilmiş saf HTTP A/B RCE zinciri `personality=0` (ASLR açık) altında **3/3** başarılı;
- Yalnızca chunk içi göreli offset'e bağlı: `R0 = chunk + 0x24e0`, fake HT data =
  `chunk + 0x6e0d8` (ilgili A/B şekli aşağıda);
- libc base `/proc/<worker>/maps` üzerinden dışarıdan alındığında, `system = libc + 0x4c490`,
  zincir `id>/tmp/p1`'i eksiksiz yürütür.

Yani: **A/B bellek zincirinin kendisi ASLR'den bağımsızdır**, yalnızca "adres kaynağı" eksiktir.
Bu bölümün Set-Cookie sızıntısı heap base'i zaten tamamladı; hâlâ eksik olan **libphp kod işaretçisi**
(`zif_system` için, libphp + `0x43a870`, libc gerektirmez) ya da libc işaretçisidir.

### 5.1 Bu turda aynı anda elde edilen no-ASLR yeniden kalibrasyonu

`172.16.0.103` üzerinde (orijinal raporun 172.16.1.112'si değil), orijinal raporun sabit
parametreleri doğrudan uygulanamaz:

```text
A: send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
B: send_b_rce2.py 16 2 0x7ffff5e6e0d8 0x7ffff7d14490 "id>/tmp/p1"
```

- 6 adet `7:7` pad, A'nın reference adresini `0x7ffff5e024e0`'e taşır,
  `R0-0x10=0x7ffff5e024d0` tam olarak 56B blok başlangıcıdır;
- B, 55B raw buffer'ın `R0-0x10`'a düşmesi için `N1=16` (31 karakterlik priming alan) gerektirir;
- Bu makinede libc `system = 0x7ffff7d14490` (offset `0x4c490`), fake HT data =
  `0x7ffff5e6e0d8`;
- proof: `/tmp/p1` içeriği `uid=33(www-data) ...`.

---

## 6. Sınırlar

1. **`display_errors=On` bir ön koşuldur**. headers_sent, uyarı çıktısından gelir; hedef
   display_errors'u kapatırsa, bu yolun `send_cookie=1` kalıntısı oluşmaz (mevcut lab On).
2. Uyarıyı tetiklemek için `>1000` POST değişkeni gerekir (varsayılan `max_input_vars=1000`);
   istek gövdesi ~1MB seviyesindedir.
3. `session.use_cookies=1` (varsayılan) ve `session.use_strict_mode=0` (varsayılan 0) gerekir.
4. chunk içi offset (`0xa9000`), `N=998`, `K=892` bu build + bu istek şekline bağlıdır;
   PHP build'i / alan uzunluğu / boundary uzunluğu değişince yeniden test gerekir. Bunların hepsi
   **chunk göreli offset**'tir, ASLR'den bağımsızdır.
5. Sızıntı yalnızca yüksek adrese okur (`PS(id)+0x18`'den itibaren). Mevcut 4KB bölge 80B string
   sayfasıdır, yalnızca heap işaretçisi içerir; 1MB'lık büyük aralık sızıntısı (gönderilebilir
   olduğu doğrulandı) hâlâ yalnızca heap işaretçisi görür, libphp/libc kod işaretçisi yoktur.
6. Eğer len kontrol-dışı bir değer okursa (örneğin HashTable'ın `arData` / 64 bit hash'i),
   `php_url_encode`'un `safe_emalloc`'u doğrudan fatal verir:
   `Possible integer overflow in memory allocation (3 * N + 32)`.
   Bu başlı başına bir "len kontrol edilemiyor" sinyalidir, ama veri alınamaz.
7. Bu sızıntının A'sı `PS(http_session_vars)` sarkan referansı üretmez (`reset_id`,
   `track_init`'ten önce başarısız olur), bu yüzden RCE'nin A'sıyla tek bir istekte birleştirilemez;
   ikisi aynı worker üzerinde ardışık kullanılabilen bağımsız primitiflerdir.

---

## 7. Bir sonraki adım: libphp kod işaretçisini sızdırmak

> **2026-10-21 sonraki ilerleme (tamamlandı)**: Bu bölümün hedefi gerçekleştirildi ve ayrıca
> saf HTTP ASLR-on RCE delindi (iki Set-Cookie sızıntısı + `zif_system`), lab içinde 5/5. Yöntem:
> A, 1001 adet 39 baytlık değer alanıyla stale `PS(id)`'yi `chunk+0xb7400`'e koyar; B, 983 adet
> iç içe diziyle `$_POST['a0443']`'ün HashTable'ını 16 elemana genişletir. `PS(id)+0x10`
> `nTableSize=16` okur, veri bölgesi `nNextFreeElement` ve `pDestructor`'ı kapsar
> (`ZVAL_PTR_DTOR = libphp+0x613c50`). Tam zincir, payload ve sürücü için bkz.
> [ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md). Aşağıda orijinal analiz korunmuştur.

Hedef: bir libphp kod adresi elde etmek (örneğin HashTable'ın
`pDestructor = ZVAL_PTR_DTOR`'u), bilinen chunk base ile birlikte g18'in
Zend-only payload'unu (`zif_system`, libphp + `0x43a870`) kullanarak **tamamen saf HTTP,
dış adres olmaksızın** ASLR-on RCE'yi tamamlamak.

Doğrulanmış deney gerçekleri:

- 998 adet `aNNNN[0]` iç içe dizi alanı kullanıldığında, B'nin chunk'ında çok sayıda 56B
  HashTable sayfası belirir; gdb taraması (no-ASLR) bu sayfaların sayfa başına 73 libphp işaretçisi
  içerdiğini gösterir, offset'ler `0x2000, 0x76000, 0x7b000, …, 0xa9000, 0xad000, 0xb2000, …`.
- Mevcut stale `PS(id)` `chunk+0xa9000`'de; bu offset iç içe dizi B'si altında tam olarak
  bir 56B HashTable sayfasıdır. Problem şuna dönüşür: **`PS(id)+0x10`'daki qword'ü bir
  `arData`/hash işaretçisi değil, makul (moderate) bir len yapmak**.
- Uygulanabilir yönler (öncelik sırasına göre):
  1. A'yı ayarlayıp `PS(id)`'yi `HT + 0x18`'e düşürmek (böylece
     `len = nNextFreeElement`, data `HT+0x30 = pDestructor`'dan başlar):
     `PS(id) ≡ page + 0x18 (mod 56)` gerekir; `PS(id)=page+64m`
     (A'nın 64B bin'i) olduğundan `m ≡ 3 (mod 7)`, yani `page+0xc0`, `page+0x280` vb.
     A'nın alan uzunluğu/boundary uzunluğu/dosya alanı şeklini tarayıp ulaşılabilir offset'i bul.
  2. Ya da `PS(id)+0x10`'u `HT+0x20`'ye düşürmek (`len = nTableSize|nInternalPointer`):
     `PS(id) ≡ page + 0x10 (mod 56)` gerekir, bu `m ≡ 2 (mod 7)`'ye karşılık gelir
     (`page+0x80` vb.) ve bu HashTable'ın `nTableSize`'ını yeterince büyük yapmak gerekir
     (örneğin dizi başına 128 eleman → len=128, `pDestructor`'ı kapsamaya yeter).
  3. PS.id'yi libphp işaretçi sayfasının düşük offset'ine (ör. `0x2000`) taşımak — daha küçük bir
     A ön-heap'i ya da farklı bir uyarı tetikleme yöntemi gerekir; şu anda 1001 alan id'yi en düşük
     yaklaşık `0x61040`'e getiriyor.
- libphp base alındıktan sonra, RCE'nin B'si `zif_system` + fake `zend_function`/
  `execute_data` (`tools/d_aslr.php`'nin Zend-only payload yerleşimi) kullanır,
  yalnızca chunk base + libphp base gerekir, libc gerekmez.

---

## 8. Dosyalar

| Dosya | Amaç |
|---|---|
| `tools/send_a_leak2.py` | Sızıntı A: 1001 alan + `max_input_vars` uyarısı + boş/NUL PHPSESSID + dosya + OOM |
| `tools/send_a_leak3.py` | Sızıntı A varyantı: ayarlanabilir alan adı/değer uzunluğu, boundary uzunluğu (`PS(id)`'yi taşımak için) |
| `tools/b_numleak.py` | B: sayısal anahtar, kısa değer (stale bloğun üzerine yazılıp yazılmadığını doğrulamak için) |
| `tools/b_numleak2.py` | **Nihai B**: 48 karakterlik değer 80B bloğu tüketir + 79 baytlık forge alanı |
| `tools/b_consume.py` / `b_consume2.py` | 80B/64B blok tüketim deneyi |
| `tools/b_nested.py` | İç içe dizi B'si (56B HashTable sayfasını chunk'ın her yerine sermek için) |
| `tools/send_b_leak.py` | Erken B (çıplak stale id / sahte başlık prototipi) |
| `tools/decode_leak.py` | `Set-Cookie`'yi decode eder, işaretçi ve chunk base çıkarır |
| `tools/aslr_demo.sh` | ASLR-on doğrulaması: dışarıdan maps okur, 3/3 A/B zincirinin göreli yerleşiminin kararlı olduğunu kanıtlar |
| `logs/http_heap_leak_20261021.resp` | Ham sızıntı yanıtı (4096B çözümlenir / 11548 karakter cookie) |
| `logs/http_heap_leak_20261021.txt` | Çözümlenen işaretçi listesi ve chunk base istatistiği |

---

## 9. Sorumluluk reddi

Yalnızca yetkili ortamlarda güvenlik açığı araştırması ve çoğaltma amaçlıdır. İstek şekilleri,
blok offset'leri ve bin dizileri bu lab'ın PHP 8.4.26 build'ine ve Apache/mod_php yapılandırmasına
bağlıdır; build ya da yapılandırma değişince yeniden kalibrasyon gerekir.
