# 172.16.0.103 üzerinde pre-RINIT `BG(unserialize)` istekler-arası primitifi

Tarih: 2026-10-21
Hedef: Debian 12.15, Apache/2.4.68 prefork/mod_php, PHP 8.4.26 kendimiz derledik
(`memory_limit 8M`, `session.upload_progress.enabled=On`, `cleanup=On`,
`session.use_cookies=0`).
Aşağıdaki tüm çalışma `172.16.0.103` üzerindedir; uzak kısımlar için hedef-tarafı
PHP exploit dosyası kullanılmaz.

## 1. Yeni istihbaratın değiştirdikleri

upload_progress hattı öncelikli olarak bir progress-bucket UAF'si değildir. Gerçek
istekler-arası primitif **pre-RINIT** session decode yoludur:

- `session.upload_progress` multipart işlemesi, `PHP_RINIT_FUNCTION(basic)`'ten önce çalışır.
- Orada bir session decode OOM'u, istekler arasında `BG(unserialize).level = 1` (ve gecikmeli-`__unserialize` durumunda `BG(serialize_lock) = 1`) bırakır.
- İstek B'nin pre-RINIT decode'u (`php_var_unserialize_init`), RINIT `BG(unserialize)`'i temizlemeden önce hâlâ bu durumu görür.

Bu, istihbaratın "pre-RINIT aşamasında BG(unserialize) durumunun istekler-arası
kalıntısından kaynaklanan UAF" ifadesiyle tutarlıdır.

## 2. 8.4.26'da doğrulandı

### 2.1 A/B upload_progress primitifi

`tools/sup_poc.py a` (dosya kısmından sonra 12MB alan) + `b` (dosyasız):

- A, `Allowed memory size of 8388608 bytes exhausted` döner.
- B, beklenen uyarıları döner:
  `Session ID is too long or contains illegal characters`,
  `Failed to read session data: files (path: /tmp)`.
- Bu build'de B çökmez; worker hayatta kalır.

### 2.2 Decode-genişleme OOM'u BG level=1 bırakır

`x|a:300000:{...}` içeren session dosyası (diskte 5.1MB, decode sırasında >8MB'ye genişler):

```text
Fatal error: Allowed memory size ... (tried to allocate 20971520 bytes)
Warning: PHP Request Startup: Failed to decode session object. Session has been destroyed
```

İstekten sonra, aynı worker'da gdb:

```text
basic_globals.unserialize.level = 1
basic_globals.unserialize.data  = 0x7ffff5e78000
basic_globals.serialize_lock    = 0
struct: last=0x7ffff5e78038 first_dtor=0x7ffff5e7b000
        entries.used_slots=1, entries.next=0
```

Yani üst düzey `php_unserialize_data` hâlâ tahsisli ve satır-içi (inline)
`entries`'i sağlam. Bu bir istekler-arası durum sızıntısıdır, ama henüz serbest
bırakılmış bir nesne değildir.

### 2.3 Gecikmeli `__unserialize` OOM'u ile serbest bırakılmış `var_entries`

Büyük bir `SplFixedArray` nesnesi içeren bir session:

```text
x|O:13:"SplFixedArray":100000:{i:0;i:0; ... i:1024;i:1024; i:1025;R:2; ...}
```

- İlk 1025 değer satır-içi `entries`'i doldurur ve fazladan bir `var_entries` tahsisini zorlar.
- Geri kalan geri referanslardır (`R:2;`) böylece decode daha fazla entry push etmez.
- Decode başarılı olur, ardından `PHP_VAR_UNSERIALIZE_DESTROY` → `var_destroy`:
  1. fazladan `var_entries` zincirini serbest bırakır,
  2. gecikmeli `SplFixedArray::__unserialize`'i çağırır,
  3. bu çağrı `size * sizeof(zval)` tahsis eder ve OOM olur.

OOM bailout'unda GDB:

```text
BAILOUT BG.level=1 data=0x7ffff5f9b000
#9  spl_fixedarray_init_non_empty_struct (size=100000, array=0x7ffff5f9f000)
#10 zim_SplFixedArray___unserialize
#11 zend_call_function
```

İstekten sonra:

```text
serialize_lock = 1
unserialize.level = 1
unserialize.data = 0x7ffff5f9b000
data->last = 0x7ffff5fa0000      <- serbest bırakılmış var_entries chunk'ı
data->entries.next = 0x7ffff5fa0000
```

Bu gerçek bir UAF'dir: `data->last` serbest bırakılmış 8160 baytlık bir `var_entries`
chunk'ına işaret eder. `serialize_lock` 1'de bırakılmıştır, çünkü OOM gecikmeli
çağrının çevresindeki `serialize_lock++/--` penceresinden bailout etti.

### 2.4 Bu build'deki yapı boyutları

```text
sizeof(struct php_unserialize_data) = 8216
sizeof(var_entries)                 = 8160   (VAR_ENTRIES_MAX = 1018)
sizeof(var_dtor_entries)            = 4096
sizeof(zend_object)                 = 56     (handlers +0x8'de)
```

İstihbaratın 8216 baytlık nesnesi `struct php_unserialize_data`'nın kendisidir;
serbest bırakılan `var_entries` bu build'de 8160/8192'dir.

## 3. Uzaktan büyük session oluşturma

N baytlık bir `PHP_SESSION_UPLOAD_PROGRESS` değeri bir session key'i
`upload_progress_<N bayt>` olur, bu yüzden büyük bir progress alanı herhangi bir
uygulama kodu olmadan büyük bir session dosyası oluşturur:

- N = 1 MiB + session yazımından sonra OOM'u zorlamak için 12MB alan:
  `/tmp/sess_<sid>` = 1.048.900 bayt ve tam/geçerli bir serileştirmedir
  (doğrulandı: `}}}` ile biter; key + progress dizisi).
- N = 2 MiB / 3 MiB: dosya yok, istek session yazımından önce OOM olur.
- Tekrarlanan büyüme istekleri dosya boyutunu 1.048.900 / eksik arasında değiştirir:
  mevcut bir session'ı decode eden bir OOM isteği
  `php_session_cancel_decode` → `session_destroy`'i tetikler, bu da dosyayı siler (unlink).

Yani upload_progress uzaktan **değeri sabit progress dizisi olan geçerli ~1MB bir
session** oluşturabilir ve yazımdan sonra OOM yaparak onu geride bırakabilir.

## 4. Tam istihbarat zinciri için mevcut engel

İstihbarat zinciri, ilk isteğin session değerinin saldırgan tarafından kurulmuş
serileştirilmiş bir nesne (`SplFixedArray` / forge edilmiş `var_entries` / vb.)
olmasını gerektirir. `session.upload_progress` yalnızca sabit progress dizisini
yazabilir; key'i ve string alanları uzunluk-önekli serileştirmedir, bu yüzden
session dosyasına bir `O:...` değeri enjekte edemezler. Dolayısıyla 3–6. adımlara
ulaşmak şunlardan birini gerektirir:

1. `$_SESSION`'da kullanıcı-kontrollü serileştirilmiş veri saklayan bir hedef uygulama (yaygın gerçek-dünya durumu), ya da
2. `/tmp/sess_<id>` için başka bir uzak dosya-yazma primitifi, ya da
3. saldırgan tarafından kontrol edilebilen farklı bir session serileştiricisi/INI yapılandırması.

Bu 8.4.26 build'inde, ek `serialize_lock=1` durumu ayrıca bir sonraki pre-RINIT
`php_var_unserialize_init`'in `BG(unserialize).data`'yı yeniden kullanmak yerine
yeni bir yerel `php_unserialize_data` tahsis ettiği anlamına gelir; istihbaratın
"serbest bırakılmış `data` sonra yeniden kullanılır" adımı 8.5.4'ün
destroy/cleanup yoluna ya da bir uygulama `unserialize()`/`session_decode()`
çağrısına bağlı olabilir. Bunun 8.5.4 kaynağına/hedefine göre yeniden kontrol
edilmesi gerekir.

## 5. Kullanışlı varlıklar (artifacts)

- `tools/mk_splref.py` — serbest bırakılmış `var_entries`'i üreten `SplFixedArray` session payload'unu üretir.
- `tools/bg_make.py` / `tools/bg_create.py` — devasa bir progress key ile uzaktan büyük session oluşturma.
- `tools/sup_poc.py` — A/B upload_progress harness.
- `logs/g18_ASLR_ZEND_103.md` — ayrı uygulama-düzeyi ASLR-on yalnızca-Zend sonucu (referans için tutuldu; "hedef PHP yok" kısıtını karşılamaz).
