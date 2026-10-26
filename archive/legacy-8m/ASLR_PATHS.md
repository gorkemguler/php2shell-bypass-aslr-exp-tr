# ASLR yol analizi: saf Zend atlatma vs. adres sızıntısı

Tarih: 2026-10-21
Ön koşul: no-ASLR saf HTTP RCE aşıldı (`NOASLR_REPORT.md`).
Kısıtlar: **tamamen uzaktan, saf HTTP; hedef-tarafı özel PHP kurgulanmaz**. Hedef sayfası yalnızca
sıradan `echo` içerir (session çağrısı yok).

Bu belge yalnızca ASLR açıldıktan sonraki iki yolu analiz eder, eski özel PHP sızıntı/ROP
sonuçlarını geçerli teslimat olarak kabul etmez.

---

## 0. Sonuç özeti

| Yol | Mevcut değerlendirme | Ana takılma |
|---|---|---|
| Yol bir: saf Zend, sızıntısız atlatma | Güvenilir primitif bulunamadı | Tüm kontrollü yazmalar NUL ile biter; partial overwrite mutlaka ASLR ile ilgili bir baytı bozar; bilinen sabit fonksiyon adresi yok |
| Yol iki: saf HTTP adres sızıntısı | Varsayılan yapılandırmada kullanılabilir giriş bulunamadı | Varsayılan `session.serialize_handler=php`, `\|` içeren session key'i reddeder; eski sızıntı `php_serialize` + kullanıcı-alanı `__serialize` reentrancy gerektirir |

"Varsayılan php.ini + vanilla session sayfası" koşulunda ASLR henüz aşılmadı.
Aşağıda yapılan deneyler, kaynak kod dayanakları ve bir sonraki doğrulanabilir atılım noktaları verilir.

---

## 1. Mevcut primitiflerin gözden geçirilmesi

no-ASLR zincirinin kilit yazma primitifi:

1. A isteği OOM olur, sarkan `PS(http_session_vars)` zend_reference'ını (R0) bırakır.
2. B isteğinin 56B ham değer buffer'ı R0'ın üzerine yazabilir ve şunları yazar:
   - `R0+0x00` gc: refcount=1, type=IS_REFERENCE
   - `R0+0x08` val.value: keyfi 8 baytlık işaretçi
   - `R0+0x10` val.type: 0x307 (IS_ARRAY_EX)
   - `R0+0x18` sources: 0
3. dtor yolu:
   `zend_delete_global_variable` → `zval_ptr_dtor` →
   `zend_reference_destroy` → `zend_array_destroy(val.value)` →
   `zend_hash_destroy` → `pDestructor(&bucket->val)`.
4. fake HashTable'ı barındırmak için en iyi konum **canlı 192B zend_string**'in data'sıdır
   (L=167), çünkü gc'si free-list'in next işaretçisiyle üzerine yazılmaz; içerik alan değeridir,
   data+0'dan itibaren kontrollüdür.

Dolayısıyla ASLR altında eksik olan: `val.value` (heap adresi) ve/veya `pDestructor` (libc/libphp
kod adresi).

---

## 2. Yol bir: saf Zend, sızıntısız ASLR atlatma

Hedef: hiçbir sızıntı kullanmadan, doğrudan ASLR'ye duyarsız işaretçi/fonksiyon işaretçisi kurmak.

### 2.1 Plan A: eski reference'ın val.value = A0'ını yeniden kullanmak (gerçek session HashTable)

- A'daki eski reference'ın `val.value`'su gerçek session HashTable A0'a işaret eder.
  no-ASLR'de fiilen A0 = `0x7ffff5e03268` (`R0+0xf48`).
- Eğer B, R0'ın val.value'sunu üzerine yazmaz da A0'ın belleğini saldırgan-kontrollü bir fake
  HashTable yaparsa, heap base'i bilmeye gerek kalmaz.
- Uygulanabilirlik kontrolü:
  - A0 56B'lik bir HashTable yapısıdır (sizeof(zend_array)=56, bin 6).
  - A0'ın `pDestructor`'ı aslında `ZVAL_PTR_DTOR`'dur (libphp işaretçisi).
  - A0'ın **canlı**, içeriği kontrollü bir tahsisle yeniden işgal edilmesi ve `gc.type == IS_ARRAY` olması gerekir.
  - Ama B'de içeriği kontrollü iki tür tahsis var:
    1. `multipart_buffer_read_body`'nin raw value buffer'ı: alan işlendikten sonra
       `efree()` edilir; serbest bırakıldıktan sonra allocator `next_free_slot`'ı blok offset 0'a
       yazar, gc'nin üzerine yazar, bu da `GC_DELREF`'in sıfıra inmemesine ve array dtor'a girmemesine yol açar.
    2. canlı zend_string: gc type'ı IS_STRING (6), `rc_dtor_func` `zend_string_destroy`'i çağırır, `zend_array_destroy`'i değil.
  - Canlı gerçek HashTable doğru type=7'ye sahiptir, ama `pDestructor`'ı gerçek
    `ZVAL_PTR_DTOR`'dur, gc'yi değiştirmeden onu değiştiremeyiz.
- Sonuç: A0 yeniden kullanımı "canlı, kontrollü, type=IS_ARRAY" bir tahsis gerektirir, şu anda yok.

### 2.2 Plan B: partial pointer overwrite (libphp yüksek baytını koruyarak)

Fikir: A0'ın `pDestructor`'ını `ZVAL_PTR_DTOR`'dan libphp içindeki başka bir fonksiyon/gadget'a
çevirmek, yalnızca düşük 2–3 baytı üzerine yazıp libphp base yüksek baytını korumak. Böylece sızıntı gerekmez.

İki sorun çözülmeli:

1. **A0+0x30'a yazıp yalnızca düşük baytı üzerine yazmak mümkün mü?**
   - String/raw buffer yazması her zaman bir NUL taşır:
     `zend_string_init` data[len]'e 0 yazar; `multipart_buffer_read_body`
     out[total]'a 0 yazar.
   - `pDestructor`'dan itibaren N bayt yazılırsa, N. bayt mutlaka 0'dır.
   - Örneğin düşük 2 baytı üzerine yazmak: `b0,b1` kontrollü, `b2=0`; düşük 3 baytı üzerine yazmak: `b0..b2` kontrollü, `b3=0`.
   - Hedef libphp adresinin yüksek baytlarında `b3/b4/b5` hepsi ASLR rastgeleliği taşır; onları 0'a
     zorlamak yalnızca hedefin mutlak adresinin ilgili baytı zaten 0'sa işe yarar. Bu base'e bağlıdır, güvenilir değildir.
2. **2–3 bayt aralığında kullanışlı bir target bulunabilir mi?**
   - Mevcut build'in libphp sembolleri fiilen ölçüldü (strip edilmemiş):
     ```text
     zif_system          0x43a870
     zend_call_function  0x566d20
     zend_hash_destroy   0x5cbb90
     zend_array_destroy  0x5cbdc0
     zval_ptr_dtor       0x613c50
     ```
   - `zval_ptr_dtor` ile `zend_call_function` arasında 0xacf30 (~700KB) mesafe var,
     `zif_system` ile arasında 0x1d93e0 (~1.9MB) mesafe var.
   - Düşük 2 bayt partial overwrite yalnızca aynı 64KB içinde atlayabilir; düşük 3 bayt artı
     zorunlu NUL'un b3=0'ı yine base baytına bağlıdır. Şu anda aynı 64KB'a düşen kullanılabilir gadget yok.
   - libphp yalnızca `popen` import eder (`objdump -T` gösterir), `system` import etmez;
     `popen@plt` da libphp base gerektirir ve ikinci parametre rsi kontrol edilemez.
   - Eski istihbaratın `zend_call_function → zif_system`'i fake FCI gerektirir, libphp base gerektiren başka bir zincirdir.

Sonuç: partial overwrite şu anda "saf Zend" fikrine en yakın yöndür, ama NUL sonlandırıcı sert
bir takılmadır; **sonlandırıcı taşımayan, keyfi uzunlukta önek yazma** bulunmadıkça.

### 2.3 Plan C: allocator'ın kendi yazdığı işaretçi (free-list next / shadow)

- Serbest bırakılan bloğun offset 0'ında açık `next_free_slot` (heap işaretçisi), offset size-8'de
  XOR kodlu shadow bulunur.
- Eğer fake reference'ın val.value'su bir serbest bloğun `next_free_slot` konumuna konursa, allocator bizim yerimize gerçek bir heap işaretçisi yazar.
- Ama o işaretçi **başka bir serbest bloğun başlangıcına** işaret eder, onun offset 0'ı da next işaretçisidir, geçerli bir array gc değildir; `GC_DELREF` sıfıra inmez.
- Hizalamada, R0+8'in bir bin'in slot başlangıcı olması gerekir; R0=0x...2320 iken,
  R0+8=0x...2328'i yalnızca 8B bin tam böler (sayfa içi offset 0x328=808=8×101),
  8B blokta kontrollü içerik yoktur.
- Sonuç: "kontrollü fake HashTable'a işaret eden bir heap işaretçisi" doğrudan elde edilemez.

### 2.4 Plan D: sabit adresli kod

- Apache ana programı PIE'dir (`file /usr/sbin/apache2` = pie executable),
  `libphp.so`, libc hepsi ASLR'ye tabidir.
- Tek sabit yürütülebilir sayfa vsyscall `0xffffffffff600000`'dur, yalnızca
  gettimeofday/time/getcpu içerir, keyfi syscall/RCE yapamaz.
- Ana program/modüller hiçbirinde doğrudan kullanılabilir `system@popen@execve` sabit PLT'si yoktur (import'lar kontrol edildi; ayrıca PIE base rastgele).
- Sonuç: kullanılabilir sabit kod adresi yok.

### 2.5 Yol bir özeti

Mevcut primitifler altında, saf Zend sızıntısız atlatma şunlardan birini gerektirir:

- **NUL taşımayan partial write** (A0->pDestructor düşük baytını değiştirip yüksek baytı koruyabilir);
- **canlı, kontrollü, type=IS_ARRAY bir tahsis** (A0'ı yeniden işgal edebilir);
- **allocator'ın kendi yazdığı işaretçi + kontrollü içerik** kombinasyonu;
- aynı 64KB içinde saldırıyı tamamlayabilen bir libphp gerçek fonksiyon işaretçisi.

Bunların hiçbiri şu anda kanıtlanmadı. Bir sonraki en değerli iş, libphp içinde
`zval_ptr_dtor` yakınındaki 64KB'daki gadget/fonksiyonları ölçmek ve "N bayt sonlandırıcısız
yazan" bir PHP tahsis yolu olup olmadığını aramaktır.

---

## 3. Yol iki: saf HTTP adres sızıntısı

Hedef: heap chunk base / libphp base / libc base'i HTTP yanıtına sızdırmak, sonra no-ASLR
zinciriyle adresleri dinamik hesaplamak.

### 3.1 Varsayılan yapılandırma altında session serileştiricisinin kısıtı (denendi)

Varsayılan:

```ini
session.serialize_handler = php
session.use_only_cookies = 1
```

Varsayılan `php` encoder, her session key'i yazmadan önce:

```c
smart_str_appendl(&buf, ZSTR_VAL(key), ZSTR_LEN(key));
if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {
    /* key '|' içeriyor: tüm encode'dan vazgeç, NULL döndür */
    fail = true;
    break;
}
smart_str_appendc(&buf, PS_DELIMITER);
php_var_serialize(&buf, struc, &var_hash);
```

Fiilen (gdb `ps_files_write`):

```text
progress key = upload_progress_X|E:20:"AAAAAAAAAAAAAAAAAAAA";
FWRITE key=injtest0005 klen=11 vlen=0
php_session_decode len=0
```

Yani: progress key `|` içerince, encoder doğrudan NULL döndürür, session boş yazılır;
END cleanup'ın okuduğu session data uzunluğu 0'dır. **Varsayılan yapılandırmada key enjeksiyonu
ile keyfi serialized veri kullanılamaz.**

Varsayılan decoder de C string parse'ı değildir:

```c
while (*q != PS_DELIMITER) {
    if (++q >= endptr) { retval = FAILURE; goto break_outer_loop; }
}
```

NUL, `|` ayıracını atlayamaz.

### 3.2 Eski sızıntı primitifinin bağımlılıkları (mevcut kısıtı karşılamaz)

`NOTES.md` bölüm 10'daki iki sızıntı da şunlara bağlıdır:

1. `session.serialize_handler = php_serialize` (varsayılan değil; script `ini_set` ya da uygulama yapılandırması).
2. Kullanıcı-alanı sınıfı `C::__serialize()` encode sürecinde `$_SESSION` dizisini serbest bırakır, sonra `zend_reference`/`stream_bucket_new` ile yeniden işgal eder, encoder UAF'si yaratır.
3. Uygulama `session_encode()` çağırır ve sonucu okunabilir bir yere çıktılar/kaydeder.

Mevcut hedef sayfası yalnızca sıradan `echo` içerir, kullanıcı-alanı sınıfı yoktur,
`session_encode()` çıktısı da yoktur; varsayılan handler ise `php`'dir. Bu yüzden bu iki sızıntı
bu kısıt altında ulaşılamaz.

### 3.3 Saf HTTP altında kontrol edilebilir session veri yüzeyi

Varsayılan yapılandırmada, saldırganın etkileyebileceği ve session dosyasına girebileceği yalnızca:

- progress key (key adı, `|` içeremez);
- progress data dizisinin sabit anahtarları/değerleri:
  `start_time`, `content_length`, `bytes_processed`, `done`,
  `files[0].field_name`, `files[0].name`, `files[0].tmp_name`,
  `files[0].error`, ...
- Bunlardan `field_name`/`name` saldırgan string'idir, ama **serileştirilmiş değer**
  (`s:<len>:"...";`) olarak yazılır, binary-safe'dir, key ya da enum olamaz.

session decoder'ın okuduğu yapı PHP'nin kendisi tarafından üretilir; saldırgan-kontrollü
`E:`/`O:`/`C:`/`R:` söz dizimi yoktur, değişkenler arası enjeksiyon da yoktur.

### 3.4 Aday sızıntı noktaları ve takılmalar

| Aday | Sonuç |
|---|---|
| progress key'e serialized `E:` enjeksiyonu → enum uyarısı `%.*s` | Varsayılan `php` encoder `\|` içeren key'i reddeder; 0 bayt yazar |
| `E:` uzunluk sınır-dışı okuma | `maxlen < len` kontrolü, len girdi buffer uzunluğuyla sınırlı |
| session dosyasını sızıntı taşıyıcısı olarak kullanmak | Önce encoder OOB yazması gerekir; varsayılan encoder'da yok |
| `unserialize` yerleşik sınıf handler'ının OOB/uyarısı | Varsayılan yapılandırma `O:`/`C:` enjekte edemez; progress data yalnızca dizi/string içerir |
| Hata mesajı `%p`/işaretçi formatı | session/unserialize yolunda `%p` yok; yalnızca enum'un `%.*s`'i var |
| `session_start` uyarısının id/path yazdırması (yalnızca uygulama çağırırsa bu aday var) | Bellek adresi içermez; id karakterleri kısıtlı |
| `/proc/self/maps` | Hedef-tarafı PHP'nin dosya okumasını gerektirir, kısıtı ihlal eder |

### 3.5 php.ini'yi değiştirmeye izin verilirse (uygulama PHP'si değil)

`session.serialize_handler`'ı `php_serialize` yaptıktan sonra:

- progress key'deki `|` artık encoder tarafından reddedilmez (`php_serialize`,
  `php_var_serialize` ile tüm diziyi serileştirir, key'in `|`'sini kontrol etmez);
- key ile ek session değişkenleri enjekte edilebilir, decode warning'i/yerleşik sınıf handler'ı tetiklenebilir;
- ama eski iki sızıntı yine "encode sırasında session dizisini serbest bırakma" reentrancy'si gerektirir, vanilla sayfada bu reentrancy yoktur.

Dolayısıyla INI değiştirilse bile otomatik olarak sızıntı olmaz; yine saf PHP yerleşik bir
reentrancy gadget'ı gerekir, şu anda bulunamadı.

---

## 4. İki yolun bir sonraki deneyi

### Yol bir (saf Zend)

1. **libphp yerleşimini ölçmek**: `nm -D`/`objdump` ile
   `zval_ptr_dtor`, `zend_call_function`, `zif_system`, `system@plt` offset'lerini al, aynı 64KB/16MB içinde kullanılabilir bir partial target olup olmadığını doğrula.
2. **Sonlandırıcısız yazma bulmak**: `erealloc` büyümesi, stream bucket, `smart_str` vb. yolların "yalnızca önek kopyalayıp NUL yazmayan" bir tahsis içerip içermediğini kontrol et; varsa, A0->pDestructor'a gerçek bir düşük bayt partial overwrite yapılabilir.
3. **A0 canlı yeniden işgal**: B'de A0'ı (56B HashTable) **canlı** kontrollü bir tahsisle yeniden işgal etmeyi ve `gc.type=IS_ARRAY` tutmayı dene; örneğin:
   - session decode ile gerçek küçük dizi üret, A0'a düşsün;
   - sonra yalnızca pDestructor düşük baytını üzerine yazıp gc'yi kapatmayan bir yazma yap.
4. **allocator işaretçi hizalaması**: A'nın parametrelerini (progress key uzunluğu, SID uzunluğu, dosya sayısı/boyutu) tara, R0'ın kayıp kaymadığına bak, R0+8'in daha büyük bir bin'in slotu olmasını sağla, böylece free-list next işaretçisiyle "kontrollü işaret eden" bir heap işaretçisi elde et.

### Yol iki (sızıntı)

1. **Yalnızca varsayılan yapılandırmada** saldırgan string'ini warning'e çıktılayabilen tüm yolları say (`php_error`'ın `%s`/`%.*s`'i), uzunluğu doğrulanmayan bir `%.*s` olup olmadığını doğrula.
2. **Yerleşik `Serializable` sınıf handler fuzz'u**: `ArrayObject`, `SplObjectStorage`, `DateTime`, `SimpleXMLElement`, `ZipArchive`, `Phar` vb.'nin `unserialize()` C uygulamasında sınır-dışı okuma/girdiyi warning'e yazan bir yol ara. Dikkat: varsayılan yapılandırma şu anda `C:`/`O:` session'a enjekte edemez, bu yüzden bu yalnızca `php_serialize` ya da uygulama-kontrollü session verisi varken anlamlıdır.
3. **progress data'nın değerleri**: `field_name`/`name`/`tmp_name`'in herhangi bir hata yolunda `%.*s` ile yazdırılıp yazdırılmadığını doğrula; şu anda kaynak kodda bulunamadı.
4. **BG(unserialize) yazma primitifi**: saf HTTP altında `serialize_lock` bağımlılığı aşılabilirse, `var_push`'ın keyfi yazması bir `zend_string.len` forge edebilir, sonra `%.*s` warning'i tetikleyip sızdırabilir. Bu zincir şu anda uygulama katmanı `__wakeup`/autoload gerektirdiği için duraklatıldı.

---

## 5. Kısıt altındaki değerlendirme

- **Saf Zend sızıntısız**: teorik olarak en zarif, ama "NUL sonlandırıcı + sabit kod adresi yok" ile kısıtlı; şu anda güvenilir bir kurgu yok.
- **Adres sızıntısı**: varsayılan `php` serileştirici altında, progress key enjeksiyonu encoder'ın `memchr('|')`'si tarafından doğrudan reddedilir; eski sızıntı ise varsayılan-olmayan serileştirici + kullanıcı-alanı reentrancy gerektirir. Saf HTTP, uygulama kodu olmadan sızıntı girişi henüz bulunamadı.
- **Varsayılan-olmayan php.ini**'ye izin verilirse (`session.serialize_handler=php_serialize`), key enjeksiyonu + yerleşik sınıf handler araştırılmaya devam edilebilir; bu hâlâ "özel PHP yazmak" değildir, ama varsayılan yapılandırmadan sapmıştır.
- Hedef uygulamada bir session nesnesi/progress uç noktası (uygulama gadget'ı) olmasına izin verilirse, eski `php_serialize` sızıntı zinciri yeniden kullanılabilir; bu uygulama katmanı bağımlılığıdır, mevcut "vanilla session sayfası" kısıtına uymaz.

Sıkı kısıt altında, mevcut teslimat açıkça **no-ASLR RCE** olarak işaretlenmelidir; ASLR'nin iki
yolu da tamamlanmadı, yukarıdaki deneylerden birinin atılım sağlaması gerekir.

---

## 6. Ek: sabit Zend offset fiilî ölçümü (2026-10-21)

Kullanıcının "Zend'de bazı adresler sabit olabilir" uyarısından sonra, aşağıdaki ölçümler yapıldı.

### 6.1 Sabit offset'ler

ASLR açık (`randomize_va_space=2`) altında, A/B tetiğiyle
`php_session_track_init`'te okunan:

- Eski reference R0 = **chunk + 0x2320**, üç master yeniden başlatmasında da aynı.
- session HashTable A0 (R0->val.value):
  - A'nın PHPSESSID uzunluğu 8..32: A0 = **chunk + 0x3268**
  - A'nın PHPSESSID uzunluğu 1..5: A0 = **chunk + 0x3230**
- Zend main chunk base'i 2MB hizalı.
- Aynı Apache master'ı altında, worker'ı ardışık 5 kez kill -9 yapınca, yeni worker'ın chunk
  base'i hiç değişmiyor (ör: `0x7fa32de00000`, B=7). Yani:
  - **Bir master yaşam döngüsü içinde chunk base'i sabittir**;
  - ama master yeniden başlatma yeniden rastgeleleştirir, worker çökmesi B'yi tekrar denemeye izin vermez.

### 6.2 chunk header'ı bir kod tramplini değildir

chunk+0x000..0x100 dump'ı:

- `heap`/`next`/`prev`/`free_slot[]` hepsi heap işaretçisi;
- `size`/`peak`/`chunks_count`/`pid` küçük tam sayılar;
- libphp/libc kod işaretçisi yok.
- 1 bayt partial write yalnızca eski val.value'yu `chunk+0x00XX`'e işaret ettirebilir,
  tam olarak header'a düşer, kullanılabilir pDestructor yok; 2 bayt partial write
  b2'yi sıfırlar (16MB blok içinde 2MB indeksinin düşük 3 biti), fiilen o slot kütüphanenin
  salt-okunur `.eh_frame` verisidir, kontrollü bir Zend chunk değildir.

### 6.3 A0'ın eski içeriği

A0=chunk+0x3268'deki eski HashTable:

```text
A0+0x00 gc        = 0xffffffff00000106   (refcount 1 değil)
A0+0x10 arData    = chunk+0x33c0
A0+0x30 pDestructor = libphp zval_ptr_dtor (gerçek kod işaretçisi)
```

refcount 1 olmadığı için, val.value üzerine yazılmazsa dtor yalnızca referansı azaltır,
`zend_array_destroy`'e girmez; bu yüzden daha önce reference forge etmek zorunluydu.

### 6.4 Yeni primitif: ikili PHPSESSID ile A0'ın gc'sine yazmak

- `php_session_valid_key()` C string taraması kullanır; PHPSESSID değeri
  `validprefix\0<binary>` olabilir, NUL'dan sonraki ikili (binary) yine
  `progress->sid` / `PS(id)`'nin zend_string'ine girer.
- `PS(id)` doğrudan `zend_string_init`'tir, onun raw değer buffer'ı önce serbest bırakılır, ardından
  320B'lik PS(id) bu slotu yeniden kullanır.
- Fiilen: SID uzunluğu 280, `sidvalid\0...` + SID offset 0x110'a fake gc konur, B'nin
  track_init anında **A0'ın ilk qword'ü `0x0000000700000001` olur**, chunk base'i bilmeye
  hiç gerek yok.
- Bu 320B canlı string page3 slot 0x3140'ta (data 0x3158),
  A0=0x3268 tam olarak data+0x110'dur.
- Bu şu anlama gelir: **gc (refcount=1, type=IS_ARRAY) A0'a göreli olarak yazılabilir.**

### 6.5 Hâlâ çözülmeyen: pDestructor / arData

- A0=0x3268 iken, pDestructor A0+0x30=0x3298'de, zaten **bir sonraki 320B slota** (0x3280) geçmiş; fiilen orası B'nin 320B tahsisi tarafından `0xffff...`'e yazılmış, eski gerçek `zval_ptr_dtor` kaybolmuş.
- A'nın SID'ini 1..5'e değiştirirsek, A0=0x3230, pDestructor aynı 320B slot içine düşer; ama:
  - gc/flags/arData'yı üzerine yazmak/kontrol etmek için 320B string uzunluğu ≥257 olmalı, oysa
    pDestructor data offset 0x108=264'te, string copy pDestructor'ı **tamamen üzerine yazar** (yüksek baytı koruyamaz);
  - pDestructor'ı korumak için uzunluk ≤263 olmalı, bu durumda arData (data offset
    0xd8+0x10=232) zaten üzerine yazılmış, mutlak bir işaretçi yazmak gerekir, ama base bilinmiyor;
  - arData'ya dokunmadan yalnızca gc/flags'i üzerine yazmak için L<232 gerekir, ama 320B bin L≥257 gerektirir; bin boyutu ile copy uzunluğu bağlı, yapılamaz.
- 8B header key planı da başarısız: R0+8=0x2328 page2 içinde yalnızca 8B slot 101 hizalı, oysa page2 başlangıç dönemi 56B tahsisi tarafından işgal edilmiş (MAP2=bin6), bin0 değil; ayrıca 8B bloğun free-list shadow'u zaten tüm 8 baytı kaplar, eski yüksek baytı koruyamaz.

### 6.6 Sonuç

Sabit Zend offset'leri gerçek ve kullanılabilir:

- R0, A0, fake HT'nin chunk'a göre offset'leri sabit;
- Aynı master içinde chunk base'i sabit;
- Eski gerçek `zval_ptr_dtor` işaretçisi A0+0x30'da.

Ama yalnızca bunlarla ASLR aşılamaz, çünkü:

1. pDestructor yüksek baytını korumak için **NUL yazmayan, yalnızca önek değiştiren** bir partial write gerekir;
2. ya da arData'yı **mutlak adresi kontrollü** bir fake bucket'a işaret ettirmek gerekir;
3. mevcut tüm kullanılabilir yazmalar "tam segment copy + NUL sonlandırma"dır ve bin geometrisi sabittir, yukarıdaki iki yöntem de kurulamadı.

Devam etmek için en değerli bir sonraki adım:
- A parametreleriyle A0'ı bir adrese taşı, "string data'sı pDestructor+1'de bitsin" ile bin/slot geometrisi aynı anda sağlansın (şu anda 0x3230/0x3268 ikisi de sağlamıyor);
- ya da "yalnızca N bayt yazan, sonlandırıcı taşımayan" herhangi bir Zend tahsis/copy yolu bul;
- ya da önce chunk base'i sızdır (aynı master içinde sabit, tek sızıntı yeniden kullanılabilir).

---

## 7. Ek: A0 biçimi ve page3 bin fiilî ölçümü

### 7.1 A0 yalnızca iki değer değil

A'nın PHPSESSID uzunluğunu ince tara (no-ASLR, page3 sabit 320B bin):

| A SID uzunluğu | A0 (chunk offset) | A0+0'daki gc | A0+0x30 |
|---|---|---|---|
| 1–13 | `0x3230` | `0x80000000005978e8` (array HashTable değil) | `0x7ffff5e61208` |
| 14–21 | `0x3268` | `0xffffffff00000106` (refcount devasa) | gerçek `zval_ptr_dtor` |
| 22–23, 32–40 | `0x3230` | yukarıdaki gibi | pDestructor değil |
| **24–30** | **`0x3310`** | **`0xc000040700000001`** (rc=1, type=IS_ARRAY) | **gerçek `zval_ptr_dtor`** |

`0x3310`, ilk kez ortaya çıkan "kendisi doğrudan HashTable olarak kullanılabilen" A0'dır:

```text
A0=chunk+0x3310
A0+0x00 = 0xc000040700000001   gc: rc=1, type=IS_ARRAY
A0+0x10 = chunk+0x4900/0x4540  arData (gerçek heap işaretçisi)
A0+0x30 = libphp zval_ptr_dtor (gerçek kod işaretçisi)
```

Yani, **gc/flags forge etmeye gerek yok**, stale reference'ın val.value=A0'ı,
`zend_array_destroy(A0)` gerçek array yolunu izler.

### 7.2 page3'ün bin'i sabittir

ASLR/no-ASLR altında, B'nin chunk page map'i her zaman şöyledir:

```text
page1 bin3 (32B)
page2 bin6 (56B)
page3-7 bin16 (320B)
page8-12 bin20 (640B)
```

Özel istek başlığı `X-Pad: A*N` (N=0/96/320/480/700/1000) ile test edildi, page map hiç değişmiyor.
gdb `zend_mm_alloc_small_slow`'da ilk 320B tahsisini yakalar:

```text
zend_mm_alloc_small_slow(bin_num=16)
  zend_hash_real_init_mixed_ex
  zend_hash_real_init_mixed
  _zend_hash_add_or_update_i
  zend_hash_add
```

İlk 640B tahsisi aynı HashTable'ın `zend_hash_do_resize`'ıdır. Dolayısıyla page3'ün
320B bin'i başlangıç dönemi HashTable arData'sının sabit tahsisidir, **istek başlığı/alanla değiştirilemez**.

### 7.3 320B slot geometrisi ve A0=0x3310

A0=0x3310, page3'ün 320B slot2'sinde (block `0x3280`, data `0x3298`):

```text
A0 = 0x3310 = slot2 data + 0x78
arData       = A0+0x10 = slot2 data + 0x88
nNumUsed     = A0+0x18 = slot2 data + 0x90
pDestructor  = A0+0x30 = slot2 data + 0xa8
```

- slot2'deki bir 320B zend_string'in data'sı 0x3298'den başlar, uzunluğu yalnızca 232..295 olabilir.
- pDestructor'ı (data offset 0xa8=168) üzerine yazmak/kontrol etmek için ≥168 uzunlukta copy gerekir; ama 320B bin'in minimum uzunluğu 232'dir, bu yüzden copy **mutlaka aynı zamanda arData'nın** (offset 0x88=136) ve öndeki gc/flags'in üzerine yazar.
- Yalnızca pDestructor bayt 0'ını NUL'lamak için (yüksek baytı korumak) L=168 gerekir; bu alloc=193 → **224B bin**'e karşılık gelir, 320B slot2'yi işgal edemez.
- arData'yı korumak için (üzerine yazmamak) L<136 gerekir; 320B slotu işgal etmek daha da imkânsız.
- Bu yüzden A0=0x3310'un gc'si geçerli olsa da, yine "copy uzunluğu vs bin boyutu" tarafından takılır: arData'yı korurken pDestructor'a partial overwrite yapılamaz.

### 7.4 Mevcut değerlendirme

- Sabit Zend offset'leri gerçekten var ve A0=0x3310 gerçek, rc=1 bir kontrollü başlangıç noktası sağlıyor;
- ama page3'ün 320B bin'i sabit, 320B slotun data uzunluk penceresi (232..295) A0'ın iç alan offset'leriyle (arData 136, pDestructor 168) eşleşmiyor;
- yine "yalnızca önek yazan, NUL taşımayan" bir yazma primitifi, ya da arData'yı kontrollü veriye işaret ettirebilen bir göreli işaretçi eksik.

Bu hat şu anda kapanmıyor; no-ASLR RCE hâlâ tek doğrulanmış kod yürütmesidir.
