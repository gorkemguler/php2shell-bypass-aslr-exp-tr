# php:8.4.26-apache / Debian 13 (trixie) / x86_64

Kayıt tarihi: 2026-10-23
Durum: uçtan uca doğrulama geçti (`uid=33(www-data)`)

## Build kimliği

| Alan | Değer |
|---|---|
| İmaj | `php:8.4.26-apache` |
| İmaj digest (kayıt anında) | `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` |
| image ID | `46b195b6378e` |
| Dağıtım (distro) | Debian GNU/Linux 13 (trixie) |
| Mimari | x86_64 |
| PHP | 8.4.26 (NTS, mod_php), build Oct 21 2026 00:31:19 |
| Apache | 2.4.69 (Debian) |
| libphp.so | `/usr/lib/apache2/modules/libphp.so` |
| libphp SHA-256 | `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` |
| libphp GNU build-id | `a534a5c4a890b378ef6c227590627d531eafa8ce` |

Eşleştirirken öncelikle `libphp.so`'nun SHA-256 / build-id'sine bakın; imaj tag'i registry
yeniden build edildikçe değişir.

## libphp sembol offset'leri

libphp yükleme base adresine göreli:

| Sembol | Offset | Bağlama (binding) |
|---|---|---|
| `zval_ptr_dtor` | `0x65EB60` | GLOBAL |
| `zif_system` | `0x465370` | LOCAL |
| `zif_passthru` | `0x465380` | LOCAL |

Çalışma zamanı adresi = `libphp_base + offset`. Zincir, sınır-dışı pencerede tekrar eden
`zval_ptr_dtor` üzerinden `libphp_base = değer - 0x65EB60` olarak geri hesaplar.

## Heap / yapı (struct) offset'leri

Mevcut 128M resmi yapılandırma, `files` session handler, tek worker baseline / resmi worker'ın
aynı child'a sabitlendiği zincir:

| Ad | İfade | Açıklama |
|---|---|---|
| fake zend_array `S` | `main_chunk + 0xF8398` | stage-3 sahte HashTable |
| A2 sonrası `hsv` | `main_chunk + 0x7D720` | `PS(hash_serialize_verifier)` heap'e işaret eder |
| `PS(id)` | `ps_globals + 0x10` | |
| `PS(mod_data)` | `ps_globals + 0x60` | 40B `ps_files` |
| `PS(send_cookie)` | `ps_globals + 0x15E` | 1 bayt |
| `PS(hash_serialize_verifier)` | `ps_globals + 0x168` | |
| main chunk parmak izi (fingerprint) | 2MiB küme içinde 87 işaretçi | sızıntı penceresinde sayımı 87 olan küme alınır |
| id chunk / libphp kümesi | 7495 / 1095 işaretçi | 0xC8000 (800KB) pencere |

Bu heap offset'leri mevcut PHP build'ine ve 128M yapılandırmasına bağlıdır; sürüm/yapılandırma
değişince yeniden kalibrasyon gerekir.

## Hedef yapılandırma

- Resmi `php.ini-production`: `display_errors=Off`, `memory_limit=128M`,
  `post_max_size=8M`, `max_input_vars=1000`
- Resmi prefork: `StartServers 5`, `MaxRequestWorkers 150`
- Exploit sırasında `--workers 150` (149 child işgal edilir, A1/B1/A2/B2 aynı child'a
  sabitlenir); tek worker baseline için `--workers 1`

## Doğrulama

- Resmi worker modu: 10/10
- Tek worker baseline: 20/20
- README'ye göre yepyeni clone sonrası çalıştırma: 2/2
- proof: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

Çoğaltma:

```bash
./pure/run_pure.sh
python3 exploit.py --port 18110
```

Loglar:

- `pure/evidence/official_workers_20261022.log`
- `pure/evidence/pwn_pure_batch_20261022.log`
- `pure/evidence/clone_readme_20261023.log`

## Dikkat

- Bu offset'ler yalnızca yukarıdaki `libphp.so` (SHA-256/build-id) için geçerlidir. PHP
  yama sürümünü, dağıtımı, imaj build'ini ya da CPU mimarisini (örneğin arm64) değiştirince
  yeni bir kayıt oluşturmak gerekir.
- `zif_system` / `zif_passthru` LOCAL sembollerdir; `nm --defined-only`
  ya da `readelf -sW` ile okuyun, yalnızca `nm -D`'ye güvenmeyin.
- Yanlış offset kullanmak worker'ı doğrudan çökertebilir; yalnızca yetkili ortamda doğrulayın.
