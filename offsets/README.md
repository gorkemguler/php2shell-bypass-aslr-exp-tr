# offsets (offset'ler)

| Mimari | Kurulum komutu | libphp SHA-256 | build-id | zval_ptr_dtor | zif_system | zif_passthru | Durum | Yazar |
|---|---|---|---|---|---|---|---|---|
| x86_64 | `docker pull php:8.4.26-apache` | `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` | `a534a5c4a890b378ef6c227590627d531eafa8ce` | `0x65EB60` | `0x465370` | `0x465380` | ✅ [ayrıntılar](php-8.4.26-apache-trixie-amd64.md) | - |
| aarch64 | `docker pull --platform linux/arm64 php:8.4.26-apache` | `e160c9d173be0e170add2ab461ba2995d0dd9ac0feb6faf3e763c052c998ab4b` | `b3525423bd3d026677be6de48285e46ae5a5604b` | `0x63812B` | `0x42CD70` | `0x42CD80` | ✅ PR #6 (tek worker 10/10, resmi worker 3/3) · yerel aarch64 fiilî test 1/1 · [log](../pure/evidence/arm64_stock_20261023.log) | ideacatlab |

> aarch64'ün `0x63812B`'i, sızıntı penceresindeki tekrar eden işaretçinin offset'idir; ELF sembolü `0x638120`'dedir (+0xB). libphp SHA-256 / build-id, yerel arm64 imajından fiilî test ile tamamlanmıştır.

# pr

PR'ler hoş karşılanır: yeni mimari, yeni sürüm ya da farklı kurulum yöntemleri için offset kayıtları; `libphp.so`'nun SHA-256'sı, build-id'si ve çalıştığına dair kanıt eklenmesi yeterlidir.
