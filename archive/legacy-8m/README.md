# Eski 8M / display_errors=On hattı (arşivlenmiş)

Bu dizin, daha önceki tek-atışlık (one-shot) exploit'i (`exploit.py`), mekanizma notlarını ve
eski build/çalıştırma yapılandırmasını saklar:

- `exploit.py` — özel-ini'li tek-atışlık exploit
- `docker/php.ini` — `display_errors=On`, `memory_limit=8M`,
  `max_input_vars=1000`
- `docker/docker-compose.yml` — eski `127.0.0.1:8088` hedefi; volume yolları bu arşiv konumuna
  göre ayarlanmıştır
- `docker/offsets.py` — eski exploit tarafından kullanılan libphp offset okuyucusu
- `lab/apache2_aslr.conf` — eski lab Apache yapılandırması

O hedef, stock resmi `php.ini-production` yerine **özel (custom)** bir `php.ini` kullanıyordu.
Bu deponun mevcut hedefi, dokunulmamış resmi `php.ini-production` (`display_errors=Off`,
`memory_limit=128M`) ile resmi `php:8.4.26-apache` imajı ve resmi prefork worker'larıdır;
bkz. [../../README.md](../../README.md) ve
[../../pure/RESEARCH_PURE_128M.md](../../pure/RESEARCH_PURE_128M.md).

Arşivlenen yollar, eski akışın hâlâ depo-kökündeki `out/` ile deponun `--single` lab modu için
hâlâ sunduğu mevcut `pure/docker/www` + `pure/docker/apache-single-worker.conf`'u çözebilmesi
için ayarlandı. `tools/`, `logs/` ve takip edilmeyen (untracked) `bwcal/` ağacı taşınmadı;
bazı eski araçlar hâlâ orijinal konumlara atıfta bulunabilir.
