set pagination off
set confirm off
set breakpoint pending on
set logging file /tmp/g_bins.log
set logging overwrite on
set logging enabled on
python
import gdb


def get_heap():
    return gdb.parse_and_eval("(zend_mm_heap*)zend_mm_get_heap()")


def flen(h, b):
    inf = gdb.selected_inferior()
    p = int(h['free_slot'][b])
    n = 0
    while p and n < 300:
        n += 1
        try:
            p = int.from_bytes(inf.read_memory(p, 8).tobytes(), 'little')
        except Exception:
            break
    return n


def chunk_stats(h):
    c = h['main_chunk']
    main = c
    out = []
    while True:
        m = c['map']
        free = int(c['free_pages'])
        bins = {}
        lpages = 0
        fpages = 0
        for i in range(512):
            info = int(m[i])
            if info & 0x80000000:
                b = info & 0x1f
                bins[b] = bins.get(b, 0) + 1
            elif info & 0x40000000:
                lpages += 1
            else:
                fpages += 1
        out.append((free, bins, lpages, fpages))
        c = c['next']
        if int(c) == int(main):
            break
    return out


class SendCookieBP(gdb.Breakpoint):
    def __init__(self):
        super(SendCookieBP, self).__init__("php_session_send_cookie")

    def stop(self):
        try:
            h = get_heap()
            fs = [int(h['free_slot'][i]) for i in (7, 9, 11, 12, 15)]
            c = h['main_chunk']
            main = c
            frees = []
            addrs = []
            total = 0
            while True:
                fp = int(c['free_pages'])
                total += fp
                frees.append(fp)
                addrs.append(hex(int(c)))
                c = c['next']
                if int(c) == int(main):
                    break
            idp = gdb.parse_and_eval("ps_globals.id")
            idlen = int(idp.dereference()['len']) if int(idp) else -1
            n7, n9, n11, n12, n15 = (flen(h, b) for b in (7, 9, 11, 12, 15))
            maps = chunk_stats(h)
            gdb.write(
                "SEND_COOKIE id=%s len=%d size=%d real=%d limit=%d "
                "free_pages=%d chunks=%s fs7=%#x/%d fs9=%#x/%d fs11=%#x/%d "
                "fs12=%#x/%d fs15=%#x/%d\n" %
                (idp, idlen, int(h['size']), int(h['real_size']),
                 int(h['limit']), total, frees, fs[0], n7, fs[1], n9,
                 fs[2], n11, fs[3], n12, fs[4], n15))
            try:
                gdb.execute("x/40gx %#x" % idp)
            except Exception:
                pass
            gdb.write("CHUNKADDR %s\n" % (addrs,))
            gdb.write("MAPS=%s\n" % (maps,))
            try:
                cc = h['cached_chunks']
                addrs = []
                i = 0
                while int(cc) and i < 16:
                    addrs.append(hex(int(cc)))
                    cc = cc['next']
                    i += 1
                gdb.write("CACHED n=%d %s\n" %
                          (int(h['cached_chunks_count']), addrs))
            except Exception as e:
                gdb.write("CACHED_ERR %r\n" % (e,))
        except Exception as e:
            gdb.write("SEND_COOKIE_ERR %r\n" % (e,))
        return False


def pageinfo(p):
    if not p:
        return 'null'
    inf = gdb.selected_inferior()
    base = p & ~0x1fffff
    pg = (p - base) // 4096
    try:
        ct = gdb.lookup_type('zend_mm_chunk').pointer()
        ch = gdb.Value(base).cast(ct)
        hf = int(ch['heap'])
        info = int(ch['map'][pg])
        heapnow = int(get_heap())
        return ('p=%#x base=%#x pg=%d chunk_heap=%#x match=%d info=%#x'
                % (p, base, pg, hf, 1 if hf == heapnow else 0, info))
    except Exception as e:
        return 'p=%#x err=%r' % (p, e)


def bin15_free_by_page(h):
    inf = gdb.selected_inferior()
    p = int(h['free_slot'][15])
    pages = {}
    n = 0
    while p and n < 400:
        n += 1
        pg = (p & ~0x1fffff) + ((p & 0x1fffff) // 4096) * 4096
        base = p & ~0x1fffff
        pageno = (p - base) // 4096
        key = (base, pageno)
        pages[key] = pages.get(key, 0) + 1
        try:
            p = int.from_bytes(inf.read_memory(p, 8).tobytes(), 'little')
        except Exception:
            break
    return ('free15=%d bins=%s' %
            (n, sorted((('%#x:%d' % (k[0], k[1])), v) for k, v in pages.items())))


class OpenBP(gdb.Breakpoint):
    def __init__(self):
        super(OpenBP, self).__init__("mod_files.c:419")

    def stop(self):
        try:
            inf = gdb.selected_inferior()
            md = gdb.parse_and_eval("mod_data")
            old = int(md.dereference())
            new = int(gdb.parse_and_eval("data"))
            oldf = ''
            basedir = 0
            if old:
                raw = inf.read_memory(old, 0x28).tobytes()
                last_key = int.from_bytes(raw[0:8], 'little')
                basedir = int.from_bytes(raw[8:16], 'little')
                fd = int.from_bytes(raw[0x24:0x28], 'little', signed=True)
                oldf = ('old=%s last_key=%#x basedir=%s fd=%d'
                        % (pageinfo(old), last_key, pageinfo(basedir), fd))
            gdb.write("OPEN_FILES new=%s %s\n" % (pageinfo(new), oldf))
            try:
                base = 0x7ffff5e00000
                ct = gdb.lookup_type('zend_mm_chunk').pointer()
                ch = gdb.Value(base).cast(ct)
                line = ' '.join('%d:%x' % (i, int(ch['map'][i]))
                                for i in range(88, 116))
                gdb.write("PAGEMAP %s chunkfree=%d\n" %
                          (line, int(ch['free_pages'])))
                gdb.write("BIN15 %s\n" % (bin15_free_by_page(get_heap()),))
            except Exception as e:
                gdb.write("PAGEMAP_ERR %r\n" % (e,))
        except Exception as e:
            gdb.write("OPEN_FILES_ERR %r\n" % (e,))
        return False


class MapWatchBP(gdb.Breakpoint):
    def __init__(self, spec):
        super(MapWatchBP, self).__init__(spec)
        self.spec = spec

    def stop(self):
        try:
            inf = gdb.selected_inferior()
            base = 0x7ffff5e00000
            ct = gdb.lookup_type('zend_mm_chunk').pointer()
            ch = gdb.Value(base).cast(ct)
            line = ' '.join('%d:%x' % (i, int(ch['map'][i]))
                            for i in range(92, 102))
            inp = int.from_bytes(inf.read_memory(base, 8).tobytes(), 'little')
            gdb.write("MAPWATCH %s chunkheap=%#x %s\n" %
                      (self.spec, inp, line))
        except Exception as e:
            gdb.write("MAPWATCH_ERR %s %r\n" % (self.spec, e))
        return False


class RshutBP(gdb.Breakpoint):
    def __init__(self):
        super(RshutBP, self).__init__("php_rshutdown_session_globals")

    def stop(self):
        try:
            idp = gdb.parse_and_eval("ps_globals.id")
            p = int(idp)
            info = ''
            if p:
                try:
                    raw = gdb.selected_inferior().read_memory(p, 16).tobytes()
                    info = 'bytes=' + raw.hex()
                except Exception as e:
                    info = 'read_err=%r' % (e,)
            gdb.write("RSHUT_ID id=%s %s %s sc=%d\n" %
                      (idp, pageinfo(p), info,
                       int(gdb.parse_and_eval("ps_globals.send_cookie"))))
        except Exception as e:
            gdb.write("RSHUT_ID_ERR %r\n" % (e,))
        return False


class BuffBP(gdb.Breakpoint):
    def __init__(self):
        super(BuffBP, self).__init__("rfc1867.c:754")

    def stop(self):
        try:
            mb = gdb.parse_and_eval("mbuff")
            buf = int(mb.dereference()['buffer'])
            bsz = int(mb.dereference()['bufsize'])
            gdb.write("MP_BUFFER %s bufsize=%d\n" % (pageinfo(buf), bsz))
        except Exception as e:
            gdb.write("MP_BUFFER_ERR %r\n" % (e,))
        return False


class InitBP(gdb.Breakpoint):
    def __init__(self):
        super(InitBP, self).__init__("php_session_initialize")

    def stop(self):
        try:
            idp = gdb.parse_and_eval("ps_globals.id")
            sc = int(gdb.parse_and_eval("ps_globals.send_cookie"))
            mod = int(gdb.parse_and_eval("ps_globals.mod"))
            uc = int(gdb.parse_and_eval("ps_globals.use_cookies"))
            usm = int(gdb.parse_and_eval("ps_globals.use_strict_mode"))
            idlen = int(idp.dereference()['len']) if int(idp) else -1
            tail = ''
            if int(idp):
                try:
                    mem = gdb.selected_inferior().read_memory(int(idp) + 0x18, 40).tobytes()
                    tail = ' data=' + mem.hex()
                except Exception as e:
                    tail = ' data_err=%r' % (e,)
            gdb.write("SESSION_INIT id=%s len=%d send_cookie=%d mod=%s "
                      "use_cookies=%d strict=%d%s\n" %
                      (idp, idlen, sc, hex(mod), uc, usm, tail))
            gdb.write("BIN15_CHAIN_INIT %s\n" % (_bin15_chain(),))
            try:
                h = get_heap()
                heads = []
                for bn in range(31):
                    hp = int(h['free_slot'][bn])
                    if hp:
                        heads.append('%d:%#x' % (bn, hp))
                gdb.write("FREELISTS %s\n" % (' '.join(heads),))
                cnt = 0
                hp = int(h['free_slot'][6])
                while hp and cnt < 500:
                    cnt += 1
                    try:
                        hp = int(gdb.parse_and_eval("*(void**)%#x" % hp))
                    except Exception:
                        break
                gdb.write("BIN6_COUNT %d\n" % cnt)
                ct = gdb.lookup_type('zend_mm_chunk').pointer()
                base = int(gdb.parse_and_eval("ps_globals.id")) & ~0x1fffff
                ch = gdb.Value(base).cast(ct)
                pm = ' '.join('%d:%#x' % (pg, int(ch['map'][pg]))
                              for pg in range(120, 136))
                gdb.write("PAGEMAP120 %s\n" % (pm,))
                pm2 = ' '.join('%d:%#x' % (pg, int(ch['map'][pg]))
                               for pg in range(500, 512))
                gdb.write("PAGEMAP_ID500 %s\n" % (pm2,))
                try:
                    ct = gdb.lookup_type('zend_mm_chunk').pointer()
                    mc = h['main_chunk']
                    cb = int(mc)
                    cc = mc
                    out = []
                    for _k in range(16):
                        out.append('%#x:%d' % (int(cc), int(cc['free_pages'])))
                        cc = cc['next']
                        if int(cc) == cb:
                            break
                    gdb.write("CHUNKLIST %s\n" % (' '.join(out),))
                    cache = h['cached_chunks']
                    out2 = []
                    for _k in range(8):
                        if not int(cache):
                            break
                        out2.append('%#x:%d' % (int(cache), int(cache['free_pages'])))
                        cache = cache['next']
                    gdb.write("CACHEDLIST %s\n" % (' '.join(out2),))
                except Exception as e:
                    gdb.write("CHUNKLIST_ERR %r\n" % (e,))
            except Exception as e:
                gdb.write("FREELISTS_ERR %r\n" % (e,))
        except Exception as e:
            gdb.write("SESSION_INIT_ERR %r\n" % (e,))
        return False


class ResetBP(gdb.Breakpoint):
    def __init__(self):
        super(ResetBP, self).__init__("php_session_reset_id")

    def stop(self):
        try:
            idp = gdb.parse_and_eval("ps_globals.id")
            sc = int(gdb.parse_and_eval("ps_globals.send_cookie"))
            idlen = int(idp.dereference()['len']) if int(idp) else -1
            gdb.write("RESET_ID id=%s len=%d send_cookie=%d\n" %
                      (idp, idlen, sc))
        except Exception as e:
            gdb.write("RESET_ID_ERR %r\n" % (e,))
        return False


class PanicBP(gdb.Breakpoint):
    def __init__(self):
        super(PanicBP, self).__init__("zend_mm_panic")

    def stop(self):
        gdb.write("ZEND_MM_PANIC\n")
        gdb.execute("bt 20")
        return False


class AbortBP(gdb.Breakpoint):
    def __init__(self):
        super(AbortBP, self).__init__("abort")

    def stop(self):
        gdb.write("ABORT_CALLED\n")
        gdb.execute("bt 20")
        return False


class SafeErrBP(gdb.Breakpoint):
    def __init__(self):
        super(SafeErrBP, self).__init__("zend_mm_safe_error")

    def stop(self):
        try:
            h = get_heap()
            gdb.write("MM_SAFE_ERROR real=%d limit=%d size=%d\n" %
                      (int(h['real_size']), int(h['limit']), int(h['size'])))
            try:
                idp = gdb.parse_and_eval("ps_globals.id")
                sc = int(gdb.parse_and_eval("ps_globals.send_cookie"))
                idlen = int(idp.dereference()['len']) if int(idp) else -1
                gdb.write("PS_AT_OOM id=%s len=%d send_cookie=%d\n" %
                          (idp, idlen, sc))
            except Exception as e:
                gdb.write("PS_AT_OOM_ERR %r\n" % (e,))
        except Exception as e:
            gdb.write("MM_SAFE_ERROR_ERR %r\n" % (e,))
        gdb.execute("bt 20")
        return False


MapWatchBP("php_hash_environment")
MapWatchBP("php_auto_globals_create_post")
SendCookieBP()
OpenBP()
BuffBP()
RshutBP()
InitBP()
ResetBP()
PanicBP()
AbortBP()
SafeErrBP()


def _bin15_chain(n=8):
    try:
        h = get_heap()
        p = int(h['free_slot'][15])
        out = []
        for _ in range(n):
            if not p:
                break
            out.append(p)
            try:
                p = int(gdb.parse_and_eval("*(void**)%#x" % p))
            except Exception:
                break
        return ' '.join(hex(x) for x in out)
    except Exception as e:
        return 'ERR %r' % (e,)

class _EmallocRet(gdb.FinishBreakpoint):
    def __init__(self, sz, ra):
        super().__init__(internal=True)
        self._sz = sz
        self._ra = ra
    def stop(self):
        try:
            rv = int(self.return_value)
        except Exception:
            rv = -1
        gdb.write("EMALLOC sz=%d ra=%#x ret=%#x\n" % (self._sz, self._ra, rv))
        return False

class _EmallocBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("_emalloc", gdb.BP_BREAKPOINT, internal=True)
    def stop(self):
        try:
            sz = int(gdb.parse_and_eval("$rdi"))
            if 200 <= sz <= 300:
                ra = int(gdb.parse_and_eval("*(void**)$rsp"))
                _EmallocRet(sz, ra)
        except Exception:
            pass
        return False

class _EfreeBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("_efree", gdb.BP_BREAKPOINT, internal=True)
    def stop(self):
        try:
            p = int(gdb.parse_and_eval("$rdi"))
            off = p - (p & ~0x1fffff)
            if 0x78000 <= off < 0x88000:
                gdb.write("EFREE %#x\n" % (p,))
                try:
                    idv = int(gdb.parse_and_eval("ps_globals.id"))
                except Exception:
                    idv = 0
                if idv and p == idv:
                    gdb.write("BIN15_CHAIN_AT_FREE_ID %s\n" % (_bin15_chain(),))
        except Exception:
            pass
        return False

_EmallocBP()
_EfreeBP()

class _EreallocRet(gdb.FinishBreakpoint):
    def __init__(self, sz):
        super().__init__(internal=True)
        self._sz = sz
    def stop(self):
        try:
            rv = int(self.return_value)
        except Exception:
            rv = -1
        gdb.write("EREALLOC_NULL sz=%d ret=%#x\n" % (self._sz, rv))
        return False

class _EreallocBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("_erealloc", gdb.BP_BREAKPOINT, internal=True)
    def stop(self):
        try:
            ptr = int(gdb.parse_and_eval("$rdi"))
            sz = int(gdb.parse_and_eval("$rsi"))
            if ptr == 0 and 200 <= sz <= 300:
                _EreallocRet(sz)
        except Exception:
            pass
        return False

_EreallocBP()
end
continue
