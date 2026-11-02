"""Проверка резолверов из модалки DNS: отвечает ли сервер, за сколько и режет ли рекламу.

Каждый резолвер спрашиваем про example.com (жив ли) и doubleclick.net (0.0.0.0 или
NXDOMAIN в ответ = блокировщик рекламы). Обычный DNS и DoH проверяет сам Python.
QUIC (h3:// и quic://) Python не умеет, поэтому их проверяет временный mihomo, если
он стоит на сервере: тот же движок, что у клиентов Clash, понимает строку резолвера
ровно так, как поймёт клиент. Без mihomo h3:// проверяется по HTTP/2 по тому же
адресу, а quic:// по DoT на тот же хост, с пометкой, что сам QUIC не проверен.

Проверка идёт с сервера, а работать резолвер будет на устройстве клиента: провайдер
клиента может резать DoH или QUIC, которые с сервера проходят.
"""
import json
import os
import random
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

MIHOMO_BIN = '/usr/local/bin/mihomo'
PROBE_OK = 'example.com'
PROBE_ADS = 'doubleclick.net'
TIMEOUT = 4.0
# Чем резолвить имя самого DoH3/DoQ-хоста во временном mihomo.
BOOTSTRAP = ['1.1.1.1', '8.8.8.8']
STUB_IPS = {'0.0.0.0', '::', '127.0.0.1', '::1'}

_mihomo_lock = threading.Lock()


# --- DNS-сообщение --------------------------------------------------------------

def _query_packet(name):
    qid = random.randint(0, 0xFFFF)
    q = b''.join(bytes([len(p)]) + p.encode('ascii') for p in name.strip('.').split('.')) + b'\0'
    return qid, struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0) + q + struct.pack('!HH', 1, 1)


def _skip_name(msg, off):
    while True:
        ln = msg[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln


def _parse_reply(msg, qid=None):
    """→ (rcode, [IPv4 из A-записей ответа])."""
    if len(msg) < 12:
        raise ValueError('короткий ответ')
    rid, fl, qd, an, _ns, _ar = struct.unpack('!HHHHHH', msg[:12])
    if qid is not None and rid != qid:
        raise ValueError('чужой ответ')
    off = 12
    for _ in range(qd):
        off = _skip_name(msg, off) + 4
    ips = []
    for _ in range(an):
        off = _skip_name(msg, off)
        rtype, _rc, _ttl, rdlen = struct.unpack('!HHIH', msg[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.append('.'.join(str(b) for b in msg[off:off + 4]))
        off += rdlen
    return fl & 0x0F, ips


# --- транспорты -----------------------------------------------------------------

def _split_hostport(s, default_port):
    s = s.strip()
    if s.startswith('['):
        host, _, rest = s[1:].partition(']')
        port = rest[1:] if rest.startswith(':') else ''
        return host, int(port) if port.isdigit() else default_port
    if s.count(':') == 1:
        host, port = s.split(':')
        return host, int(port) if port.isdigit() else default_port
    return s, default_port


def _udp(server, name):
    host, port = _split_hostport(server, 53)
    qid, pkt = _query_packet(name)
    fam, _, _, _, addr = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)[0]
    sock = socket.socket(fam, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(pkt, addr)
        deadline = time.time() + TIMEOUT
        while True:
            data, _ = sock.recvfrom(4096)
            if len(data) >= 2 and struct.unpack('!H', data[:2])[0] == qid:
                return _parse_reply(data, qid)
            if time.time() > deadline:
                raise socket.timeout()
    finally:
        sock.close()


_no_proxy = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _doh(url, name):
    """RFC 8484: POST application/dns-message. ID в DoH принято ставить 0."""
    _qid, pkt = _query_packet(name)
    pkt = b'\0\0' + pkt[2:]
    req = urllib.request.Request(url, data=pkt, method='POST', headers={
        'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message',
        'User-Agent': 'awg-panel-dns-check'})
    with _no_proxy.open(req, timeout=TIMEOUT) as r:
        ctype = (r.headers.get('Content-Type') or '').lower()
        body = r.read(65536)
    if 'dns-message' not in ctype:
        raise ValueError('по этому адресу не DoH-сервер')
    return _parse_reply(body)


def _dot(host, name):
    """DNS over TLS на 853: тот же хост, что у DoQ, у публичных резолверов обычно жив."""
    host, port = _split_hostport(host, 853)
    qid, pkt = _query_packet(name)
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.sendall(struct.pack('!H', len(pkt)) + pkt)
            buf = b''
            while len(buf) < 2 or len(buf) < 2 + struct.unpack('!H', buf[:2])[0]:
                chunk = s.recv(4096)
                if not chunk:
                    raise ValueError('соединение закрыто')
                buf += chunk
    return _parse_reply(buf[2:2 + struct.unpack('!H', buf[:2])[0]], qid)


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _mihomo_ns(url):
    """Строка резолвера в синтаксисе mihomo: h3://X → https://X#h3=true."""
    if url.startswith('h3://'):
        return 'https://' + url[len('h3://'):] + '#h3=true'
    return url


def _via_mihomo(url, names, binary=None):
    """Временный mihomo без портов и TUN: только DNS и API на loopback.
    → {name: (rcode, ips, ms)} либо исключение с причиной."""
    with _mihomo_lock:
        d = tempfile.mkdtemp(prefix='awgp-dnscheck-')
        p = None
        try:
            port = _free_port()
            secret = '%032x' % random.getrandbits(128)
            cfg = ['mode: rule', 'log-level: warning',
                   'external-controller: 127.0.0.1:%d' % port,
                   'secret: "%s"' % secret,
                   'dns:', '  enable: true', '  ipv6: false', '  default-nameserver:']
            cfg += ['    - "%s"' % b for b in BOOTSTRAP]
            cfg += ['  nameserver:', '    - "%s"' % _mihomo_ns(url).replace('"', ''),
                    'rules:', '  - MATCH,DIRECT', '']
            with open(os.path.join(d, 'config.yaml'), 'w') as f:
                f.write('\n'.join(cfg))
            p = subprocess.Popen([binary or MIHOMO_BIN, '-d', d], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, cwd=d)
            api = 'http://127.0.0.1:%d' % port
            auth = {'Authorization': 'Bearer ' + secret}

            def get(path, timeout):
                req = urllib.request.Request(api + path, headers=auth)
                try:
                    with _no_proxy.open(req, timeout=timeout) as r:
                        return r.status, r.read()
                except urllib.error.HTTPError as e:
                    return e.code, e.read()

            up = False
            until = time.time() + 6
            while time.time() < until:
                if p.poll() is not None:
                    break
                try:
                    if get('/version', 1)[0] == 200:
                        up = True
                        break
                except Exception:
                    pass
                time.sleep(0.15)
            if not up:
                raise RuntimeError('mihomo не принял этот адрес резолвера')
            out = {}
            for name in names:
                t0 = time.time()
                code, body = get('/dns/query?name=%s&type=A' % urllib.parse.quote(name), TIMEOUT + 2)
                ms = int((time.time() - t0) * 1000)
                try:
                    j = json.loads(body or b'{}')
                except ValueError:
                    j = {}
                if code != 200 or 'Status' not in j:
                    raise RuntimeError(j.get('message') or ('HTTP %d' % code))
                ips = [a.get('data') for a in (j.get('Answer') or []) if a.get('type') == 1]
                out[name] = (j.get('Status', 0), ips, ms)
                if not ips:
                    break
            return out
        finally:
            if p is not None:
                try:
                    p.kill()
                    p.wait(2)
                except Exception:
                    pass
            shutil.rmtree(d, ignore_errors=True)


# --- проверка одной записи ------------------------------------------------------

RCODE_NAMES = {2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED'}


def _human_error(e):
    s = str(e)
    low = s.lower()
    if isinstance(e, urllib.error.HTTPError):
        if e.code in (400, 403, 404, 405):
            return 'HTTP %d: проверьте путь и ID в адресе' % e.code
        return 'HTTP %d' % e.code
    if isinstance(e, urllib.error.URLError) and isinstance(getattr(e, 'reason', None), Exception):
        return _human_error(e.reason)
    if isinstance(e, (socket.timeout, TimeoutError)) or 'timed out' in low \
            or 'deadline' in low or 'timeout' in low:
        return 'нет ответа за %d с' % TIMEOUT
    if isinstance(e, socket.gaierror) or 'name or service not known' in low \
            or 'nodename nor servname' in low or 'name resolution' in low \
            or 'getaddrinfo' in low or 'no such host' in low:
        return 'имя сервера не резолвится'
    if 'certificate' in low:
        return 'ошибка TLS-сертификата'
    if 'refused' in low:
        return 'соединение отклонено'
    if 'unreachable' in low:
        return 'сеть недоступна (у сервера нет IPv6?)'
    return s[:160] or e.__class__.__name__


def _run(entry, fn):
    """fn(name) → (rcode, ips). Итог по двум именам."""
    res = dict(entry, ok=False, ms=0, ip='', ads=False, error='')
    t0 = time.time()
    try:
        rcode, ips = fn(PROBE_OK)
    except Exception as e:
        res['ms'] = int((time.time() - t0) * 1000)
        res['error'] = _human_error(e)
        return res
    res['ms'] = int((time.time() - t0) * 1000)
    if rcode:
        res['error'] = 'сервер ответил ошибкой %s' % RCODE_NAMES.get(rcode, rcode)
        return res
    if not ips:
        res['error'] = 'пустой ответ'
        return res
    res['ok'] = True
    res['ip'] = ips[0]
    try:
        rcode, ips = fn(PROBE_ADS)
        res['ads'] = rcode == 3 or (bool(ips) and all(x in STUB_IPS for x in ips))
    except Exception:
        pass
    return res


def _check_plain(server):
    return _run({'server': server, 'kind': 'UDP'}, lambda n: _udp(server, n))


def _check_encrypted(url, mihomo_bin=None):
    scheme = url.split('://', 1)[0].lower()
    kind = {'https': 'DoH', 'h3': 'DoH3', 'quic': 'DoQ'}.get(scheme, scheme)
    entry = {'server': url, 'kind': kind}
    if scheme == 'https':
        return _run(entry, lambda n: _doh(url, n))
    binary = mihomo_bin or MIHOMO_BIN
    if os.path.exists(binary):
        cache = {}

        def via(n):
            if not cache:
                cache.update(_via_mihomo(url, [PROBE_OK, PROBE_ADS], binary))
            if n not in cache:
                raise RuntimeError('нет ответа')
            return cache[n][0], cache[n][1]
        res = _run(entry, via)
        if PROBE_OK in cache:
            res['ms'] = cache[PROBE_OK][2]   # без времени на запуск mihomo
        return res
    rest = url.split('://', 1)[1]
    if scheme == 'h3':
        res = _run(entry, lambda n: _doh('https://' + rest, n))
        res['note'] = 'QUIC не проверен: на сервере нет mihomo. Проверен тот же адрес по HTTP/2.'
        return res
    host = rest.split('/', 1)[0]
    res = _run(entry, lambda n: _dot(host, n))
    res['note'] = 'QUIC не проверен: на сервере нет mihomo. Проверен тот же хост по DoT.'
    return res


def check(plain, doh):
    """plain — адреса UDP-резолверов, doh — URL зашифрованного (или '').
    Всё параллельно, потолок около 15 с (у gunicorn таймаут 30)."""
    jobs = [(_check_plain, s) for s in plain]
    if doh:
        jobs.append((_check_encrypted, doh))
    if not jobs:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(jobs))) as ex:
        futs = [ex.submit(fn, arg) for fn, arg in jobs]
        return [f.result() for f in futs]
