#!/usr/bin/env python3
"""iotpipe: raw IoT network evidence -> Splunk-ready events, Splunk app and HEC upload.

Dependency-free (Python 3.11+ standard library). External programs: Zeek (required for the `zeek`
step), tshark (optional, TLS fingerprints). Everything site-specific lives in a TOML file
(see pipeline/site.example.toml); nothing about a particular home is hard-coded here.

  python3 pipeline/iotpipe.py check   [-c SITE.toml]   # what was found, what is missing
  python3 pipeline/iotpipe.py zeek    [-c ...] [--force]  # run Zeek over every capture
  python3 pipeline/iotpipe.py prepare [-c ...]         # build <out>/splunk/*.ndjson + lookups
  python3 pipeline/iotpipe.py app     [-c ...]         # build the Splunk app (+ .tgz) from the prepared lookups
  python3 pipeline/iotpipe.py send    [-c ...] --url https://splunk:8088 [--insecure] [--only ST ...] [--dry-run]
                                                      # HEC token in the environment variable SPLUNK_HEC_TOKEN
  python3 pipeline/iotpipe.py all     [-c ...]         # check + zeek + prepare + app

Guide: pipeline_guide.md
"""
import argparse, csv, collections, datetime, fnmatch, glob, gzip, ipaddress, json, os, re, shutil, ssl
import struct, subprocess, sys, tarfile, time, tomllib, urllib.error, urllib.request
from zoneinfo import ZoneInfo

VERSION = '0.1'
HERE = os.path.dirname(os.path.abspath(__file__))
SOURCETYPES = {   # sourcetype -> one-line description (also used for props.conf and the guide's field reference)
    'iot:conn':       'One event per network connection (Zeek conn.log), attributed to a device',
    'iot:dns':        'DNS lookups seen on the wire (Zeek dns.log; mDNS/LLMNR left out unless enabled)',
    'iot:tls':        'TLS sessions (Zeek ssl.log): server name, version, cipher',
    'iot:tls_hello':  'TLS ClientHello fingerprints (tshark): JA4, JA3, server name',
    'iot:http':       'Unencrypted HTTP requests (Zeek http.log), secrets in URLs redacted',
    'iot:dhcp':       'DHCP exchanges (Zeek dhcp.log): who got which address, host names',
    'iot:volume':     'Bytes and packets per device per minute, split by peer class (from the pcaps)',
    'iot:health':     'Per interface and minute: frames seen and router advertisements (from the pcaps)',
    'iot:fw':         'Router firewall log lines (iptables LOG prefixes), parsed',
    'iot:pihole':     'Pi-hole DNS queries from IoT devices, with blocked/allowed decoded',
    'iot:annotation': 'Ground-truth markers: what the operator did and when',
}
# Pi-hole FTL query status / type codes (FTL v5/v6)
PH_STATUS = {0: 'unknown', 1: 'blocked (gravity)', 2: 'forwarded', 3: 'cached', 4: 'blocked (regex)', 5: 'blocked (exact)',
             6: 'blocked (upstream IP)', 7: 'blocked (upstream null)', 8: 'blocked (upstream NXDOMAIN)',
             9: 'blocked (gravity CNAME)', 10: 'blocked (regex CNAME)', 11: 'blocked (exact CNAME)', 12: 'retried',
             13: 'retried (DNSSEC)', 14: 'in progress', 15: 'blocked (database busy)', 16: 'blocked (special domain)',
             17: 'cached (stale)'}
PH_BLOCKED = {1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16}
PH_TYPE = {1: 'A', 2: 'AAAA', 3: 'ANY', 4: 'SRV', 5: 'SOA', 6: 'PTR', 7: 'TXT', 8: 'NAPTR', 9: 'MX', 10: 'DS',
           11: 'RRSIG', 12: 'DNSKEY', 13: 'NS', 14: 'OTHER', 15: 'SVCB', 16: 'HTTPS'}
MONTHS = {m: i for i, m in enumerate(('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), 1)}


# ----------------------------------------------------------------------------------------------- helpers
def say(*a): print(*a, flush=True)


def merge(a, b):
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict): merge(a[k], v)
        elif isinstance(v, list) and isinstance(a.get(k), list): a[k] = a[k] + v
        else: a[k] = v
def die(msg): sys.exit(f'iotpipe: {msg}')

def retry(fn, *a, tries=20):
    """The project folder sits on a network mount that sometimes answers EAGAIN; retry briefly."""
    for i in range(tries):
        try: return fn(*a)
        except BlockingIOError:
            if i == tries - 1: raise
            time.sleep(0.5)

def write_atomic(path, text):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    def w():
        with open(path + '.tmp', 'w', encoding='utf-8', newline='\n') as fh: fh.write(text)
        os.replace(path + '.tmp', path)
    retry(w)

def norm_mac(m): return (m or '').strip().lower()


def unicast_host(ip):
    """True for an address that can identify one host (not ::, 0.0.0.0, loopback, multicast, link-local)."""
    try: a = ipaddress.ip_address(ip)
    except ValueError: return False
    return not (a.is_unspecified or a.is_loopback or a.is_multicast or a.is_link_local or str(a) == '255.255.255.255')

class Site:
    """The site description (TOML) plus derived lookups."""
    def __init__(self, path):
        if not os.path.exists(path): die(f'config not found: {path} (copy pipeline/site.example.toml)')
        with open(path, 'rb') as fh: c = tomllib.load(fh)
        # optional private overlay next to the config (site.private.toml): values that must never be shared,
        # e.g. the household's own public prefixes. Tables are merged, lists appended.
        self.private = path[:-5] + '.private.toml' if path.endswith('.toml') else path + '.private'
        if os.path.exists(self.private):
            with open(self.private, 'rb') as fh: merge(c, tomllib.load(fh))
        else: self.private = None
        self.path, self.c = path, c
        base = os.path.dirname(os.path.abspath(path))
        self.root = os.path.normpath(os.path.join(base, c.get('paths', {}).get('root', '.')))
        p = c.get('paths', {})
        self.out = self.abs(p.get('out', 'pipeline_out'))
        self.zeek_dir = self.abs(p.get('zeek', os.path.join(p.get('out', 'pipeline_out'), 'zeek')))
        s = c.get('site', {})
        self.name = s.get('name', 'home')
        self.tz = ZoneInfo(s.get('timezone', 'UTC'))
        self.index = c.get('splunk', {}).get('index', 'iot')
        n = c.get('networks', {})
        self.nets = {k: [ipaddress.ip_network(x, strict=False) for x in n.get(k, [])]
                     for k in ('iot', 'main_lan', 'out_of_scope')}
        self.router_ips = set(n.get('router_ips', []))
        self.dns_ips = set(n.get('dns_servers', []))
        # the household's own public addresses: classified as own_public and masked in every output
        self.own = [(ipaddress.ip_network(o['prefix'], strict=False), ipaddress.ip_network(o['mask'], strict=False))
                    for o in n.get('own_public', [])]
        for net, mask in self.own:
            if net.prefixlen != mask.prefixlen or net.version != mask.version: die(f'own_public: {net} and its mask {mask} must match in size')
        self.router_macs = {norm_mac(m) for m in n.get('router_macs', [])}
        self.default_iface = c.get('captures', {}).get('default_iface', 'wl0.2')
        self.devices = {}          # mac -> dict
        self.ip_hints = {}         # ip -> mac (static addresses from the config)
        for d in c.get('device', []):
            mac = norm_mac(d['mac'])
            d = dict(d, mac=mac)
            d.setdefault('role', 'iot'); d.setdefault('home_iface', self.default_iface)
            d.setdefault('local_only', False); d.setdefault('baselined', False); d.setdefault('type', '')
            self.devices[mac] = d
            for ip in d.get('ips', []): self.ip_hints[str(ipaddress.ip_address(ip))] = mac
        self.controllers = {}      # ip -> name (main-LAN hosts that legitimately start connections to IoT devices)
        for d in c.get('controller', []):
            for ip in d.get('ips', []): self.controllers[str(ipaddress.ip_address(ip))] = d['name']
            if d.get('mac'): self.devices.setdefault(norm_mac(d['mac']), dict(d, mac=norm_mac(d['mac']), role='controller',
                                                     home_iface='', local_only=False, baselined=False, type='controller'))
        self._cls = {}

    def abs(self, p): return p if os.path.isabs(p) else os.path.normpath(os.path.join(self.root, p))
    def rel(self, p): return os.path.relpath(p, self.root)

    def ip_class(self, ip):
        """Classify an address as seen from the IoT segment: iot, lan, router, dns, oos, multicast, broadcast,
        linklocal, private_other, bogon (can't exist on the internet) or wan."""
        r = self._cls.get(ip)
        if r: return r
        try: a = ipaddress.ip_address(ip)
        except ValueError: return 'unknown'
        s = str(a)
        if any(a in net for net, _ in self.own): r = 'own_public'
        elif s in self.dns_ips: r = 'dns'
        elif s in self.router_ips: r = 'router'
        elif a.is_multicast: r = 'multicast'
        elif s == '255.255.255.255' or (a.version == 4 and s.endswith('.255') and any(a in n for n in self.nets['iot'] + self.nets['main_lan'])): r = 'broadcast'
        elif any(a in n for n in self.nets['iot']): r = 'iot'
        elif any(a in n for n in self.nets['main_lan']): r = 'lan'
        elif any(a in n for n in self.nets['out_of_scope']): r = 'oos'
        elif a.is_link_local: r = 'linklocal'
        elif a.is_loopback or a.is_unspecified or a.is_reserved or (a.version == 4 and a in ipaddress.ip_network('0.0.0.0/8')): r = 'bogon'
        elif a.is_private: r = 'private_other'
        else: r = 'wan'
        self._cls[ip] = r
        return r

    def mask_ip(self, v):
        if not self.own or not isinstance(v, str) or (':' not in v and '.' not in v): return v
        try: a = ipaddress.ip_address(v)
        except ValueError: return v
        for net, mask in self.own:
            if a.version == net.version and a in net:
                host = int(a) & int(net.hostmask)
                return str(ipaddress.ip_address(int(mask.network_address) | host))
        return v

    def mask_event(self, ev):
        if not self.own: return ev
        for k, v in ev.items():
            if k.endswith('_ip') or k.endswith('_addr') or k in ('answers', 'peer_ip'):
                ev[k] = [self.mask_ip(x) for x in v] if isinstance(v, list) else self.mask_ip(v)
        return ev

    def dev(self, mac):
        return self.devices.get(norm_mac(mac))


def discover_captures(site):
    """Capture folders: <root>/<YYYYMMDD-HHMMSS>_<label>/<iface>_*.pcap[.gz] (iot-capture.sh layout)."""
    cc = site.c.get('captures', {})
    pat = cc.get('pattern', '[0-9]*-[0-9]*_*')
    meta = site.c.get('capture', {})
    caps = []
    for d in sorted(glob.glob(os.path.join(site.root, pat))):
        if not os.path.isdir(d): continue
        label = re.sub(r'^[0-9-]+_', '', os.path.basename(d))
        pcaps = sorted(glob.glob(os.path.join(d, '*.pcap')) + glob.glob(os.path.join(d, '*.pcap.gz')))
        if not pcaps: continue
        m = meta.get(label, {})
        if m.get('skip'): continue
        ifaces = {}
        for p in pcaps:
            ifaces.setdefault(os.path.basename(p).split('_')[0], []).append(p)
        caps.append({'dir': d, 'label': label, 'ifaces': ifaces, 'state': m.get('state', ''),
                     'baseline': bool(m.get('baseline', False)), 'description': m.get('description', '')})
    return caps


def open_pcap(path):
    return gzip.open(path, 'rb') if path.endswith('.gz') else open(path, 'rb')


def iter_frames(path):
    """Yield (ts, frame bytes, original length) from a classic pcap (Ethernet link type)."""
    with open_pcap(path) as f:
        gh = f.read(24)
        if len(gh) < 24: return
        magic = struct.unpack('<I', gh[:4])[0]
        if magic in (0xa1b2c3d4, 0xa1b23c4d): e = '<'
        elif magic in (0xd4c3b2a1, 0x4d3cb2a1): e = '>'
        else: die(f'{path}: not a classic pcap (pcapng? convert with: editcap -F pcap in.pcapng out.pcap)')
        nano = magic in (0xa1b23c4d, 0x4d3cb2a1)
        lt = struct.unpack(e + 'I', gh[20:24])[0]
        if lt != 1: die(f'{path}: link type {lt}, only Ethernet (1) is supported')
        rec = struct.Struct(e + 'IIII')
        while True:
            h = f.read(16)
            if len(h) < 16: return
            sec, frac, incl, orig = rec.unpack(h)
            yield sec + frac / (1e9 if nano else 1e6), f.read(incl), orig


def mac_str(b): return ':'.join(f'{x:02x}' for x in b)


def emit(fh, ts, ev):
    """One event per line; "ts" first and fixed-format, so Splunk's TIME_PREFIX/TIME_FORMAT find it."""
    body = json.dumps({k: v for k, v in ev.items() if k != 'ts'}, ensure_ascii=False, separators=(',', ':'))
    fh.write('{"ts":%.6f%s' % (ts, ',' + body[1:] if len(body) > 2 else '}') + '\n')


# ----------------------------------------------------------------------------------------------- check
def cmd_check(site, args):
    ok = True
    say(f'iotpipe {VERSION}, config {site.path}')
    say(f'  root {site.root}\n  out  {site.out}\n  zeek {site.zeek_dir}')
    say(f'  site "{site.name}", timezone {site.tz.key}, Splunk index "{site.index}"')
    say(f'  private overlay: {site.rel(site.private) if site.private else "none"}; own public prefixes masked: {len(site.own)}')
    if sys.version_info < (3, 11): say('  ✗ Python 3.11+ needed (tomllib)'); ok = False
    zeek = zeek_bin(site)
    say(f'  zeek:   {zeek or "NOT FOUND (needed for the zeek step)"}')
    say(f'  tshark: {shutil.which("tshark") or "not found (optional: TLS fingerprints)"}')
    iot = [d for d in site.devices.values() if d['role'] != 'controller']
    say(f'  devices: {len(iot)} ({", ".join(d["name"] for d in iot)}); controllers: {len(site.controllers)} addresses')
    if not site.nets['iot']: say('  ✗ networks.iot is empty'); ok = False
    caps = discover_captures(site)
    say(f'  captures: {len(caps)}')
    for c in caps:
        z = all(os.path.exists(os.path.join(site.zeek_dir, f'{c["label"]}_{i}', 'conn.log')) for i in c['ifaces'])
        say(f'    {c["label"]:<18} state {c["state"] or "-":<4} baseline {"yes" if c["baseline"] else "no ":<3} '
            f'ifaces {",".join(sorted(c["ifaces"]))}  zeek {"done" if z else "missing"}')
    fw = fw_files(site)
    say(f'  firewall logs: {len(fw)} file(s)')
    ph = site.c.get('pihole', {}).get('export')
    if ph: say(f'  pihole export: {ph} {"(found)" if os.path.exists(site.abs(ph)) else "(MISSING)"}')
    for a in site.c.get('annotations', {}).get('files', []):
        say(f'  annotations: {a} {"(found)" if os.path.exists(site.abs(a)) else "(MISSING)"}')
    return ok


# ----------------------------------------------------------------------------------------------- zeek
def zeek_bin(site):
    z = site.c.get('zeek', {}).get('binary')
    for cand in ([z] if z else []) + ['/opt/zeek/bin/zeek', '/usr/local/zeek/bin/zeek', shutil.which('zeek')]:
        if cand and os.path.exists(cand): return cand
    return None


def cmd_zeek(site, args):
    zeek = zeek_bin(site)
    if not zeek:
        todo = [f'{c["label"]}_{i}' for c in discover_captures(site) for i in c['ifaces']
                if not os.path.exists(os.path.join(site.zeek_dir, f'{c["label"]}_{i}', 'conn.log'))]
        if todo or args.force: die('Zeek not found; install it (guide, step 2) or set [zeek] binary')
        say('  Zeek not installed, but every capture already has Zeek logs: nothing to do'); return
    script = site.abs(site.c.get('zeek', {}).get('script', os.path.join(os.path.relpath(HERE, site.root), 'zeek', 'iot-local.zeek')))
    if not os.path.exists(script): die(f'Zeek script not found: {script}')
    bpf = site.c.get('zeek', {}).get('bpf', 'not vlan')
    for c in discover_captures(site):
        for iface, pcaps in sorted(c['ifaces'].items()):
            out = os.path.join(site.zeek_dir, f'{c["label"]}_{iface}')
            if os.path.exists(os.path.join(out, 'conn.log')) and not args.force:
                say(f'  {c["label"]}_{iface}: done already (--force to redo)'); continue
            shutil.rmtree(out, ignore_errors=True); os.makedirs(out)
            t0 = time.time()
            for p in pcaps:   # gzip'd pcaps are streamed through stdin
                cmd = [zeek, '-C', '-r', '-' if p.endswith('.gz') else os.path.abspath(p)]
                if bpf: cmd += ['-f', bpf]
                cmd += [script]
                stdin = gzip.open(p, 'rb') if p.endswith('.gz') else None
                with open(os.path.join(out, 'zeek_stderr.txt'), 'a') as err:
                    r = subprocess.run(cmd, cwd=out, stdin=stdin, stderr=err)
                if r.returncode: die(f'zeek failed on {p} (see {out}/zeek_stderr.txt)')
            say(f'  {c["label"]}_{iface}: {len(os.listdir(out)) - 1} logs in {time.time() - t0:.0f} s')


# ----------------------------------------------------------------------------------------------- prepare
def zeek_log(path):
    if not os.path.exists(path): return
    with open(path, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            if line.startswith('{'): yield json.loads(line)


def renamed(r):
    """Zeek's id.* fields -> src_ip/src_port/dest_ip/dest_port (no dots: simpler SPL)."""
    for a, b in (('id.orig_h', 'src_ip'), ('id.orig_p', 'src_port'), ('id.resp_h', 'dest_ip'), ('id.resp_p', 'dest_port')):
        if a in r: r[b] = r.pop(a)
    return r


FLIP = (('src_ip', 'dest_ip'), ('src_port', 'dest_port'), ('orig_l2_addr', 'resp_l2_addr'), ('orig_bytes', 'resp_bytes'),
        ('orig_pkts', 'resp_pkts'), ('orig_ip_bytes', 'resp_ip_bytes'), ('local_orig', 'local_resp'))


def unflip(r):
    """Zeek marks connections whose direction it guessed and reversed with '^' in history (e.g. mDNS from 5353 to
    5353). Undo it so 'orig' is always the sender of the first packet."""
    if '^' not in (r.get('history') or ''): return r
    for a, b in FLIP:
        if a in r or b in r: r[a], r[b] = r.get(b), r.get(a)
    r['zeek_flipped'] = True
    return r


def unknown_dev(mac, iface):
    return {'mac': mac, 'name': f'unknown {mac}', 'role': 'unknown', 'home_iface': iface, 'baselined': False}


def device_fields(site, d, side=None):
    f = {'device': d['name'], 'device_mac': d['mac'], 'device_role': d['role']}
    if side: f['device_side'] = side
    return f


def redact_url(site, uri):
    keys = site.c.get('privacy', {}).get('redact_url_params', ['sso', 'auth', 'token', 'key', 'password', 'secret'])
    if not uri or '?' not in uri: return uri
    path, q = uri.split('?', 1)
    parts = []
    for kv in q.split('&'):
        k = kv.split('=', 1)[0]
        parts.append(f'{k}=<redacted>' if k.lower() in keys and '=' in kv else kv)
    return path + '?' + '&'.join(parts)


class Prep:
    def __init__(self, site):
        self.site = site
        self.dir = os.path.join(site.out, 'splunk')
        shutil.rmtree(self.dir, ignore_errors=True); os.makedirs(self.dir)
        self.fh = {st: open(os.path.join(self.dir, st.replace(':', '_') + '.ndjson'), 'w', encoding='utf-8')
                   for st in SOURCETYPES}
        self.count = collections.Counter()
        self.ipmap = []            # (ip, mac, first, last) learned from the captures
        self.cap_times = {}        # label -> [first, last]
        self.notes = []

    def capture_at(self, ts, margin=0):
        for k, (a, b) in self.cap_times.items():
            if a - margin <= ts <= b + margin: return k
        return ''

    def out(self, st, ts, ev):
        emit(self.fh[st], ts, self.site.mask_event(ev)); self.count[st] += 1

    def close(self):
        for f in self.fh.values(): f.close()

    # --- pcaps: per-minute volume and health -------------------------------------------------------------
    def pcap_pass(self, cap):
        site = self.site
        skip_vlan = site.c.get('captures', {}).get('skip_vlan_tagged', True)
        for iface, pcaps in sorted(cap['ifaces'].items()):
            vol = collections.defaultdict(collections.Counter)    # (mac, minute) -> counters
            unknown = {}                                           # MACs in the IoT network that the config doesn't list
            health = collections.defaultdict(collections.Counter)  # minute -> counters
            first = last = None
            for p in pcaps:
                for ts, d, orig in iter_frames(p):
                    first = ts if first is None else min(first, ts); last = ts if last is None else max(last, ts)
                    m = int(ts // 60 * 60)
                    health[m]['frames'] += 1
                    if len(d) < 14: continue
                    dst, src = mac_str(d[0:6]), mac_str(d[6:12])
                    et, off = struct.unpack('!H', d[12:14])[0], 14
                    if et == 0x8100:
                        if skip_vlan: health[m]['vlan_tagged_skipped'] += 1; continue
                        et, off = struct.unpack('!H', d[16:18])[0], 18
                    if et == 0x0800 and len(d) >= off + 20:
                        ln = struct.unpack('!H', d[off + 2:off + 4])[0]
                        s_ip, d_ip = '.'.join(map(str, d[off + 12:off + 16])), '.'.join(map(str, d[off + 16:off + 20]))
                    elif et == 0x86dd and len(d) >= off + 40:
                        ln = struct.unpack('!H', d[off + 4:off + 6])[0] + 40
                        s_ip = str(ipaddress.IPv6Address(d[off + 8:off + 24])); d_ip = str(ipaddress.IPv6Address(d[off + 24:off + 40]))
                        if d[off + 6] == 58 and len(d) > off + 40 and d[off + 40] == 134 and src in site.router_macs:
                            health[m]['router_adverts'] += 1
                    else:
                        continue
                    sd, dd = site.dev(src), site.dev(dst)
                    if not sd and iface == site.default_iface and src not in site.router_macs and site.ip_class(s_ip) == 'iot':
                        sd = unknown.setdefault(src, unknown_dev(src, iface))
                    if not dd and iface == site.default_iface and dst not in site.router_macs and not (d[0] & 1) and site.ip_class(d_ip) == 'iot':
                        dd = unknown.setdefault(dst, unknown_dev(dst, iface))
                    if sd and sd['role'] != 'controller' and sd['home_iface'] == iface:
                        c = vol[(src, m)]; cls = site.ip_class(d_ip)
                        c['bytes_out'] += ln; c['pkts_out'] += 1; c[f'out_{cls}'] += ln
                    if dd and dd['role'] != 'controller' and dd['home_iface'] == iface:
                        c = vol[(dst, m)]; cls = site.ip_class(s_ip)
                        c['bytes_in'] += ln; c['pkts_in'] += 1; c[f'in_{cls}'] += ln
            if first is None: continue
            ct = self.cap_times.setdefault(cap['label'], [first, last])
            ct[0], ct[1] = min(ct[0], first), max(ct[1], last)
            base = {'capture': cap['label'], 'state': cap['state'], 'iface': iface}
            for (mac, m), c in sorted(vol.items(), key=lambda x: x[0][1]):
                d = site.dev(mac) or unknown[mac]
                self.out('iot:volume', m, {**base, **device_fields(site, d), 'baselined': d['baselined'], **c})
            for m in range(int(first // 60 * 60), int(last // 60 * 60) + 60, 60):   # every minute, zeros included
                self.out('iot:health', m, {**base, 'frames': health[m]['frames'], 'router_adverts': health[m]['router_adverts'],
                                            **({'vlan_tagged_skipped': health[m]['vlan_tagged_skipped']} if health[m]['vlan_tagged_skipped'] else {})})

    # --- Zeek logs ---------------------------------------------------------------------------------------
    def zeek_pass(self, cap):
        site = self.site
        for iface in sorted(cap['ifaces']):
            zd = os.path.join(site.zeek_dir, f'{cap["label"]}_{iface}')
            if not os.path.exists(os.path.join(zd, 'conn.log')):
                self.notes.append(f'no Zeek logs for {cap["label"]}_{iface}: run the zeek step'); continue
            base = {'capture': cap['label'], 'state': cap['state'], 'iface': iface}
            uid_dev = {}   # uid -> device fields, or None if the connection is counted on another interface
            seen = {}
            keep_unattr = site.c.get('captures', {}).get('keep_unattributed', False)
            for r in zeek_log(os.path.join(zd, 'conn.log')):
                r = unflip(renamed(r))
                om, rm = norm_mac(r.pop('orig_l2_addr', '')), norm_mac(r.pop('resp_l2_addr', ''))
                for ip, mac in ((r.get('src_ip'), om), (r.get('dest_ip'), rm)):
                    if mac and mac not in site.router_macs and ip and unicast_host(ip):
                        k = (ip, mac); seen[k] = (min(seen.get(k, (r['ts'],))[0], r['ts']), max(seen.get(k, (0, 0))[1], r['ts']))
                od, rd = site.dev(om), site.dev(rm)
                d, side = (od, 'orig') if od and od['role'] != 'controller' else (rd, 'resp') if rd and rd['role'] != 'controller' else (None, None)
                if d is None:
                    # not a known device: keep it once (on the default interface) as unattributed traffic
                    if iface != site.default_iface: uid_dev[r['uid']] = None; continue
                    if site.ip_class(r.get('src_ip', '')) == 'iot' and om not in site.router_macs:
                        dv = {'device': f'unknown {om}' if om else 'unknown', 'device_mac': om, 'device_role': 'unknown', 'device_side': 'orig'}
                    elif keep_unattr:
                        dv = {'device': '', 'device_mac': '', 'device_role': '', 'device_side': ''}
                    else:   # other hosts' traffic (e.g. the whole household in a flat capture): not ours to analyse
                        uid_dev[r['uid']] = None; continue
                elif d['home_iface'] != iface:
                    uid_dev[r['uid']] = None; continue
                else:
                    dv = device_fields(site, d, side)
                uid_dev[r['uid']] = dv
                dev_is_orig = dv['device_side'] != 'resp'
                peer_ip = r.get('dest_ip') if dev_is_orig else r.get('src_ip')
                ev = {**base, **dv, **r,
                      'peer_ip': peer_ip, 'peer_port': r.get('dest_port') if dev_is_orig else r.get('src_port'),
                      'peer_class': site.ip_class(peer_ip or ''),
                      'peer_name': site.controllers.get(peer_ip, ''),
                      'initiated_by': 'device' if dev_is_orig else 'peer',
                      'bytes_out': (r.get('orig_ip_bytes') if dev_is_orig else r.get('resp_ip_bytes')) or 0,
                      'bytes_in': (r.get('resp_ip_bytes') if dev_is_orig else r.get('orig_ip_bytes')) or 0}
                self.out('iot:conn', r['ts'], ev)
            for (ip, mac), (a, b) in seen.items(): self.ipmap.append((ip, mac, a, b))
            inc_mdns = site.c.get('zeek', {}).get('include_mdns', False)
            for r in zeek_log(os.path.join(zd, 'dns.log')):
                r = renamed(r)
                if not inc_mdns and r.get('dest_port') in (5353, 5355): continue
                dv = uid_dev.get(r.get('uid'))
                if dv is None: continue
                self.out('iot:dns', r['ts'], {**base, **dv, **r})
            for r in zeek_log(os.path.join(zd, 'ssl.log')):
                r = renamed(r); dv = uid_dev.get(r.get('uid'))
                if dv is None: continue
                r.pop('cert_chain_fps', None); r.pop('client_cert_chain_fps', None)
                self.out('iot:tls', r['ts'], {**base, **dv, **r, 'peer_class': site.ip_class(r.get('dest_ip', ''))})
            for r in zeek_log(os.path.join(zd, 'http.log')):
                r = renamed(r); dv = uid_dev.get(r.get('uid'))
                if dv is None: continue
                r['uri'] = redact_url(site, r.get('uri'))
                self.out('iot:http', r['ts'], {**base, **dv, **r, 'peer_class': site.ip_class(r.get('dest_ip', ''))})
            for r in zeek_log(os.path.join(zd, 'dhcp.log')):
                d = site.dev(r.get('mac'))
                if d and (d['role'] == 'controller' or d['home_iface'] != iface): continue
                if not d:   # unlisted MAC: only if it's in the IoT network (else it's another household host)
                    if iface != site.default_iface: continue
                    if not any(site.ip_class(r.get(k) or '') == 'iot' for k in ('assigned_addr', 'client_addr', 'requested_addr')): continue
                dv = device_fields(site, d) if d else {'device': f'unknown {norm_mac(r.get("mac"))}', 'device_mac': norm_mac(r.get('mac')), 'device_role': 'unknown'}
                if r.get('assigned_addr') and r.get('mac') and unicast_host(r['assigned_addr']): self.ipmap.append((r['assigned_addr'], norm_mac(r['mac']), r['ts'], r['ts'] + (r.get('lease_time') or 0)))
                r.pop('uids', None)
                self.out('iot:dhcp', r['ts'], {**base, **dv, **r})

    def tls_hello_pass(self, cap):
        site = self.site
        if not site.c.get('tls', {}).get('ja4', True): return
        tshark = shutil.which('tshark')
        if not tshark:
            if 'tshark not found: iot:tls_hello (JA4) skipped' not in self.notes: self.notes.append('tshark not found: iot:tls_hello (JA4) skipped')
            return
        for iface, pcaps in sorted(cap['ifaces'].items()):
            for p in pcaps:
                cmd = [tshark, '-r', p, '-Y', 'tls.handshake.type==1 && !vlan', '-T', 'fields', '-E', 'separator=\t',
                       '-e', 'frame.time_epoch', '-e', 'eth.src', '-e', 'ip.src', '-e', 'ipv6.src', '-e', 'ip.dst', '-e', 'ipv6.dst',
                       '-e', 'tcp.dstport', '-e', 'tls.handshake.extensions_server_name', '-e', 'tls.handshake.ja4', '-e', 'tls.handshake.ja3']
                r = subprocess.run(cmd, capture_output=True, text=True)
                if r.returncode:
                    self.notes.append(f'tshark failed on {p}: {r.stderr.strip()[:200]}'); continue
                for line in r.stdout.splitlines():
                    f = line.split('\t') + [''] * 10
                    d = site.dev(f[1])
                    if d and (d['role'] == 'controller' or d['home_iface'] != iface): continue
                    if not d and iface != site.default_iface: continue
                    dst = f[4] or f[5]
                    dv = device_fields(site, d) if d else {'device': f'unknown {norm_mac(f[1])}', 'device_mac': norm_mac(f[1]), 'device_role': 'unknown'}
                    self.out('iot:tls_hello', float(f[0]), {'capture': cap['label'], 'state': cap['state'], 'iface': iface, **dv,
                             'src_ip': f[2] or f[3], 'dest_ip': dst, 'dest_port': int(f[6]) if f[6].isdigit() else None,
                             'peer_class': site.ip_class(dst), 'server_name': f[7], 'ja4': f[8], 'ja3': f[9]})

    # --- firewall log --------------------------------------------------------------------------------------
    def fw_pass(self):
        site = self.site
        fc = site.c.get('firewall', {})
        lines = collections.Counter()      # line -> max count in any one file (files may overlap)
        src_of = {}
        rx = re.compile(r'^(\w{3})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)\s+(?:\S+\s+)?kernel:\s+(?:\[\s*[\d.]+\]\s+)?([A-Z0-9_]+)\s+(.*)$')
        for path in fw_files(site):
            c = collections.Counter(l.rstrip('\r\n') for l in open(path, encoding='utf-8', errors='replace') if l.strip())
            for l, n in c.items():
                if n > lines[l]: lines[l] = n; src_of[l] = path
        prefixes = fc.get('prefixes')        # optional allow-list
        year_cfg = fc.get('year')
        unsynced = 0
        for l, n in lines.items():
            m = rx.match(l)
            if not m: continue
            mon, day, hh, mm, ss, prefix, rest = m.groups()
            if prefixes and prefix not in prefixes: continue
            if mon == 'Jan' and day == '1' and fc.get('skip_unsynced', True):
                unsynced += n; continue           # written before NTP set the router clock (1 Jan)
            # syslog lines carry no year: take it from the config, else from the file's modification time
            # (a December line in a file saved in January belongs to the previous year)
            if year_cfg: year = int(year_cfg)
            else:
                mt = os.path.getmtime(src_of[l]); year = datetime.datetime.fromtimestamp(mt, site.tz).year
                if datetime.datetime(year, MONTHS[mon], int(day), tzinfo=site.tz).timestamp() > mt + 86400: year -= 1
            ts = datetime.datetime(year, MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=site.tz).timestamp()
            kv = {}
            for tok in rest.split():
                if '=' in tok:
                    k, v = tok.split('=', 1)
                    if k not in kv: kv[k] = v      # first LEN= is the IP length; the second is UDP's
                else: kv[tok] = True               # flags such as DF
            mac = kv.get('MAC', '')
            src_mac = mac[18:35] if len(mac) >= 35 else ''
            ev = {'log_prefix': prefix, 'action': 'blocked' if prefix.endswith('DROP') else 'redirected' if 'REDIRECT' in prefix else 'logged',
                  'in_iface': kv.get('IN', ''), 'out_iface': kv.get('OUT', ''), 'src_mac': src_mac,
                  'proto': kv.get('PROTO', ''), 'src_port': int(kv['SPT']) if 'SPT' in kv else None,
                  'dest_port': int(kv['DPT']) if 'DPT' in kv else None, 'length': int(kv['LEN']) if kv.get('LEN', '').isdigit() else None,
                  'icmp_type': int(kv['TYPE']) if kv.get('TYPE', '').isdigit() else None, 'file': os.path.basename(src_of[l])}
            for k, f in (('SRC', 'src_ip'), ('DST', 'dest_ip')):
                try: ev[f] = str(ipaddress.ip_address(kv.get(k, '')))
                except ValueError: ev[f] = kv.get(k, '')
            ev['capture'] = self.capture_at(ts, 60)
            ev['dest_class'] = site.ip_class(ev['dest_ip'])
            ev['dest_name'] = site.controllers.get(ev['dest_ip'], '')
            d = site.dev(src_mac)
            ev.update(device_fields(site, d) if d else {'device': f'unknown {src_mac}' if src_mac else 'unknown', 'device_mac': src_mac, 'device_role': 'unknown'})
            for _ in range(n): self.out('iot:fw', ts, ev)
        if unsynced: self.notes.append(f'firewall: {unsynced} line(s) dated 1 Jan skipped (router clock not yet set)')

    # --- Pi-hole ---------------------------------------------------------------------------------------------
    def mac_at(self, ip, t, margin=3600):
        best = None
        for i, m, a, b in self.ipmap_by_ip.get(ip, ()):
            if a - margin <= t <= b + margin:
                if best is None or (b - a) > (best[1] - best[0]): best = (a, b, m)
        return best[2] if best else self.site.ip_hints.get(ip)

    def pihole_pass(self):
        site = self.site
        pc = site.c.get('pihole', {})
        if not pc.get('export'): return
        path = site.abs(pc['export'])
        if not os.path.exists(path): self.notes.append(f'pihole export missing: {path}'); return
        self.ipmap_by_ip = collections.defaultdict(list)
        for ip, m, a, b in self.ipmap: self.ipmap_by_ip[str(ipaddress.ip_address(ip))].append((ip, m, a, b))
        window = pc.get('window', 'captures')
        margin = pc.get('window_margin_s', 600)
        wins = [(a - margin, b + margin) for a, b in self.cap_times.values()]
        csv.field_size_limit(sys.maxsize)
        kept = dropped = 0
        with open(path, newline='', encoding='utf-8', errors='replace') as fh:
            for r in csv.DictReader(fh):
                try: t = float(r['timestamp'])
                except (KeyError, ValueError): continue
                if window == 'captures' and not any(a <= t <= b for a, b in wins): dropped += 1; continue
                ip = r.get('client', '')
                try: ip = str(ipaddress.ip_address(ip))
                except ValueError: continue
                if not unicast_host(ip): dropped += 1; continue      # e.g. "::" = Pi-hole's own lookups
                mac = self.mac_at(ip, t)
                d = site.dev(mac) if mac else None
                in_iot = site.ip_class(ip) == 'iot'
                if not in_iot and not (d and d['role'] != 'controller'): dropped += 1; continue
                st, ty = int(r.get('status') or 0), int(r.get('type') or 0)
                dv = device_fields(site, d) if d and d['role'] != 'controller' else {'device': f'unknown {ip}', 'device_mac': mac or '', 'device_role': 'unknown'}
                self.out('iot:pihole', t, {'capture': self.capture_at(t, margin), **dv, 'client_ip': ip, 'query': r.get('domain', ''), 'qtype': PH_TYPE.get(ty, str(ty)),
                         'status_code': st, 'status': PH_STATUS.get(st, str(st)), 'blocked': st in PH_BLOCKED,
                         'reply_time_ms': round(float(r['reply_time']) * 1000, 3) if r.get('reply_time') not in (None, '') else None,
                         'forward': r.get('forward', '')})
                kept += 1
        self.notes.append(f'pihole: kept {kept} IoT queries, dropped {dropped} (other clients or outside the capture windows)')

    def annotation_pass(self):
        site = self.site
        for f in site.c.get('annotations', {}).get('files', []):
            p = site.abs(f)
            if not os.path.exists(p): self.notes.append(f'annotations missing: {p}'); continue
            for r in csv.DictReader(open(p, encoding='utf-8')):
                if not r.get('time') or r['time'].startswith('#'): continue
                t = datetime.datetime.fromisoformat(r['time'])
                if t.tzinfo is None: t = t.replace(tzinfo=site.tz)
                self.out('iot:annotation', t.timestamp(), {'capture': r.get('capture', ''), 'kind': r.get('kind', ''),
                                                           'label': r.get('label', ''), 'text': r.get('text', '')})


def fw_files(site):
    pats = site.c.get('firewall', {}).get('files', [])
    out = []
    for p in pats: out += [f for f in sorted(glob.glob(site.abs(p))) if os.path.isfile(f)]
    return sorted(set(out))


def write_lookups(site, prep, caps):
    lk = os.path.join(site.out, 'lookups'); os.makedirs(lk, exist_ok=True)
    rows = [['mac', 'device', 'role', 'type', 'home_iface', 'local_only', 'baselined', 'notes']]
    for d in site.devices.values():
        rows.append([d['mac'], d['name'], d['role'], d.get('type', ''), d.get('home_iface', ''), str(d.get('local_only', False)).lower(),
                     str(d.get('baselined', False)).lower(), d.get('notes', '')])
    write_csv(os.path.join(lk, 'iot_devices.csv'), rows)
    rows = [['ip', 'controller']] + [[ip, n] for ip, n in sorted(site.controllers.items())]
    write_csv(os.path.join(lk, 'iot_controllers.csv'), rows)
    rows = [['capture', 'state', 'baseline', 'start', 'end', 'start_local', 'end_local', 'description']]
    for c in caps:
        a, b = prep.cap_times.get(c['label'], (None, None))
        fmt = lambda t: datetime.datetime.fromtimestamp(t, site.tz).strftime('%Y-%m-%d %H:%M:%S') if t else ''
        rows.append([c['label'], c['state'], str(c['baseline']).lower(), f'{a:.0f}' if a else '', f'{b:.0f}' if b else '', fmt(a), fmt(b), c['description']])
    write_csv(os.path.join(lk, 'iot_captures.csv'), rows)


def write_csv(path, rows):
    import io
    s = io.StringIO(); csv.writer(s, lineterminator='\n').writerows(rows); write_atomic(path, s.getvalue())


def cmd_prepare(site, args):
    caps = discover_captures(site)
    if not caps: die('no captures found (see [captures] pattern)')
    prep = Prep(site)
    t0 = time.time()
    for c in caps:
        say(f'  {c["label"]}: pcaps …'); prep.pcap_pass(c)
        say(f'  {c["label"]}: Zeek logs …'); prep.zeek_pass(c)
        say(f'  {c["label"]}: TLS fingerprints …'); prep.tls_hello_pass(c)
    say('  firewall logs …'); prep.fw_pass()
    say('  Pi-hole …'); prep.pihole_pass()
    prep.annotation_pass()
    prep.close()
    write_lookups(site, prep, caps)
    rep = {'iotpipe': VERSION, 'config': site.rel(site.path), 'generated': datetime.datetime.now(site.tz).isoformat(timespec='seconds'),
           'captures': {k: [round(a, 3), round(b, 3)] for k, (a, b) in prep.cap_times.items()},
           'events': dict(sorted(prep.count.items())), 'notes': prep.notes}
    write_atomic(os.path.join(site.out, 'prepare_report.json'), json.dumps(rep, indent=1) + '\n')
    say(f'done in {time.time() - t0:.0f} s -> {site.rel(prep.dir)}/')
    for st in SOURCETYPES: say(f'  {st:<15} {prep.count[st]:>9,}')
    for n in prep.notes: say(f'  note: {n}')


# ----------------------------------------------------------------------------------------------- Splunk app
APP = 'iot_segmentation'


def props_conf():
    out = ['# Generated by pipeline/iotpipe.py: one stanza per sourcetype.',
           '# Events are one JSON object per line with "ts" (epoch seconds) as the first key.', '']
    for st, desc in SOURCETYPES.items():
        out += [f'[{st}]', f'# {desc}', 'SHOULD_LINEMERGE = false', 'LINE_BREAKER = ([\\r\\n]+)', 'TRUNCATE = 200000',
                'TIME_PREFIX = ^\\{"ts":', 'TIME_FORMAT = %s.%6N', 'MAX_TIMESTAMP_LOOKAHEAD = 20',
                'KV_MODE = json', 'AUTO_KV_JSON = true', 'category = Network & Security', f'description = {desc}', '']
    return '\n'.join(out)


def cmd_app(site, args):
    lk = os.path.join(site.out, 'lookups')
    if not os.path.exists(os.path.join(lk, 'iot_devices.csv')): die('run prepare first (it writes the lookups)')
    app = os.path.join(site.out, 'splunk_app', APP)
    shutil.rmtree(app, ignore_errors=True)
    src = os.path.join(HERE, 'splunk_app', APP)      # static parts (dashboards, macros, …) kept in the repo
    if os.path.exists(src): shutil.copytree(src, app)
    os.makedirs(os.path.join(app, 'default'), exist_ok=True); os.makedirs(os.path.join(app, 'lookups'), exist_ok=True)
    os.makedirs(os.path.join(app, 'metadata'), exist_ok=True)
    write_atomic(os.path.join(app, 'default', 'app.conf'),
                 f'[install]\nis_configured = true\n\n[ui]\nis_visible = true\nlabel = IoT Segmentation\n\n'
                 f'[launcher]\nauthor = IoT Segmentation project\nversion = {VERSION}\n'
                 f'description = Smart-home IoT traffic: device baselines, firewall evidence and detection rules\n\n'
                 f'[package]\nid = {APP}\ncheck_for_updates = false\n')
    write_atomic(os.path.join(app, 'default', 'props.conf'), props_conf())
    write_atomic(os.path.join(app, 'default', 'transforms.conf'),
                 '\n'.join(f'[{n}]\nfilename = {n}.csv\n' for n in ('iot_devices', 'iot_controllers', 'iot_captures')))
    sys.path.insert(0, HERE); import dashboard            # detection macros + overview dashboard
    write_atomic(os.path.join(app, 'default', 'macros.conf'), dashboard.macros_conf(site.index))
    write_atomic(os.path.join(app, 'default', 'data', 'ui', 'views', 'iot_overview.xml'), dashboard.build_view())
    write_atomic(os.path.join(app, 'default', 'data', 'ui', 'nav', 'default.xml'), dashboard.NAV)
    write_atomic(os.path.join(app, 'default', 'indexes.conf'),
                 f'# Optional: creates the index on Splunk Enterprise. Splunk Cloud: create "{site.index}" in the UI instead.\n'
                 f'[{site.index}]\nhomePath = $SPLUNK_DB/{site.index}/db\ncoldPath = $SPLUNK_DB/{site.index}/colddb\n'
                 f'thawedPath = $SPLUNK_DB/{site.index}/thaweddb\n')
    write_atomic(os.path.join(app, 'metadata', 'default.meta'), '[]\naccess = read : [ * ], write : [ admin ]\nexport = system\n')
    for f in os.listdir(lk): shutil.copy(os.path.join(lk, f), os.path.join(app, 'lookups', f))
    tgz = os.path.join(site.out, f'{APP}.tgz')
    with tarfile.open(tgz, 'w:gz') as t: t.add(app, arcname=APP)
    say(f'app -> {site.rel(app)}/  and  {site.rel(tgz)} (Splunk: Apps → Manage Apps → Install app from file)')


# ----------------------------------------------------------------------------------------------- HEC
def cmd_send(site, args):
    token = os.environ.get('SPLUNK_HEC_TOKEN')
    if not token and not args.dry_run: die('set the HEC token in the environment: export SPLUNK_HEC_TOKEN=…')
    url = args.url.rstrip('/')
    if not url.endswith('/services/collector/event'): url += '/services/collector/event'
    ctx = ssl.create_default_context()
    if args.insecure: ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    d = os.path.join(site.out, 'splunk')
    files = sorted(glob.glob(os.path.join(d, '*.ndjson')))
    if not files: die('nothing to send: run prepare first')
    total = 0
    for f in files:
        st = os.path.basename(f)[:-7].replace('_', ':', 1)
        if args.only and st not in args.only: continue
        n, batch, size = 0, [], 0
        def flush():
            nonlocal batch, size
            if not batch: return
            body = ''.join(batch).encode()
            if not args.dry_run: post(url, token, body, ctx)
            batch, size = [], 0
        for line in open(f, encoding='utf-8'):
            ev = json.loads(line)
            env = {'time': ev['ts'], 'host': site.name, 'source': f'iotpipe:{ev.get("capture") or st.split(":")[1]}',
                   'sourcetype': st, 'index': site.index, 'event': ev}
            s = json.dumps(env, separators=(',', ':'))
            batch.append(s); size += len(s); n += 1
            if size > args.batch_bytes: flush()
        flush()
        total += n
        say(f'  {st:<15} {n:>9,} events{" (dry run)" if args.dry_run else " sent"}')
    say(f'total {total:,} events -> {url} index={site.index}')


def post(url, token, body, ctx, tries=5):
    req = urllib.request.Request(url, data=body, method='POST',
                                 headers={'Authorization': f'Splunk {token}', 'Content-Type': 'application/json'})
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
                res = json.loads(r.read() or b'{}')
                if res.get('code', 0) != 0: die(f'HEC error: {res}')
                return
        except urllib.error.HTTPError as e:
            msg = e.read().decode(errors='replace')
            if e.code in (429, 503) and i < tries - 1: time.sleep(2 ** i); continue
            die(f'HEC HTTP {e.code}: {msg}')
        except urllib.error.URLError as e:
            if i < tries - 1: time.sleep(2 ** i); continue
            die(f'cannot reach {url}: {e.reason}')


# ----------------------------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('command', choices=['check', 'zeek', 'prepare', 'app', 'send', 'all'])
    ap.add_argument('-c', '--config', default=os.path.join(HERE, 'site.toml'))
    ap.add_argument('--force', action='store_true', help='zeek: redo captures that already have logs')
    ap.add_argument('--url', help='send: Splunk HEC base URL, e.g. https://splunk.example:8088')
    ap.add_argument('--insecure', action='store_true', help='send: accept a self-signed HEC certificate')
    ap.add_argument('--only', nargs='*', help='send: only these sourcetypes (e.g. iot:fw iot:pihole)')
    ap.add_argument('--dry-run', action='store_true', help='send: build the requests but do not post them')
    ap.add_argument('--batch-bytes', type=int, default=800_000)
    a = ap.parse_args()
    site = Site(a.config)
    if a.command == 'check': sys.exit(0 if cmd_check(site, a) else 1)
    if a.command == 'zeek': cmd_zeek(site, a)
    if a.command == 'prepare': cmd_prepare(site, a)
    if a.command == 'app': cmd_app(site, a)
    if a.command == 'send':
        if not a.url: die('send needs --url')
        cmd_send(site, a)
    if a.command == 'all':
        cmd_check(site, a); cmd_zeek(site, a); cmd_prepare(site, a); cmd_app(site, a)


if __name__ == '__main__':
    main()
