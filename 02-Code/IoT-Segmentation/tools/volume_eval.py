#!/usr/bin/env python3
"""Volume-upload scenario evaluation (R3-seg / R3-dev), dependency-free.

  python3 tools/volume_eval.py            # writes derived/analysis/upload_eval.json and prints the tables

Reads the upload capture (20261031-172658_upload/), the Zeek logs of that capture (derived/zeek/upload_*/,
for MEGA attribution) and the segmented baseline summaries (derived/analysis/summary_seg_*.json).
Counts IP-layer bytes (IPv4 total length, IPv6 payload length + 40), the same unit as the baseline.
Each device is counted only on its home interface (Hue on eth7, everything else on wl0.2).
Thresholds are the pre-registered ones from planning/volume_upload_runsheet.md.
"""
import collections, datetime, glob, ipaddress, json, os, statistics, struct, sys
from zoneinfo import ZoneInfo

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TZ = ZoneInfo('Australia/Sydney')
CAP = '20261031-172658_upload'
DEV = {  # MAC -> (name, home interface, baselined?)
    'ec:b5:fa:bc:52:10': ('Hue Bridge', 'eth7', True),
    '0c:4e:a0:30:22:54': ('SwitchBot Hub 2', 'wl0.2', True),
    '8c:87:d0:09:0d:6b': ('Matter switch 0d6b', 'wl0.2', True),
    '8c:87:d0:09:0d:6e': ('Matter switch 0d6e', 'wl0.2', True),
    '7c:f1:7e:10:03:a0': ('Tapo smart plug', 'wl0.2', True),
    'c4:e7:ae:20:54:57': ('Meross smart plug', 'wl0.2', False),
    'd8:f1:5b:90:ee:b3': ('VFD clock', 'wl0.2', False),
    '42:e3:fe:60:6c:d9': ('Test host (MacBook)', 'wl0.2', False),
}
TEST = '42:e3:fe:60:6c:d9'
def ts(s): return datetime.datetime.strptime('2026-10-31 ' + s, '%Y-%m-%d %H:%M:%S').replace(tzinfo=TZ).timestamp()
WINDOWS = [  # minute-aligned edges from upload_run/timeline.txt; Run A ends when its transfer ended (17:41:31 in
             # Zeek conn.log; the timeline's "Run A end" 17:40:50 was logged before the upload had finished)
    ('quiet', ts('17:27:00'), ts('17:37:00')),
    ('run_A', ts('17:37:00'), ts('17:42:00')),
    ('gap', ts('17:42:00'), ts('17:46:00')),
    ('run_B', ts('17:46:00'), ts('18:17:00')),
    ('tail', ts('18:17:00'), ts('18:29:00')),   # capture stopped 18:28:22
    ('slow_hour', ts('17:46:00'), ts('18:29:00')),  # everything after Run A: the hour R3 would see for Run B
]
R3_SEG = 10 * 206309          # 10 × Hue median hourly upload (segmented capture), B/h
R3_DEV_TAPO = 10 * 76         # 10 × Tapo median, B/h

def external(ip):
    a = ipaddress.ip_address(ip)
    return not (a.is_private or a.is_multicast or a.is_link_local or a.is_loopback or a.is_unspecified or a.is_reserved
                or ip == '255.255.255.255')

# MEGA addresses: every address a *mega* name resolved to (Zeek dns.log) or that carried a mega SNI (ssl/quic.log)
mega = set()
for log in glob.glob('derived/zeek/upload_*/dns.log'):
    for line in open(log):
        r = json.loads(line)
        if 'mega' in (r.get('query') or ''):
            mega |= {a for a in r.get('answers') or [] if a[0].isdigit() or ':' in a} - {'0.0.0.0', '::'}
for log in glob.glob('derived/zeek/upload_*/ssl.log') + glob.glob('derived/zeek/upload_*/quic.log'):
    for line in open(log):
        r = json.loads(line)
        if 'mega' in (r.get('server_name') or ''): mega.add(r['id.resp_h'])

def mac(b): return ':'.join(f'{x:02x}' for x in b)
minute = collections.Counter()      # (dev, minute_ts, cls) -> IP bytes out to external (cls: 'all' / 'mega')
l2_from_clients = 0                 # all frames sent by Wi-Fi clients on wl0.2 (cross-check with the router's rx_bytes)
first_ts = last_ts = None
for iface in ('wl0.2', 'eth7'):
    path = glob.glob(f'{CAP}/{iface}_*.pcap')[0]
    with open(path, 'rb') as f:
        gh = f.read(24); e = '<' if struct.unpack('<I', gh[:4])[0] in (0xa1b2c3d4, 0xa1b23c4d) else '>'
        nano = struct.unpack('<I', gh[:4])[0] in (0xa1b23c4d, 0x4d3cb2a1)
        while True:
            h = f.read(16)
            if len(h) < 16: break
            sec, frac, incl, orig = struct.unpack(e + 'IIII', h); d = f.read(incl)
            t = sec + frac / (1e9 if nano else 1e6)
            first_ts = t if first_ts is None else min(first_ts, t); last_ts = t if last_ts is None else max(last_ts, t)
            src = mac(d[6:12])
            if iface == 'wl0.2' and src != '92:28:aa:2b:39:62' and src != 'cc:28:aa:2b:39:60': l2_from_clients += orig
            if src not in DEV or DEV[src][1] != iface: continue
            et, off = struct.unpack('!H', d[12:14])[0], 14
            if et == 0x8100: et, off = struct.unpack('!H', d[16:18])[0], 18
            if et == 0x0800:
                ln = struct.unpack('!H', d[off + 2:off + 4])[0]; dst = '.'.join(map(str, d[off + 16:off + 20]))
            elif et == 0x86dd:
                ln = struct.unpack('!H', d[off + 4:off + 6])[0] + 40
                dst = str(ipaddress.IPv6Address(d[off + 24:off + 40]))
            else: continue
            if not external(dst): continue
            m = int(t // 60 * 60)
            minute[(src, m, 'all')] += ln
            if dst in mega: minute[(src, m, 'mega')] += ln

def total(dev, cls, a, b): return sum(v for (d, m, c), v in minute.items() if d == dev and c == cls and a <= m < b)
res = {'capture': CAP, 'first_packet': first_ts, 'last_packet': last_ts, 'mega_addresses': sorted(mega),
       'thresholds_B_per_h': {'R3_seg': R3_SEG, 'R3_dev_tapo': R3_DEV_TAPO}, 'l2_bytes_from_wifi_clients': l2_from_clients,
       'windows': {}, 'clock_hours': {}, 'rolling_60min_max': {}, 'devices': {}}
for name, a, b in WINDOWS:
    a, b = int(a), int(b)
    hrs = (b - a) / 3600
    row = {}
    for dev in DEV:
        for cls in ('all', 'mega'):
            v = total(dev, cls, a, b)
            if v or dev == TEST: row[f'{DEV[dev][0]}|{cls}'] = {'bytes': v, 'rate_B_per_h': round(v / hrs) if hrs else 0}
    res['windows'][name] = {'start': a, 'end': b, 'minutes': round(hrs * 60), 'rows': row}
for hr in sorted({int(m // 3600 * 3600) for (_, m, _) in minute}):
    lab = datetime.datetime.fromtimestamp(hr, TZ).strftime('%H:00')
    res['clock_hours'][lab] = {f'{DEV[d][0]}|{c}': total(d, c, hr, hr + 3600) for d in DEV for c in ('all', 'mega') if total(d, c, hr, hr + 3600)}
mins = sorted({m for (_, m, _) in minute})
for dev in DEV:
    for cls in ('all', 'mega'):
        best = max((total(dev, cls, m, m + 3600), m) for m in mins) if mins else (0, None)
        if best[0]: res['rolling_60min_max'][f'{DEV[dev][0]}|{cls}'] = {'bytes': best[0], 'window_start': best[1]}
# per-device R3 for the baselined devices (control): 10 × own median hourly upload from the segmented capture
h = collections.defaultdict(list)
for iface in ('wl0.2', 'eth7'):
    for dv, _, v in json.load(open(f'derived/analysis/summary_seg_{iface}.json'))['hourly_external_bytes_out']: h[dv].append(v)
for dev, (name, _, base) in DEV.items():
    med = int(statistics.median(h[name])) if h.get(name) else 0
    worst = max((v for k, v in res['clock_hours'].items() for kk, v in v.items() if kk == f'{name}|all'), default=0)
    res['devices'][name] = {'mac': dev, 'baselined': base, 'baseline_median_B_per_h': med if base else None,
                            'max_clock_hour_B': worst, 'R3_dev_fires': (worst > 10 * med) if base and med else None}
os.makedirs('derived/analysis', exist_ok=True)
json.dump(res, open('derived/analysis/upload_eval.json', 'w'), indent=1)
print(json.dumps({k: res[k] for k in ('windows', 'clock_hours', 'rolling_60min_max', 'devices')}, indent=1))
print('mega addresses', len(mega), 'L2 bytes from Wi-Fi clients', l2_from_clients)
