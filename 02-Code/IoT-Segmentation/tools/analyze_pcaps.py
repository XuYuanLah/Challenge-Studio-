#!/usr/bin/env python3
"""Per-device flow, DNS, TLS-SNI and mDNS analysis of the IoT captures (no external deps).

Each device is analysed only on its own capture interface (Hue Bridge -> eth7,
all others -> wl0.2) so no packet is counted twice. VLAN-tagged frames (VLAN 114
in the flat eth7 capture) are skipped: out of scope.
Outputs JSON + flow CSVs under derived/analysis/.
"""
import struct, ipaddress, json, csv, sys, os, collections, datetime
from zoneinfo import ZoneInfo
TZ = ZoneInfo('Australia/Sydney')

DEV = {  # MAC -> (name, home interface)
    'ec:b5:fa:bc:52:10': ('Hue Bridge', 'eth7'),
    '0c:4e:a0:30:22:54': ('SwitchBot Hub 2', 'wl0.2'),
    '8c:87:d0:09:0d:6b': ('Matter switch 0d6b', 'wl0.2'),
    '8c:87:d0:09:0d:6e': ('Matter switch 0d6e', 'wl0.2'),
    '7c:f1:7e:10:03:a0': ('Tapo smart plug', 'wl0.2'),
}
ROUTER_MACS = {'cc:28:aa:2b:39:60': 'router (br0)', '92:28:aa:2b:39:62': 'router (br52)'}
MAINLAN = {
    '192.168.0.1': 'router', '192.168.0.2': 'Mac Studio', '192.168.0.4': 'MacBook Pro',
    '192.168.0.8': 'Pi-hole (RPi)', '192.168.0.13': 'Mac mini Server', '192.168.0.14': 'iKOOLCORE-R2',
    '192.168.0.22': 'HomePod', '192.168.0.221': 'iPhone',
    'fd00:d:e:f::8': 'Pi-hole (RPi)', 'fd00:d:e:f:183e:4f13:4044:5684': 'HomePod', 'fd00:d:e:f::1': 'router',
}
PIHOLE = {'192.168.0.8', 'fd00:d:e:f::8'}
NETS = [
    (ipaddress.ip_network('192.168.107.0/27'), 'iot'), (ipaddress.ip_network('fd00:d:e:6b::/64'), 'iot'),
    (ipaddress.ip_network('192.168.0.0/24'), 'mainlan'), (ipaddress.ip_network('fd00:d:e:f::/64'), 'mainlan'),
    (ipaddress.ip_network('2001:db8:100::/48'), 'mainlan_gua'),
    (ipaddress.ip_network('192.168.114.0/24'), 'vlan114'),
]
def mac(b): return ':'.join(f'{x:02x}' for x in b)

def classify(ip):
    a = ipaddress.ip_address(ip)
    if a.is_multicast or ip == '255.255.255.255' or (a.version == 4 and ip.endswith('.255')): return 'multicast/broadcast'
    for n, c in NETS:
        if a in n: return c
    if a.is_link_local: return 'link-local'
    if a.is_private or a.is_reserved or a.is_unspecified: return 'other-nonpublic'
    return 'external'

def qname(p, off, depth=0):
    labels = []; jumped = False; end = None
    while off < len(p) and depth < 20:
        l = p[off]
        if l == 0: off += 1; break
        if l & 0xc0 == 0xc0:
            if off + 1 >= len(p): return None, len(p)
            if not jumped: end = off + 2
            off = ((l & 0x3f) << 8) | p[off + 1]; jumped = True; depth += 1; continue
        labels.append(p[off + 1:off + 1 + l].decode('ascii', 'replace')); off += 1 + l
    return '.'.join(labels), (end if jumped else off)

def parse_dns(p):
    if len(p) < 12: return None
    qd, an = struct.unpack('>HH', p[4:8]); off = 12; qs = []; ans = []
    try:
        for _ in range(qd):
            n, off = qname(p, off); t = struct.unpack('>H', p[off:off+2])[0]; off += 4; qs.append((n, t))
        for _ in range(an):
            n, off = qname(p, off); t, c, ttl, rl = struct.unpack('>HHIH', p[off:off+10]); off += 10
            rd = p[off:off+rl]
            if t == 1 and rl == 4: ans.append((n, 'A', str(ipaddress.IPv4Address(rd))))
            elif t == 28 and rl == 16: ans.append((n, 'AAAA', str(ipaddress.IPv6Address(rd))))
            elif t == 5: ans.append((n, 'CNAME', qname(p, off)[0]))
            elif t == 12: ans.append((n, 'PTR', qname(p, off)[0]))
            off += rl
    except Exception:
        pass
    return qs, ans

def sni(p):
    try:
        if len(p) < 43 or p[0] != 0x16 or p[5] != 0x01: return None
        off = 43; sl = p[off]; off += 1 + sl
        cl = struct.unpack('>H', p[off:off+2])[0]; off += 2 + cl
        ml = p[off]; off += 1 + ml
        el = struct.unpack('>H', p[off:off+2])[0]; off += 2; end = off + el
        while off + 4 <= end:
            t, l = struct.unpack('>HH', p[off:off+4]); off += 4
            if t == 0:
                nl = struct.unpack('>H', p[off+3:off+5])[0]; return p[off+5:off+5+nl].decode('ascii', 'replace')
            off += l
    except Exception:
        return None

def run(pcap, iface, label, out):
    flows = {}; dnsmap = collections.defaultdict(set); dnsq = []; snis = collections.Counter()
    mdns_types = collections.Counter(); mdns_hosts = set(); odd = collections.Counter(); hourly = collections.Counter()
    l2hosts = set(); thread_pkts = 0; mdns_iot_dst = collections.Counter(); n = 0
    with open(pcap, 'rb') as f:
        gh = f.read(24); e = '<' if gh[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
        nano = gh[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'); rec = struct.Struct(e + 'IIII')
        while True:
            h = f.read(16)
            if len(h) < 16: break
            s, fr, incl, orig = rec.unpack(h); d = f.read(incl); n += 1
            ts = s + fr / (1e9 if nano else 1e6)
            if len(d) < 14: continue
            dm, sm = mac(d[0:6]), mac(d[6:12]); et = struct.unpack('>H', d[12:14])[0]
            if et in (0x8100, 0x88a8): continue                       # VLAN 114 etc.: out of scope
            l2hosts.add(sm)
            p = d[14:]
            if et == 0x0800 and len(p) >= 20:
                ihl = (p[0] & 15) * 4; proto = p[9]; src = str(ipaddress.IPv4Address(p[12:16])); dst = str(ipaddress.IPv4Address(p[16:20])); pl = p[ihl:]; ln = struct.unpack('>H', p[2:4])[0]
            elif et == 0x86dd and len(p) >= 40:
                proto = p[6]; src = str(ipaddress.IPv6Address(p[8:24])); dst = str(ipaddress.IPv6Address(p[24:40])); pl = p[40:]; ln = 40 + struct.unpack('>H', p[4:6])[0]
                while proto in (0, 43, 60) and len(pl) >= 8: proto = pl[0]; pl = pl[(pl[1] + 1) * 8:]
                if src.startswith('fd05:37e5:64c4') or dst.startswith('fd05:37e5:64c4'): thread_pkts += 1
            else:
                continue
            sport = dport = 0; flags = 0; payload = b''
            if proto == 6 and len(pl) >= 20:
                sport, dport = struct.unpack('>HH', pl[:4]); flags = pl[13]; payload = pl[(pl[12] >> 4) * 4:]
            elif proto == 17 and len(pl) >= 8:
                sport, dport = struct.unpack('>HH', pl[:4]); payload = pl[8:]
            # mDNS service types visible on this interface (exposure)
            if proto == 17 and dport == 5353 and sm not in DEV:
                r = parse_dns(payload)
                if r:
                    for nm, *_ in r[0] + r[1]:
                        if nm and nm.startswith('_') and '._' in nm: mdns_types[nm.split('.local')[0].split('._sub.')[-1] if '._sub.' in nm else nm.replace('.local', '')] += 1
                    mdns_hosts.add(sm)
            if sm in DEV and DEV[sm][1] == iface: dev, local, remote, lport, rport, out_dir = DEV[sm][0], src, dst, sport, dport, True
            elif dm in DEV and DEV[dm][1] == iface: dev, local, remote, lport, rport, out_dir = DEV[dm][0], dst, src, dport, sport, False
            else: continue
            if out_dir and proto == 17 and dport == 5353: mdns_iot_dst[(dev, dst)] += 1
            if out_dir and dst == '255.2.0.0': odd[(dev, 'dst 255.2.0.0', proto, dport)] += 1
            # DNS
            if proto == 17 and (sport == 53 or dport == 53):
                r = parse_dns(payload)
                if r:
                    if out_dir and dport == 53:
                        for nm, t in r[0]: dnsq.append((ts, dev, dst, nm, t))
                    if not out_dir and sport == 53:
                        for nm, t, v in r[1]:
                            if t in ('A', 'AAAA'): dnsmap[v].add(r[0][0][0] if r[0] else nm)
            if out_dir and proto == 6 and payload:
                sn = sni(payload)
                if sn: snis[(dev, sn, dport)] += 1
            prot = {6: 'tcp', 17: 'udp', 1: 'icmp', 58: 'icmpv6'}.get(proto, str(proto))
            # server-side port: well-known heuristics
            key = (dev, prot, remote, rport if (out_dir or rport < lport or rport in (53, 123, 443, 5540, 5353, 8883)) else lport, 'out' if out_dir else 'in')
            if proto == 6:
                syn = flags & 0x12 == 0x02
                key = (dev, prot, remote, (rport if out_dir else lport) if syn else key[3], key[4])
            fl = flows.get(key)
            if fl is None:
                fl = flows[key] = {'first': ts, 'last': ts, 'pkts_out': 0, 'pkts_in': 0, 'bytes_out': 0, 'bytes_in': 0, 'syn': 0, 'sessions': 1}
            elif ts - fl['last'] > 120: fl['sessions'] += 1
            fl['last'] = ts
            if out_dir: fl['pkts_out'] += 1; fl['bytes_out'] += ln
            else: fl['pkts_in'] += 1; fl['bytes_in'] += ln
            if proto == 6 and flags & 0x12 == 0x02: fl['syn'] += 1
            if out_dir and classify(remote) == 'external':
                hourly[(dev, datetime.datetime.fromtimestamp(ts, TZ).strftime('%m-%d %H:00'))] += ln
    rows = []
    for (dev, prot, remote, port, direc), fl in flows.items():
        rows.append({'device': dev, 'proto': prot, 'remote': remote, 'remote_class': classify(remote),
                     'remote_name': MAINLAN.get(remote) or ','.join(sorted(dnsmap.get(remote, []))[:3]),
                     'port': port, 'initiator_side': direc, **fl})
    with open(f'{out}/flows_{label}.csv', 'w', newline='') as fo:
        w = csv.DictWriter(fo, fieldnames=list(rows[0])); w.writeheader(); w.writerows(sorted(rows, key=lambda r: (r['device'], -r['bytes_out'] - r['bytes_in'])))
    summary = {'pcap': pcap, 'iface': iface, 'packets': n, 'l2_sources': len(l2hosts), 'thread_ula_pkts': thread_pkts,
               'mdns_service_types_from_non_iot': dict(mdns_types.most_common()), 'mdns_non_iot_sources': len(mdns_hosts),
               'dns_queries': [[t, d, s, q, ty] for t, d, s, q, ty in dnsq],
               'sni': [[d, s, p, c] for (d, s, p), c in snis.most_common()],
               'odd_destinations': [[*k, v] for k, v in odd.items()],
               'mdns_iot_destinations': [[*k, v] for k, v in mdns_iot_dst.items()],
               'hourly_external_bytes_out': [[*k, v] for k, v in sorted(hourly.items())]}
    json.dump(summary, open(f'{out}/summary_{label}.json', 'w'), indent=1)
    print(label, iface, n, 'pkts', len(rows), 'flows', len(dnsq), 'dnsq', sum(snis.values()), 'sni')

if __name__ == '__main__':
    out = 'derived/analysis'
    for cap, lab in (('20261006-215327_flat', 'flat'), ('20261010-002759_seg', 'seg'), ('20261011-134542_app_interaction', 'app'), ('20261011-164338_tapo', 'tapo')):
        for iface in ('wl0.2', 'eth7'):
            pc = [os.path.join(cap, x) for x in os.listdir(cap) if x.startswith(iface + '_') and x.endswith('.pcap')][0]
            run(pc, iface, f'{lab}_{iface}', out)
