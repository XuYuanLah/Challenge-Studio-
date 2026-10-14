#!/usr/bin/env python3
"""Summarise classic pcap files without external dependencies.

For each pcap: packet count, first/last timestamp, VLAN-tagged frame counts,
and a source MAC -> source IP map (IPv4, IPv6, ARP sender).
Usage: pcap_inventory.py OUT_JSON PCAP [PCAP ...]
"""
import json, struct, sys, ipaddress, collections, os

def mac(b): return ':'.join(f'{x:02x}' for x in b)

def summarise(path):
    with open(path, 'rb') as f:
        gh = f.read(24)
        magic = gh[:4]
        if magic == b'\xd4\xc3\xb2\xa1': endian, nano = '<', False
        elif magic == b'\xa1\xb2\xc3\xd4': endian, nano = '>', False
        elif magic == b'\x4d\x3c\xb2\xa1': endian, nano = '<', True
        elif magic == b'\xa1\xb2\x3c\x4d': endian, nano = '>', True
        else: raise SystemExit(f'{path}: not a classic pcap')
        linktype = struct.unpack(endian + 'I', gh[20:24])[0]
        rec = struct.Struct(endian + 'IIII')
        n = 0; first = last = None
        vlan = collections.Counter()
        macip = collections.defaultdict(set)
        ethertypes = collections.Counter()
        while True:
            h = f.read(16)
            if len(h) < 16: break
            ts_s, ts_f, incl, orig = rec.unpack(h)
            d = f.read(incl)
            n += 1
            ts = ts_s + ts_f / (1e9 if nano else 1e6)
            if first is None: first = ts
            last = ts
            if linktype != 1 or len(d) < 14: continue
            src = mac(d[6:12]); et = struct.unpack('>H', d[12:14])[0]; off = 14
            while et in (0x8100, 0x88a8) and len(d) >= off + 4:
                vid = struct.unpack('>H', d[off:off+2])[0] & 0x0fff
                vlan[vid] += 1
                et = struct.unpack('>H', d[off+2:off+4])[0]; off += 4
            ethertypes[f'0x{et:04x}'] += 1
            p = d[off:]
            if et == 0x0800 and len(p) >= 20:
                ip = str(ipaddress.IPv4Address(p[12:16]))
                if ip != '0.0.0.0': macip[src].add(ip)
            elif et == 0x86dd and len(p) >= 40:
                ip = ipaddress.IPv6Address(p[8:24])
                if not ip.is_unspecified: macip[src].add(str(ip))
            elif et == 0x0806 and len(p) >= 28:
                ip = str(ipaddress.IPv4Address(p[14:18]))
                if ip != '0.0.0.0': macip[src].add(ip)
    return {
        'file': path, 'size': os.path.getsize(path), 'linktype': linktype,
        'packets': n, 'first_ts': first, 'last_ts': last,
        'vlan_tagged_frames': dict(sorted(vlan.items())),
        'ethertypes': dict(ethertypes.most_common()),
        'mac_to_ips': {m: sorted(v) for m, v in sorted(macip.items())},
    }

if __name__ == '__main__':
    out = [summarise(p) for p in sys.argv[2:]]
    json.dump(out, open(sys.argv[1], 'w'), indent=1)
    for s in out:
        print(f"{s['file']}: {s['packets']} pkts, VLAN tags {s['vlan_tagged_frames']}, {len(s['mac_to_ips'])} src MACs")
