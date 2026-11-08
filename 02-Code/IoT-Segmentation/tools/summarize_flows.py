#!/usr/bin/env python3
"""Aggregate derived/analysis flows/summaries into per-device baseline tables (stdout + JSON)."""
import csv, json, collections, sys
A = 'derived/analysis'
res = {}
for cap in ('flat', 'seg', 'app', 'tapo'):
    rows = []; summ = {}
    for iface in ('wl0.2', 'eth7'):
        rows += list(csv.DictReader(open(f'{A}/flows_{cap}_{iface}.csv')))
        summ[iface] = json.load(open(f'{A}/summary_{cap}_{iface}.json'))
    dur = max(float(r['last']) for r in rows) - min(float(r['first']) for r in rows)
    out = {}
    for dev in sorted({r['device'] for r in rows}):
        R = [r for r in rows if r['device'] == dev]
        d = {}
        by = collections.defaultdict(lambda: [0, 0, 0, 0, set()])  # bytes_out, bytes_in, sessions, syn, names
        for r in R:
            k = (r['remote_class'], r['proto'], r['port'], r['initiator_side'])
            b = by[k]; b[0] += int(r['bytes_out']); b[1] += int(r['bytes_in']); b[2] += int(r['sessions']); b[3] += int(r['syn'])
            b[4].add(r['remote_name'] or r['remote'])
        d['by_class_proto_port'] = sorted([[*k, v[0], v[1], v[2], v[3], sorted(v[4])[:6], len(v[4])] for k, v in by.items()], key=lambda x: -(x[4] + x[5]))
        ext = [r for r in R if r['remote_class'] == 'external']
        d['external_remotes'] = len({r['remote'] for r in ext})
        d['external_names'] = sorted({n for r in ext for n in (r['remote_name'] or '').split(',') if n})
        d['external_bytes_out'] = sum(int(r['bytes_out']) for r in ext); d['external_bytes_in'] = sum(int(r['bytes_in']) for r in ext)
        d['external_ports'] = dict(collections.Counter(f"{r['proto']}/{r['port']}" for r in ext))
        d['total_bytes'] = sum(int(r['bytes_out']) + int(r['bytes_in']) for r in R)
        d['internal_peers'] = sorted({(r['remote_name'] or r['remote'], r['proto'], r['port'], r['initiator_side'], r['remote_class']) for r in R if r['remote_class'] in ('mainlan', 'mainlan_gua', 'iot')})
        dnsq = [q for s in summ.values() for q in s['dns_queries'] if q[1] == dev]
        d['dns_queries'] = len(dnsq); d['dns_servers'] = dict(collections.Counter(q[2] for q in dnsq))
        d['dns_top'] = collections.Counter(q[3] for q in dnsq).most_common(15)
        d['sni'] = [x for s in summ.values() for x in s['sni'] if x[0] == dev]
        out[dev] = d
    res[cap] = {'duration_h': dur / 3600, 'devices': out,
                'iface': {i: {k: s[k] for k in ('packets', 'l2_sources', 'thread_ula_pkts', 'mdns_non_iot_sources', 'odd_destinations', 'mdns_iot_destinations')} | {'mdns_types': len(s['mdns_service_types_from_non_iot']), 'mdns_types_list': list(s['mdns_service_types_from_non_iot'])[:40]} for i, s in summ.items()}}
json.dump(res, open(f'{A}/baselines.json', 'w'), indent=1, default=list)
for cap, c in res.items():
    print(f"\n######## {cap}  ({c['duration_h']:.2f} h)")
    for i, s in c['iface'].items(): print('  iface', i, s)
    for dev, d in c['devices'].items():
        print(f"\n== {dev}: total {d['total_bytes']/1e6:.2f} MB, ext remotes {d['external_remotes']}, ext out/in {d['external_bytes_out']/1e3:.0f}/{d['external_bytes_in']/1e3:.0f} kB, dnsq {d['dns_queries']} {d['dns_servers']}")
        print('   ext ports', d['external_ports'])
        print('   ext names', d['external_names'][:25])
        print('   SNI', d['sni'][:12])
        print('   DNS top', d['dns_top'][:12])
        print('   internal', d['internal_peers'][:20])
        for x in d['by_class_proto_port'][:12]: print('   ', x)
