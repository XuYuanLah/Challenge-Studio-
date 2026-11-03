#!/usr/bin/env python3
"""Trim a full Pi-hole FTL query export to IoT clients within the experiment windows.

Input : pihole_export.csv  (sqlite3 -header -csv pihole-FTL.db "SELECT * FROM queries;")
Output: derived/pihole_iot_trimmed.csv  (original columns + window, time_local, device)

A row is kept only if its timestamp falls inside one of the windows below AND its
client address belongs to an IoT device for that window:
  - flat window: the main-LAN addresses the IoT devices used before segmentation,
    derived from their MACs in the flat capture (derived/pcap_inventory.json)
  - later windows: the IoT VLAN (192.168.107.0/27, fd00:d:e:6b::/64)
Everything else (main LAN hosts, VLAN 114, other periods) is dropped.
"""
import csv, json, sys, ipaddress, datetime, collections
csv.field_size_limit(sys.maxsize)
from zoneinfo import ZoneInfo

TZ = ZoneInfo('Australia/Sydney')
def ep(s): return datetime.datetime.strptime(s, '%Y-%m-%d %H:%M:%S').replace(tzinfo=TZ).timestamp()

# IoT devices by MAC (identified from the segmented captures; names per device inventory)
IOT_MACS = {
    '0c:4e:a0:30:22:54': 'SwitchBot Hub 2',
    '7c:f1:7e:10:03:a0': 'Tapo smart plug',
    '8c:87:d0:09:0d:6b': 'Matter switch 0d6b',
    '8c:87:d0:09:0d:6e': 'Matter switch 0d6e',
    'ec:b5:fa:bc:52:10': 'Hue Bridge',
}
IOT_NETS = [ipaddress.ip_network('192.168.107.0/27'), ipaddress.ip_network('fd00:d:e:6b::/64')]

WINDOWS = [  # label, start, end (Australia/Sydney)
    ('W1_flat_capture',      '2026-10-06 21:53:27', '2026-10-07 21:53:29'),
    ('W2_seg_capture',       '2026-10-10 00:27:59', '2026-10-11 00:28:02'),
    ('W3_fwlog_app_interaction', '2026-10-11 09:00:00', '2026-10-11 14:05:00'),
    ('W4_tapo_capture',      '2026-10-11 16:43:38', '2026-10-11 17:53:44'),
]

def main(src, inv, dst):
    # address -> device name, per capture state
    flat_map, seg_map = {}, {}
    for s in json.load(open(inv)):
        target = flat_map if '_flat/' in s['file'] else seg_map
        for m, ips in s['mac_to_ips'].items():
            if m in IOT_MACS:
                for ip in ips:
                    a = ipaddress.ip_address(ip)
                    if not a.is_link_local: target[str(a)] = IOT_MACS[m]
    wins = [(l, ep(a), ep(b)) for l, a, b in WINDOWS]
    stats = collections.Counter(); scanned = 0
    with open(src, newline='', encoding='utf-8', errors='surrogateescape') as fi, \
         open(dst, 'w', newline='', encoding='utf-8', errors='surrogateescape') as fo:  # keep raw bytes of odd domains
        r = csv.reader(fi); w = csv.writer(fo)
        hdr = next(r); ti, ci = hdr.index('timestamp'), hdr.index('client')
        w.writerow(hdr + ['window', 'time_local', 'device'])
        for row in r:
            scanned += 1
            try: ts = float(row[ti])
            except (ValueError, IndexError): continue
            for label, a, b in wins:
                if a <= ts <= b: break
            else: continue
            client = row[ci]
            if label.startswith('W1'):
                dev = flat_map.get(client)
            else:
                dev = seg_map.get(client)
                if dev is None:
                    try:
                        addr = ipaddress.ip_address(client)
                        if any(addr in n for n in IOT_NETS): dev = 'IoT VLAN (unmapped)'
                    except ValueError:
                        pass
            if dev is None: continue
            t = datetime.datetime.fromtimestamp(ts, TZ).strftime('%Y-%m-%d %H:%M:%S.%f%z')
            w.writerow(row + [label, t, dev]); stats[(label, dev)] += 1
    print(f'scanned {scanned} rows'); print('flat IoT addresses:', sorted(flat_map)); print('seg IoT addresses:', sorted(seg_map))
    for (l, d), n in sorted(stats.items()): print(f'{l:28s} {d:22s} {n}')
    print('kept', sum(stats.values()))

if __name__ == '__main__':
    main(*(sys.argv[1:4] if len(sys.argv) == 4 else
           ('pihole_export.csv', 'derived/pcap_inventory.json', 'derived/pihole_iot_trimmed.csv')))
