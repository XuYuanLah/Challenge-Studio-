#!/usr/bin/env python3
"""Render evidence_manifest.md from SHA256SUMS plus the descriptive table below.

Usage (from the working folder):
  python3 tools/build_manifest.py --sums   # re-hash the evidence set into SHA256SUMS, then render
  python3 tools/build_manifest.py          # render only
Evidence = original artefacts + first-order extracts + the tools. Outputs of the analysis
tools (REGEN below) are regenerable, so they are listed but neither hashed nor given IDs.
Fails if an evidence file in SHA256SUMS isn't described by a row, or a row names a file that isn't hashed.
"""
import os, sys, csv, json, time, hashlib, datetime, subprocess, collections
from zoneinfo import ZoneInfo
csv.field_size_limit(sys.maxsize)
sys.dont_write_bytecode = True                      # importing trim_pihole must not create tools/__pycache__
sys.path.insert(0, 'tools'); from trim_pihole import WINDOWS
TZ = ZoneInfo('Australia/Sydney')
NOT_EVIDENCE = {'SHA256SUMS', 'evidence_manifest.md', 'segmentation_report.md', 'analysis.md',  # reports
                'peer_review_summary.md',                                                      # peer-review handout
                'tools/build_manifest.py',                                                     # renders reports, produces no evidence
                'tools/make_team_bundle.py',
                'tools/check_consistency.py'}                                                  # report tooling: cross-document consistency check                                                   # builds the team bundle; holds real values, never shared
REGEN = ('derived/pcap_inventory.json', 'derived/analysis/', 'derived/zeek/', 'derived/tls/')  # regenerable tool outputs

def retry(fn, *a):
    for _ in range(40):
        try: return fn(*a)
        except BlockingIOError: time.sleep(0.5)       # transient EAGAIN on the mounted home
    return fn(*a)
def sha256(path):
    def run():
        hh = hashlib.sha256()
        with open(path, 'rb') as fh:
            for b in iter(lambda: fh.read(1 << 22), b''): hh.update(b)
        return hh.hexdigest()
    return retry(run)
def evidence_files():
    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d != '__pycache__' and not (root == '.' and d in ('asuswrt-configs', 'team_bundle'))]
        for fn in files:
            q = os.path.relpath(os.path.join(root, fn))
            if q in NOT_EVIDENCE or q.startswith(REGEN) or q.endswith('.tmp'): continue
            yield q
if '--sums' in sys.argv:
    lines = [f'{sha256(q)}  {q}\n' for q in sorted(evidence_files())]
    def write():
        with open('SHA256SUMS.tmp', 'w') as fh: fh.writelines(lines)
        os.replace('SHA256SUMS.tmp', 'SHA256SUMS')
    retry(write); print('hashed', len(lines))
sums = {}
for line in open('SHA256SUMS'):
    h, f = line.rstrip('\n').split('  ', 1); sums[f] = h
inv = {s['file']: s for s in json.load(open('derived/pcap_inventory.json'))}
def lt(ts, fmt='%Y-%m-%d %H:%M:%S'): return datetime.datetime.fromtimestamp(ts, TZ).strftime(fmt)
def human(n, intfmt=True):
    for u in ('B', 'KiB', 'MiB', 'GiB'):
        if n < 1024 or u == 'GiB': return f'{n:.0f} {u}' if (u == 'B' and intfmt) else f'{n:.1f} {u}'
        n /= 1024
def size(f): return human(os.path.getsize(f))
def size_dir(d): return human(sum(os.path.getsize(x) for x in sums if x.startswith(d)), intfmt=False)
def pc(f):
    s = inv[f]; tags = s['vlan_tagged_frames']
    t = f"{s['packets']:,} pkts; {lt(s['first_ts'])} → {lt(s['last_ts'])}"
    return t + (f"; **{sum(tags.values()):,} VLAN {','.join(map(str,tags))}-tagged frames**" if tags else '')
def h(f): return f'`{sums[f][:16]}…`'
def git(*a): return subprocess.run(['git', '-C', 'asuswrt-configs', *a], capture_output=True, text=True, check=True).stdout.strip()

# ---- stable evidence IDs
# E01–E69 were assigned by the first manifest (2026-10-11 15:34) and are cited in analysis.md.
# A file that moves keeps its ID; new evidence is appended. Never reorder, delete or reuse entries.
ID_ORDER = [
 '20261006-215327_flat/wl0.2_20261006-215327.pcap', '20261006-215327_flat/eth7_20261006-215327.pcap',
 '20261006-215327_flat/run.log', '20261006-215327_flat/wl0.2.log', '20261006-215327_flat/eth7.log',          # E01–E05
 '20261010-002759_seg/wl0.2_20261010-002759.pcap', '20261010-002759_seg/eth7_20261010-002759.pcap',
 '20261010-002759_seg/run.log', '20261010-002759_seg/wl0.2.log', '20261010-002759_seg/eth7.log',              # E06–E10
 '20261011-134542_app_interaction/wl0.2_20261011-134542.pcap', '20261011-134542_app_interaction/eth7_20261011-134542.pcap',
 '20261011-134542_app_interaction/run.log', '20261011-134542_app_interaction/wl0.2.log',
 '20261011-134542_app_interaction/eth7.log',                                                                  # E11–E15
 'interaction_timeline.txt', 'firewall_logs/FW_log_3h.log', 'firewall_logs/FW_log_app_interaction.log',
 'firewall_logs/FW_matter-5540-iot-lan-drop.log',                                                             # E16–E19
 'router_states/after_app/fw4_counters_1401.txt', 'router_states/after_app/fw6_counters_1401.txt',
 'router_states/after_app/conntrack_iot_1401.txt',                                                            # E20–E22
 'pihole_export.csv', 'derived/pihole_iot_trimmed.csv',                                                       # E23–E24
 'Settings_RT-BE88U.CFG', 'nvram_flat.txt', 'nvram.txt', 'nvram_seg.txt', 'nvram_tweak.txt',                  # E25–E29
 'asuswrt-configs/ (git repo)', 'derived/pcap_inventory.json', 'derived/analysis/baselines.json',             # E30–E32
 'derived/analysis/flows_app_eth7.csv', 'derived/analysis/flows_app_wl0.2.csv', 'derived/analysis/flows_flat_eth7.csv',
 'derived/analysis/flows_flat_wl0.2.csv', 'derived/analysis/flows_seg_eth7.csv', 'derived/analysis/flows_seg_wl0.2.csv',
 'derived/analysis/summary_app_eth7.json', 'derived/analysis/summary_app_wl0.2.json', 'derived/analysis/summary_flat_eth7.json',
 'derived/analysis/summary_flat_wl0.2.json', 'derived/analysis/summary_seg_eth7.json',
 'derived/analysis/summary_seg_wl0.2.json',                                                                   # E33–E44
 'derived/zeek/app_interaction_eth7/', 'derived/zeek/app_interaction_wl0.2/', 'derived/zeek/flat_eth7/',
 'derived/zeek/flat_wl0.2/', 'derived/zeek/seg_eth7/', 'derived/zeek/seg_wl0.2/',                             # E45–E50
 'derived/tls/clienthello_fingerprints.tsv', 'derived/active/nmap_main_to_iot_tcp.xml',
 'derived/active/nmap_main_to_iot_tcp.nmap', 'derived/active/nmap_main_to_iot_tcp.gnmap',
 'derived/active/nmap_main_to_iot_udp.xml', 'derived/active/nmap_main_to_iot_udp.nmap',
 'derived/active/nmap_main_to_iot_udp.gnmap', 'derived/active/hue_api0_config.json',
 'derived/active/nmap_main_to_iot.started', 'derived/active/nmap_main_to_iot.finished',                      # E51–E60
 'tools/setup_env.sh', 'tools/run_zeek.sh', 'tools/zeek/iot-local.zeek', 'tools/tls_fingerprints.sh',
 'tools/pcap_inventory.py', 'tools/analyze_pcaps.py', 'tools/summarize_flows.py', 'tools/trim_pihole.py',
 'tools/build_manifest.py',                                                                                   # E61–E69
 # added 2026-10-11 evening: tapo capture (state D, at d0c3085) and its logs/state
 '20261011-164338_tapo/wl0.2_20261011-164338.pcap', '20261011-164338_tapo/eth7_20261011-164338.pcap',
 '20261011-164338_tapo/run.log', '20261011-164338_tapo/wl0.2.log', '20261011-164338_tapo/eth7.log',           # E70–E74
 'firewall_logs/FW_tapo_capture.log',                                                                         # E75
 'router_states/before_tapo_capture/fw4_counters_1643.txt', 'router_states/before_tapo_capture/fw6_counters_1643.txt',
 'router_states/before_tapo_capture/conntrack_iot_1643.txt',                                                  # E76–E78
 'router_states/after_tapo_capture/fw4_counters_1751.txt', 'router_states/after_tapo_capture/fw6_counters_1751.txt',
 'router_states/after_tapo_capture/conntrack_iot_1751.txt',                                                   # E79–E81
 'derived/analysis/flows_tapo_eth7.csv', 'derived/analysis/flows_tapo_wl0.2.csv',
 'derived/analysis/summary_tapo_eth7.json', 'derived/analysis/summary_tapo_wl0.2.json',                      # E82–E85
 'derived/zeek/tapo_eth7/', 'derived/zeek/tapo_wl0.2/',                                                       # E86–E87
 # added 2026-10-11 night: active test from the IoT VLAN (MacBook on I0N_IoT)
 'firewall_logs/FW_iot_active.log', 'router_states/iot_lan_before_and_after/', 'iot_active/',                  # E88–E90
 # added 2026-10-12: state E re-test from the IoT VLAN (after reboot and restart_wireless)
 'firewall_logs/FW_hardening.log', 'router_states/hardening_before_and_after/', 'iot_retest/',              # E91–E93
 'router_states/hardening_dns6_ont_retest_2_before_and_after/', 'firewall_logs/FW_hardening_dns6_ont_retest_2.txt',  # E94–E95
]
EID = {p: f'E{i:02d}' for i, p in enumerate(ID_ORDER, 1)}
assert len(EID) == len(ID_ORDER), 'duplicate entry in ID_ORDER'
MOVED = [  # (current path, path in the first manifest, SHA-256 prefix there)
 ('interaction_timeline.txt', 'app_int_timeline.txt', 'cc64e0c797b9fcef'),
 ('firewall_logs/FW_log_3h.log', 'FW_log_3h.log', '03ed44db52a10097'),
 ('firewall_logs/FW_log_app_interaction.log', 'FW_log_app_interaction.log', 'e548b20c515f079d'),
 ('firewall_logs/FW_matter-5540-iot-lan-drop.log', 'matter-5540-iot-lan-drop.log', 'eb7fc30c9075b358'),
 ('router_states/after_app/fw4_counters_1401.txt', 'Router state after app interaction/fw4_counters_1401.txt', '733a29ef5124dad3'),
 ('router_states/after_app/fw6_counters_1401.txt', 'Router state after app interaction/fw6_counters_1401.txt', '8a9fdba993d4c8e4'),
 ('router_states/after_app/conntrack_iot_1401.txt', 'Router state after app interaction/conntrack_iot_1401.txt', 'a65198aebb6eff25'),
]

rows = []  # (id, path, description, window/content, sensitivity, metrics)
def add(f, *r): rows.append((EID[f], f) + r)

# ---- captures
caps = [
 ('20261006-215327_flat', 'State A (flat): 24 h capture, IoT SSID and Hue port, before segmentation', 'Raw. Contains main-LAN broadcast/multicast from every host (hostnames in mDNS, `<PD>` GUA addresses, Thread border-router traffic) and, on `eth7`, VLAN 114 frames (roommate, out of scope). Sanitise: drop VLAN-tagged frames, keep only IoT MACs, remap `<PD>`.', '1, 3, 4, 5 (baselines, before/after)', {'eth7_sens': ' **The `eth7` pcap also carries the Hue Bridge\'s `sso` token in cleartext HTTP; redact it.**'}),
 ('20261010-002759_seg', 'State C/D (segmented): 24 h capture of the IoT network; includes the Matter drop period (10-10 12:12–12:48)', 'Raw. IoT devices, router, HomePod/Apple controller addresses; router `<PD>` GUA appears. Sanitise: remap `<PD>`; MACs may stay (own devices).', '1, 3, 4, 5 (baselines, before/after)', {'eth7_sens': ' **The `eth7` pcap also carries the Hue Bridge\'s `sso` token in cleartext HTTP; redact it.**'}),
 ('20261011-134542_app_interaction', 'App-interaction capture (Apple Home, Eve, Hue, SwitchBot), stopped manually after 7 min', 'Raw. Same content classes as the segmented capture.', '1, 3, 4, 5 (baselines, before/after)', {}),
 ('20261011-164338_tapo', 'State D verification capture (at `d0c3085`: after the `75807a2` NTP and `d0c3085` reflector-filter changes): Tapo firmware update, Hue Bridge and Matter switch power cycles (E16); planned 24 h, stopped manually after 70 min', 'Raw. Same content classes as the segmented capture.', '1, 2, 4, 5 (state D verification, firmware-update scenario)',
  {'wl0.2': '. **This interface stopped at 17:03:11** (`pcap_loop: The interface disappeared`); `eth7` ran to the end',
   'wl0.2.log': '; ends with `pcap_loop: The interface disappeared` (17:03:11)',
   'run.log': '; planned 24 h, stopped at 17:53:44'}),
]
for d, desc, sens, met, notes in caps:
    for iface in ('wl0.2', 'eth7'):
        f = [x for x in sums if x.startswith(d + '/' + iface + '_') and x.endswith('.pcap')][0]
        add(f, f'{desc}; interface `{iface}`{notes.get(iface, "")}', pc(f), sens + notes.get(iface + '_sens', ''), met)
    for lg, what in (('run.log', 'capture run log: settings, tcpdump version, offload disable/re-enable, drop counters (0 dropped)'),
                     ('wl0.2.log', 'tcpdump stderr / statistics for `wl0.2`'), ('eth7.log', 'tcpdump stderr / statistics for `eth7`')):
        add(f'{d}/{lg}', what + notes.get(lg, ''), 'same window as the capture', 'Low', '5 (capture completeness)')

# ---- logs, state, timeline
add('interaction_timeline.txt', 'Action log (ground truth) for the interaction captures. App interaction: start time of each app session (Apple Home 13:45:51, Eve 13:47:55, Hue 13:49:44, SwitchBot 13:51:08); actions were version/update checks (no updates available), the "add new device" page in each app, and toggling several devices in Apple Home. Tapo capture: Tapo firmware update started 16:43:50, update succeeded and plug confirmed reachable 16:45:36, Hue Bridge power cycle 16:46:04, Zemismart (Matter) switch power cycle 17:12:29, annotated: both switches had failed to reconnect after the owner\'s earlier router/wireless restart. Replaces `app_int_timeline.txt`; its first four lines are byte-identical to that file. **Amended 2026-10-12** (owner): only that annotation was added; previous SHA-256 `ba6897938ff86242…`.', '2026-10-11 13:45:51 → 17:12:29 (event times; app sessions: start times only)', 'Low', '1, 4, 5 (ground truth for attribution)')
add('firewall_logs/FW_log_3h.log', 'Router syslog filtered to `IOT_TO_WAN_NEW` (rule `e637e73`) over a ~3 h syslog window: 214 entries. Sources: Hue Bridge `.26` ×119 (77 NTP to public servers, 42 TCP 443), SwitchBot Hub 2 `.15` ×94 (91 of them mDNS to `255.2.0.0`), Tapo smart plug `.23` ×1. All IPv4.', '2026-10-11 10:27:45 → 13:18:56 (first/last entry; file has no trailing newline)', 'Medium: internal addresses, device MACs, public destinations', '2, 5')
add('firewall_logs/FW_log_app_interaction.log', 'Same filter for the app-interaction window: 12 entries (SwitchBot `.15` ×9, all mDNS to `255.2.0.0`; Hue `.26` ×3)', '2026-10-11 13:46:11 → 13:52:33', 'Medium', '1, 2, 5')
add('firewall_logs/FW_matter-5540-iot-lan-drop.log', '`IOT_TO_LAN_DROP` entries for Matter subscription reports (UDP source port 5540) to the Apple controller, before the UDP timeout fix: 60 entries from 4 devices', '2026-10-10 12:12:02 → 12:47:59', 'Medium: internal addresses incl. HomePod ULA', '3, 4, 5 (Matter case study)')
add('firewall_logs/FW_tapo_capture.log', 'Same filter for the tapo capture: 247 entries, no `IOT_TO_LAN_DROP`. Sources: Hue Bridge `.26` ×210 (185 NTP to public servers, 25 TCP 443), SwitchBot Hub 2 `.15` ×27 (23 mDNS to `255.2.0.0`, 3 TCP 8883, 1 NTP), Tapo smart plug `.23` ×10 (7 TCP 443, 3 NTP). All IPv4. Two syslog segments joined by a blank line (line 214): **gap 17:14:30 → 17:31:07** where syslog rotated; the counter delta in E76/E79 puts the loss at ~19 entries.', '2026-10-11 16:43:51 → 17:50:07 (first/last entry; no trailing newline)', 'Medium', '1, 2, 4, 5')
snap = {  # window, note for the counter files, note for the conntrack file
 'after_app': ('2026-10-11 14:01 (from filename)',
   'Snapshot taken **after** the app interaction only (no "before" snapshot for that window), so counters are cumulative since the last firewall restart.',
   'Snapshot taken **after** the app interaction. Matter sessions (UDP 5540): iPhone → `.15`, `.17`, `.26`; HomePod → `.15`.'),
 'before_tapo_capture': ('2026-10-11 16:43 (from filename)',
   'Snapshot taken just **before** the tapo capture. The firewall had been restarted shortly before (`IOT_TO_WAN_NEW` LOG counter at 60), so before/after deltas cover the capture window.',
   'Snapshot taken just **before** the tapo capture. **No Matter (UDP 5540) session for any IoT device**; 45 of the entries are the Hue Bridge\'s.'),
 'after_tapo_capture': ('2026-10-11 17:51 (from filename)',
   'Snapshot taken **after** the tapo capture; `IOT_TO_WAN_NEW` LOG counter 326 (+266 since 16:43).',
   'Snapshot taken **after** the tapo capture. HomePod Matter sessions (UDP 5540) to all five Matter devices: `.15`, `.17`, `.20`, `.23`, `.26`.')}
for s, tag in (('after_app', '1401'), ('before_tapo_capture', '1643'), ('after_tapo_capture', '1751')):
    win, note_fw, note_ct = snap[s]
    for kind, what in (('fw4_counters', 'IPv4 FORWARD rule counters (`iptables -vnL FORWARD`)'),
                       ('fw6_counters', 'IPv6 FORWARD rule counters (`ip6tables -vnL FORWARD`); the IPv6 `IOT_TO_WAN_NEW` LOG rule shows 0 packets'),
                       ('conntrack_iot', 'Connection-tracking entries involving the IoT network (`/proc/net/nf_conntrack`)')):
        f = f'router_states/{s}/{kind}_{tag}.txt'
        if kind == 'conntrack_iot': what = what[:-1] + f', {sum(1 for l in open(f) if l.strip())} entries)'
        add(f, f'{what}. {note_ct if kind == "conntrack_iot" else note_fw}', win, 'High: contains the WAN IPv4 address' if kind == 'conntrack_iot' else 'Medium', '2, 3, 4, 5')

add('router_states/iot_lan_before_and_after/', 'IPv4/IPv6 FORWARD (`fw4`/`fw6`) and INPUT (`in4`/`in6`) rule counters (`iptables`/`ip6tables -vnL … --line-numbers`), taken just before (`_2157`) and after (`_2212`) the active test from the IoT VLAN (8 files). Deltas: IoT → main-LAN DROP +58,771 (v4) / +598 (v6); `IOT_TO_WAN_NEW` +466 / +152; INPUT `tcp dpt:22` ACCEPT (any interface) +24.', '2026-10-11 21:57 and 22:12 (from filenames)', 'Medium', '3, 5')
add('firewall_logs/FW_iot_active.log', 'Router syslog filtered to `IOT_TO_WAN_NEW` / `IOT_TO_LAN_DROP`, covering the active test: 1,111 entries (898 WAN, 213 LAN drop), 767 of them inside the test window. Test host (`192.168.107.8`, private MAC `b2:1c:d7:ba:85:9d`): 411 WAN incl. the DNS-bypass probes to `1.1.1.1` UDP 53 and TCP 853, 197 LAN drops. Also contains two of the owner\'s other Apple devices, which joined via a Keychain-synced passphrase (randomised MACs `1e:b2:de:92:90:28` at `.18`, `c2:c0:9a:ec:14:36` at `.19`; not analysed) and the first 20 entries stamped `Jan 1` (router clock before NTP sync after a reboot).', '2026-10-11 21:52:11 → 22:12:05 (plus pre-sync boot entries)', 'Medium–High: internal addresses, device MACs, one `<PD>` address (redact)', '1, 2, 3, 5')

add('router_states/hardening_before_and_after/', 'Router state for the **state E re-test**, taken just before (`hardening_before/*_2355`, state after boot) and after (`hardening_after/*_0002`) the test, 18 files each: IPv4/IPv6 FORWARD and INPUT counters (`fw4`/`fw6`/`in4`/`in6`), `IOT_INPUT` v4/v6, firmware sub-chains `SDN_FI`, `PTCSRVWAN`, `PTCSRVLAN` (v4/v6; the v6 `PTCSRV*` chains don\'t exist), nat PREROUTING v4/v6, `brctl show` + `stp_state`, `ip -6 addr`, the `ntpd_vlan` cron job, IoT conntrack. A `restart_wireless` ran between the two (bridge ifindexes change). Deltas: `IOT_INPUT` v4 DROP 43 → ~131k; v4 TCP/UDP 53 DNAT +19/+3, v6 UDP +1, v6 TCP 0; FORWARD TCP 853 DROP +3.', '2026-10-11 23:55:10 and 2026-10-12 00:02:36 (file times)', 'High: `conntrack_iot_*` and `nat4_prerouting_*` contain the WAN IPv4; `ipv6_addr_*` contains `<PD>` and `<WAN-RA>` addresses (redact)', '3, 4, 5')
add('firewall_logs/FW_hardening.log', 'Router syslog filtered to `IOT_TO_(ROUTER_DROP|LAN_DROP|WAN_NEW)` and `IOT_DNS_REDIRECT` during the state E re-test: 447 entries (291 WAN, 97 router drop, 53 LAN drop, 6 DNS redirect). Router-drop and redirect entries come only from the test host (`b2:1c:d7:ba:85:9d`); also present: the owner\'s Apple devices `.18` and `.13` (`ac:bc:b5:d3:d1:dd`, not analysed) and Hue public NTP. Starts at 23:58:01, so r1 (23:56) isn\'t in it.', '2026-10-11 23:58:01 → 2026-10-12 00:02:54', 'Medium–High: internal addresses, device MACs; 48 entries carry the router\'s WAN-side IPv6 address (`<WAN-RA>`, zero-padded form; redact)', '1, 3, 5')

add('router_states/hardening_dns6_ont_retest_2_before_and_after/', 'Router counters just before and after the second follow-up (2 files): IPv4 FORWARD rows for DoT (853) and the ONT rules (`br52`/`br56` DROP, `br0` ACCEPT to `192.168.255.0/30`), IPv6 nat PREROUTING (DNS redirect), and the head of IPv6 FORWARD. Deltas: `br52` ONT DROP 23 → 49, `br0` ONT ACCEPT 26 → 55, v6 TCP 53 DNAT 2 → 4, v6 IoT WAN LOG 30 → 59. The v6 TCP 853 DROP row isn\'t included.', '2026-10-12 ~01:00 (around the probes at 01:00:09; file times are upload times)', 'Low: internal addresses only', '3, 5')

add('firewall_logs/FW_hardening_dns6_ont_retest_2.txt', 'Router syslog filtered to the IoT prefixes around the second follow-up: 34 entries, all from the test host (`b2:1c:d7:ba:85:9d`). ICMP to the ONT (00:48:31); an earlier DNS/DoT run (00:58:24: 2 v6 TCP `IOT_DNS_REDIRECT`, 8 SYNs to `[2606:4700:4700::1111]:853`); the saved run: 10 SYNs to `192.168.255.1:80` (00:58:54–00:59:29), 2 v6 TCP `IOT_DNS_REDIRECT` (01:00:09), 9 SYNs to Cloudflare 853 (to 01:01:16). No IoT device appears.', '2026-10-12 00:48:31 → 01:01:16', 'Low–Medium: test-host addresses and MAC', '3, 5')
# ---- DNS
PIHOLE_ROWS = 26_019_795  # "scanned" count printed by tools/trim_pihole.py on this export (equals last id − first id + 1)
with open('pihole_export.csv', 'rb') as fh:
    fh.readline(); ph_first = float(fh.readline().split(b',')[1])
    fh.seek(-4096, 2); ph_last = float(fh.read().splitlines()[-1].split(b',')[1])
trim = collections.Counter(); ntrim = 0
with open('derived/pihole_iot_trimmed.csv', newline='', encoding='utf-8', errors='surrogateescape') as fh:
    for r in csv.DictReader(fh): trim[(r['window'], r['device'])] += 1; ntrim += 1
add('pihole_export.csv', f'Full Pi-hole FTL `queries` table export (`sqlite3 -header -csv pihole-FTL.db "SELECT * FROM queries;"`): {PIHOLE_ROWS:,} rows, **all networks**. VLAN 114 is unfiltered, VLAN 107 and the main LAN are filtered (blocking active). Re-exported after the tapo capture; supersedes the first export (ended 13:54:28).', f'{lt(ph_first)} → {lt(ph_last)}', '**Restricted / never share:** full browsing history of every household client incl. the roommate. Kept only as the source of the trimmed extract.', '5 (source)')
add('derived/pihole_iot_trimmed.csv', f'Trimmed Pi-hole extract: **IoT clients only, experiment windows only**, {ntrim:,} rows. Original columns kept, plus `window`, `time_local`, `device`. Produced by `tools/trim_pihole.py` (see "Pi-hole extract" below).', f'W1 flat capture, W2 segmented capture, W3 2026-10-11 09:00 → 14:05, W4 tapo capture (export ends {lt(ph_last, "%H:%M:%S")})', 'Low–Medium: IoT client addresses and IoT cloud domains only', '2, 5 (domains behind WAN connections)')

# ---- config / state records
for f, what, win, sens in (
 ('Settings_RT-BE88U.CFG', 'Web-UI settings backup: the only nvram record of state A (flat). Trivially reversible encoding (`HDR2`).', 'state A', '**Secret:** router admin credentials, Wi-Fi passphrases. Never share.'),
 ('nvram_flat.txt', 'Decoded `.CFG` (5468 entries)', 'state A', '**Secret** (as above)'),
 ('nvram.txt', 'nvram dump, state B (VLAN 107 created in GUI)', 'state B', '**Secret:** Wi-Fi passphrases (`*_wpa_psk`, `apg*_security`), public addresses'),
 ('nvram_seg.txt', 'nvram dump, state C (segmented)', 'state C', '**Secret** (as above)'),
 ('nvram_tweak.txt', 'nvram dump, state D (UDP timeout 1800 s, `ct_expect_max` 8192). Every later change (the rest of D, and E) is scripts-only, so this is also the current nvram.', 'state D (and E)', '**Secret** (as above)')):
    add(f, what, win, sens, '5 (lab configuration)')
HEAD, SUBJ = git('rev-parse', 'HEAD'), git('log', '-1', '--format=%s')
NTRACKED, DIRTY = len(git('ls-files').splitlines()), bool(git('status', '--porcelain'))
add('asuswrt-configs/ (git repo)', f'Router scripts and configs. Content-addressed by git: **HEAD `{HEAD[:12]}`** ("{SUBJ}"), {NTRACKED} tracked files, working tree {"**dirty**" if DIRTY else "clean"}.', f'commits `c3684e6` → `{HEAD[:7]}`', 'Local only, never pushed. **Contains a secret:** `scripts/ddns-start` holds a plaintext DDNS credential. Redact it only in the copy that goes into the shared bundle.', '5 (codebase, rules)')

# ---- active tests (live observations, not regenerable) and tools
for f, what, sens in (('derived/active/nmap_main_to_iot_tcp.xml', 'Active test, main LAN → IoT, TCP top-1000 + version detection (nmap 7.95, 2026-10-11 15:29–15:31)', 'Low: IoT addresses/services'),
                      ('derived/active/nmap_main_to_iot_tcp.nmap', 'Same, human-readable output', 'Low'),
                      ('derived/active/nmap_main_to_iot_tcp.gnmap', 'Same, greppable output', 'Low'),
                      ('derived/active/nmap_main_to_iot_udp.xml', 'Active test, main LAN → IoT, selected UDP ports', 'Low'),
                      ('derived/active/nmap_main_to_iot_udp.nmap', 'Same, human-readable output', 'Low'),
                      ('derived/active/nmap_main_to_iot_udp.gnmap', 'Same, greppable output', 'Low'),
                      ('derived/active/hue_api0_config.json', 'Unauthenticated `GET /api/0/config` response from the Hue Bridge (model, firmware, API version, bridge ID, MAC)', 'Low: own device identifiers'),
                      ('derived/active/nmap_main_to_iot.started', 'Active test start timestamp (UTC)', 'Low'),
                      ('derived/active/nmap_main_to_iot.finished', 'Active test end timestamp (UTC)', 'Low')):
    add(f, what, '2026-10-11', sens, '3, 5')
add('iot_active/', 'Active test **from the IoT VLAN**: nmap 7.99 from a MacBook on `I0N_IoT` (`wifi.txt`: `192.168.107.8`, `fd00:d:e:6b:4b0:2628:1856:4090`, private MAC). `1_lan_ping` (ICMP sweep of the main LAN), `2_lan_tcp` (main LAN /24, TCP top-100), `3_lan_udp` (key hosts, selected UDP), `4_router_tcp`/`_udp` (router at `192.168.107.1` and `192.168.0.1`, all TCP ports + versions, selected UDP), `5_v6_tcp` (router and main-LAN ULAs), `6_rm_gw` (router address `192.168.114.1` only), each as `.nmap`/`.gnmap`/`.xml`; `context.txt` (interface, routes, resolvers), `iot2lan.started`/`.finished` (UTC), `terminal_history.txt` (full session incl. `sntp`, `ping6`, DNS-bypass probes).', '2026-10-11 21:57:08 → 22:11:48', 'Medium: test-host MAC/addresses, internal service inventory, laptop host name in the shell prompt', '1, 3, 5')
add('iot_retest/', '**State E re-test from the IoT VLAN** (same MacBook as E90): `r1_router_tcp` (router TCP select ports on `192.168.107.1`, `192.168.0.1`, `192.168.114.1`), `r2_router_alltcp` (all TCP on `192.168.107.1`), `r3_router_udp` (selected UDP), `r4_v6` (`fd00:d:e:6b::1`), each as `.nmap`/`.gnmap`/`.xml` (nmap 7.99, commands in the XML `args`); `retest.started`/`.finished` (UTC); `terminal_history.txt` (outputs only: nmap, `dig` redirect probes and an `example.com` control, `nc` to `1.1.1.1:853` and `192.168.0.1:22`, `sntp`, `ping`); `router_term_out.txt` (router side: STP before and after `service restart_wireless`, IoT ULA, INPUT/`IOT_INPUT`/nat PREROUTING/FORWARD dump right after the restart); `hardening_dns6_retest.txt` (IPv6 DNS follow-up: `nslookup diag.meethue.com` against Pi-hole, Cloudflare v6, the router\'s main-LAN ULA and a nonexistent ULA; all answered with Pi-hole\'s block answers; UDP only, no counters); `hardening_dns6_ont_test_2.txt` (second follow-up, 2026-10-12 01:00:09: `nc 192.168.255.1 80` and `nc -6` to Cloudflare 853 time out; `dig +tcp` over IPv6 to Cloudflare and the router returns Pi-hole\'s block answer with EDE 15).', '2026-10-11 23:55 → 2026-10-12 00:02:30; follow-ups 00:28 (file time) and 01:00:09', 'Medium: test-host addresses, router service inventory; laptop host name in the shell prompt (`hardening_dns6_retest.txt`)', '1, 3, 4, 5')
for f, what in (('tools/setup_env.sh', 'Re-installs tshark, Zeek 8.0 (OBS repo), nmap, jq after a terminal reset'),
                ('tools/run_zeek.sh', 'Runs Zeek over every capture'),
                ('tools/zeek/iot-local.zeek', 'Zeek site policy (JSON, MAC logging, cert validation, known hosts/services)'),
                ('tools/tls_fingerprints.sh', 'tshark JA4/JA3/SNI extraction'),
                ('tools/pcap_inventory.py', 'Dependency-free pcap summariser (classic pcap, Ethernet, 802.1Q aware)'),
                ('tools/analyze_pcaps.py', 'Per-device flow / DNS / TLS-SNI / mDNS analysis of the captures (VLAN-tagged frames skipped)'),
                ('tools/summarize_flows.py', 'Aggregates flows and summaries into per-device baselines'),
                ('tools/trim_pihole.py', 'Pi-hole extract filter (windows × IoT addresses)')):
    add(f, what, '—', 'Low', '5 (reproducibility)')

# ---- coverage check: every hashed file is described, every described file is hashed
covered = set()
for _, f, *_ in rows:
    if f.endswith('(git repo)'): continue
    if f.endswith('/'): covered |= {x for x in sums if x.startswith(f)}
    else: assert f in sums, f'row without hash: {f}'; covered.add(f)
assert covered == set(sums), f'hashed but not described: {sorted(set(sums) - covered)}'
for new, old, pre in MOVED: assert new in sums, new
RETIRED = [EID[q] for q in ID_ORDER if EID[q] not in {r[0] for r in rows}]
def ranges(ids):
    n = sorted(int(x[1:]) for x in ids); out, i = [], 0
    while i < len(n):
        j = i
        while j + 1 < len(n) and n[j + 1] == n[j] + 1: j += 1
        out.append(f'E{n[i]:02d}' + (f'–E{n[j]:02d}' if j > i else '')); i = j + 1
    return ', '.join(out)

out = []
w = out.append
w('# Evidence Manifest: IoT Segmentation Project\n')
w(f'Working folder: `IoT Segmentation/` · Generated {datetime.datetime.now(TZ).strftime("%Y-%m-%d %H:%M %Z")} · Status: **raw evidence and first-order extracts; every capture analysed** (`analysis.md`, the tapo capture in §13). A sanitised bundle will be produced after analysis.\n')
w('**Verify integrity:** `sha256sum -c SHA256SUMS` from the working folder. `SHA256SUMS` is the authoritative hash list. It covers every evidence file below: original artefacts, first-order extracts (the trimmed Pi-hole log, the active-test outputs) and the tools; `python3 tools/build_manifest.py --sums` rebuilds it. The git repo is identified by its commit hash instead. Left out on purpose: report documents (`segmentation_report.md`, `analysis.md`, `peer_review_summary.md`, this manifest and its generator `tools/build_manifest.py`), the team-bundle builder `tools/make_team_bundle.py` and the consistency checker `tools/check_consistency.py`, and the outputs of the analysis tools, which are regenerable (see "Regenerable outputs"). The tables show hash prefixes; the appendix lists full hashes.\n')
w('**Evidence IDs are stable.** E01–E69 come from the first manifest (2026-10-11 15:34); `analysis.md` cites some of them. Files moved since then keep their ID (see "Moved files" below); evidence added later gets the next free ID (E70 onwards). Rows are grouped by type, so IDs aren\'t in numerical order. Retired IDs (regenerable outputs and the manifest generator, not cited in `analysis.md`; never reused): ' + ranges(RETIRED) + '.\n')
w('**Analysis environment:** a NAT\'d terminal on the **main LAN**; it is never on the IoT VLAN. Its only traffic into the IoT VLAN was the active test (E52–E60, 2026-10-11 15:29–15:31), outside every capture window, so it doesn\'t appear in the IoT captures or firewall logs. A separate **test host on the IoT VLAN** (a MacBook, E90) ran the IoT → main-LAN/router tests on 2026-10-11 21:57–22:12. No capture was running then; its traffic is in E88 and E89. Its DNS queries come from a main-LAN client address and are excluded from the Pi-hole extract by the client filter.\n')
w('**Time zone:** all times are AEDT (UTC+11, `Australia/Sydney`) unless stated. Router syslog and `run.log` use local time; pcap timestamps are stored in UTC epoch.\n')
w('## Artefacts\n')
w('| ID | File | Size | SHA-256 (prefix) | What it is | Window / content | Sensitivity / sanitisation | Supports metric |')
w('|---|---|---|---|---|---|---|---|')
for i, f, d, win, s, m in rows:
    if f.endswith('(git repo)'): sz, hh = '—', f'`{HEAD[:12]}` (git HEAD)'
    elif f.endswith('/'): sz, hh = size_dir(f), 'see appendix'
    else: sz, hh = size(f), h(f)
    w(f'| {i} | `{f}` | {sz} | {hh} | {d} | {win} | {s} | {m} |')
w('\nMetric numbers refer to the Learning Contract evaluation metrics: 1 scenarios executed, 2 suspicious-behaviour detections, 3 inter-segment reachability blocked, 4 device functions preserved, 5 reproducible evidence.\n')

w('### Moved files (since the first manifest)\n')
w('| ID | Current path | Path in the first manifest | Content |')
w('|---|---|---|---|')
for new, old, pre in MOVED:
    same = sums[new].startswith(pre)
    w(f'| {EID[new]} | `{new}` | `{old}` | ' + ('unchanged (same SHA-256)' if same else f'extended (old SHA-256 `{pre}…`)') + ' |')
w('')

w('## Regenerable outputs (not hashed, no IDs)\n')
w('Produced from the hashed captures by the hashed tools; rebuild them instead of verifying them. They change whenever a tool is improved or a capture is added, which is why they sit outside `SHA256SUMS`. The analysis cites them by path.\n')
w('| Output | Command (from the working folder) | Former IDs | Sensitivity |')
w('|---|---|---|---|')
for o, c, ids, sens in (
 ('`derived/pcap_inventory.json`: per-pcap packet counts, first/last timestamps, VLAN-tagged frames, source MAC → IP map. Also an input to `trim_pihole.py` and to this manifest.', '`python3 tools/pcap_inventory.py derived/pcap_inventory.json 2026*/*.pcap`', 'E31', 'Medium: every MAC/address seen, incl. main LAN and VLAN 114 (flat capture)'),
 ('`derived/analysis/`: `flows_<cap>_<iface>.csv` (per-device flow tables, Splunk-ingestible), `summary_<cap>_<iface>.json` (DNS, TLS SNI, mDNS exposure, odd destinations, hourly cloud volume), `baselines.json`', '`python3 tools/analyze_pcaps.py && python3 tools/summarize_flows.py`', 'E32–E44, E82–E85', 'Medium: main-LAN hosts and `<PD>` GUA entries (class `mainlan_gua`); remap before sharing'),
 ('`derived/zeek/<cap>_<iface>/`: Zeek 8.0 JSON logs (BPF `not vlan`)', '`sh tools/run_zeek.sh` (Zeek from `tools/setup_env.sh`)', 'E45–E50, E86–E87', '**High:** `flat_eth7`/`seg_eth7` `http.log` hold the Hue `sso` token; flat-state logs hold main-LAN host names'),
 ('`derived/tls/clienthello_fingerprints.tsv`: JA4/JA3 + SNI of every TLS ClientHello', '`sh tools/tls_fingerprints.sh`', 'E51', 'Low–Medium: device addresses, cloud endpoints')):
    w(f'| {o} | {c} | {ids} | {sens} |')
w('\nOrder matters only for the inventory: run `pcap_inventory.py` before `trim_pihole.py`.\n')

w('## Capture set overview\n')
def pk(d, iface): return f"{[s for k, s in inv.items() if k.startswith(d + '/' + iface + '_')][0]['packets']:,}"
w('| Capture | State | Interfaces | Duration | Packets (wl0.2 / eth7) | Kernel drops | Offload |')
w('|---|---|---|---|---|---|---|')
for d, state, ifs, dur in (
 ('20261006-215327_flat', 'A: flat (IoT on `br0`)', '`wl0.2`, `eth7` (trunk: untagged `br0` + tagged 107/114)', '24 h'),
 ('20261010-002759_seg', 'C → D (UDP timeout fix applied during the run, ~12:35 on 10-10)', '`wl0.2`, `eth7` (access port, VLAN 107)', '24 h'),
 ('20261011-134542_app_interaction', 'D + `IOT_TO_WAN_NEW` logging', '`wl0.2`, `eth7`', '7 min 4 s (stopped manually)'),
 ('20261011-164338_tapo', 'D at `d0c3085`: IoT NTP and reflector filter (`75807a2`, `d0c3085`)', '`wl0.2`, `eth7`', '`eth7` 70 min (stopped manually); **`wl0.2` 19 min 33 s** (interface disappeared at 17:03:11)')):
    w(f'| `{d}` | {state} | {ifs} | {dur} | {pk(d, "wl0.2")} / {pk(d, "eth7")} | 0 / 0 | fc + runner disabled for the run |')
w('')
w('## IoT device address map (from the captures)\n')
w('| MAC | Device (working name) | State A address (main LAN) | State C–E IPv4 | State C–E IPv6 (SLAAC) | Port |')
w('|---|---|---|---|---|---|')
w('| `ec:b5:fa:bc:52:10` | Hue Bridge (Philips Lighting / Signify OUI) | `192.168.0.50` | `192.168.107.26` | `fd00:d:e:6b:eeb5:faff:febc:5210` | `eth7` |')
w('| `0c:4e:a0:30:22:54` | SwitchBot Hub 2 | `192.168.0.48` | `192.168.107.15` | — (no IPv6 seen) | `wl0.2` |')
w('| `8c:87:d0:09:0d:6b` | Matter switch (likely Zemismart; vendor unverified) | `192.168.0.21` | `192.168.107.17` | `fd00:d:e:6b:8e87:d0ff:fe09:d6b` | `wl0.2` |')
w('| `8c:87:d0:09:0d:6e` | Matter switch (likely Zemismart; vendor unverified) | `192.168.0.19` | `192.168.107.20` | `fd00:d:e:6b:8e87:d0ff:fe09:d6e` | `wl0.2` |')
w('| `7c:f1:7e:10:03:a0` | Tapo smart plug | `192.168.0.207` | `192.168.107.23` | `fd00:d:e:6b:7ef1:7eff:fe10:3a0` | `wl0.2` |')
w('\nApple Matter controllers seen talking to IoT devices (main LAN): the **HomePod** `192.168.0.22` / `fd00:d:e:f:183e:4f13:4044:5684` (`ac:bc:b5:…`, home hub, the destination in the Matter drop log), and the **iPhone** `192.168.0.221` (`94:89:78:…`), which held Matter sessions (UDP 5540) to the Matter switch `.17`, the Hue Bridge `.26` and the SwitchBot hub `.15` in the post-interaction conntrack snapshot. The phone acts as a controller directly while the Home app is in use.\n')
w('Transient addresses in the tapo capture (also in `derived/pcap_inventory.json`): the **Tapo plug** announces `192.168.1.80` by gratuitous ARP before taking its DHCP lease (16:45:15 after the firmware-update reboot, 17:10:45 on a Wi-Fi rejoin); no IP traffic uses it. The **Hue Bridge** used the IPv4 link-local address `169.254.11.47` for ~18 s after its power cycle (16:46:37 → DHCP ACK 16:46:55).\n')

w('## Pi-hole extract (`derived/pihole_iot_trimmed.csv`)\n')
w('**Command:** `python3 tools/trim_pihole.py` (defaults: `pihole_export.csv`, `derived/pcap_inventory.json` → `derived/pihole_iot_trimmed.csv`). Odd bytes in domain names are preserved (`surrogateescape`). Re-running it on the current export reproduces the file byte for byte.\n')
w('**A row is kept only if both conditions hold:**\n')
w('| Window | From | To | Client must be |')
w('|---|---|---|---|')
for label, a, b in WINDOWS:
    rule = ('one of the IoT devices\' **main-LAN** addresses during state A (mapped by MAC from the flat capture)' if label.startswith('W1')
            else 'in `192.168.107.0/27` or `fd00:d:e:6b::/64`, or a mapped IoT address from the later captures')
    w(f'| {label} | {a} | {b} | {rule} |')
w(f'\nEverything else is dropped: all main-LAN hosts (homelab, phones, computers), all of VLAN 114 (roommate), and all other periods. {PIHOLE_ROWS:,} rows → **{ntrim:,} rows**.\n')
DEVCOLS = (('Hue Bridge',), ('SwitchBot Hub 2',), ('Tapo smart plug',), ('Matter switch 0d6b', 'Matter switch 0d6e'))
extra = sorted({d for (_, d) in trim} - {x for c in DEVCOLS for x in c})
w('| Window | Hue Bridge | SwitchBot Hub 2 | Tapo smart plug | Matter switches |' + ''.join(f' {e} |' for e in extra) + ' Notes |')
w('|---|---|---|---|---|' + '---|' * len(extra) + '---|')
WNOTE = {'W3': 'complete now; the first export ended at 13:54:28 (Hue 345 then)',
         'W4': f'the export ends at {lt(ph_last, "%H:%M:%S")}, {int((datetime.datetime.strptime(WINDOWS[3][2], "%Y-%m-%d %H:%M:%S").replace(tzinfo=TZ).timestamp() - ph_last) // 60)} min before the window ends'}
for label, _, _ in WINDOWS:
    cells = [sum(trim[(label, x)] for x in c) for c in DEVCOLS] + [trim[(label, e)] for e in extra]
    w(f'| {label} | ' + ' | '.join(f'{c:,}' for c in cells) + f' | {WNOTE.get(label[:2], "")} |')
w('\n**Column codes** (Pi-hole FTL schema): `type` 1 = A, 2 = AAAA. `status` 1 = blocked (gravity), 2 = forwarded, 3 = answered from cache, 17 = answered from stale cache; 0 = unknown. `reply_type`, `dnssec`, `list_id` and `ede` are left as exported.\n')
w('**Caveats:** in W1 the IoT devices used dynamic main-LAN DHCP addresses. A reused address within the 24 h window would be misattributed. The 24 h lease time makes this unlikely, but it hasn\'t been ruled out. The later-window address map also contains the Tapo\'s transient `192.168.1.80`; no Pi-hole row has that client.\n')

w('## Observations noted while building the manifest (to verify in analysis, not conclusions)\n')
w('### From the first manifest (2026-10-11 15:34; since examined in `analysis.md`)\n')
for o in (
 '**SwitchBot Hub 2 sends mDNS (UDP 5353) to `255.2.0.0` through the WAN:** 91 of its 94 `IOT_TO_WAN_NEW` entries in `FW_log_3h.log` and all 9 in the app window. That isn\'t a valid multicast or broadcast destination. It looks like a firmware bug, and it uses up the log rate limit. Candidate anomaly / scenario.',
 '**No IoT IPv6 traffic to the WAN:** the IPv6 `IOT_TO_WAN_NEW` rule counter is 0, and every logged WAN connection is IPv4. NAT6 appears unused by these devices.',
 '**Matter switches made no DNS queries in any window:** consistent with local-only (Matter) operation with no cloud dependency.',
 '**Hue Bridge blocked (status 1) queries rose from 58 (W1) to 1,066 (W2).** Its total query count roughly doubled while forwarded/cached counts stayed similar. Needs a per-domain look; possibly retries of a blocked domain.',
 '**The app-interaction capture ran for only 7 min** and the timeline has start times only for the app sessions. Eve traffic isn\'t expected on the IoT network at all (Eve Room uses Thread via the HomePod on the main LAN, and the Eve app runs on the phone).',
 '**Router state for the app-interaction window was captured after the interaction only (14:01),** so rule counters can\'t be diffed for that window. The tapo capture has before/after snapshots (below).',
 '**The iPhone (`.221`) is a direct Matter controller during app use,** in addition to the HomePod hub. Its sessions are main LAN → IoT, which the policy allows. Its Home-app cloud traffic stays on the main LAN and isn\'t in the IoT captures; same for the Eve, Hue and SwitchBot apps.',
 '**Thread-related traffic in the flat capture** (reported during initial analysis): consistent with a Thread border router\'s traffic flooding `br0` while the IoT SSID was bridged into it. For example, `6c:a6:04:b5:39:28` (`192.168.0.15`) uses the separate ULA `fd05:37e5:64c4::1`.',
 '**The flat `eth7` capture contains 89,336 VLAN 114-tagged frames** (roommate network): `eth7` was a trunk in state A. Out of scope; must be removed in the sanitised bundle.'):
    w(f'- {o}')
w('\n### From the tapo capture (2026-10-11 16:43–17:53; since examined in `analysis.md` §13)\n')
for o in (
 '**`wl0.2` stopped at 17:03:11, and Wi-Fi clients rejoined twice.** tcpdump reported `pcap_loop: The interface disappeared`; the last `wl0.2` frames are Broadcom driver event frames (EtherType `0x886c`) from the router. `eth7` still sees the VLAN\'s flooded broadcast/multicast: the SwitchBot hub and the Tapo plug rejoin (DHCP DISCOVER/REQUEST, ARP probes) at **17:03:26** and again at **17:10:45–17:10:51**, consistent with two wireless restarts. Unicast Wi-Fi traffic after 17:03:11 isn\'t captured.',
 '**Matter switches absent until 17:10:54.** Neither switch sent a frame on either interface from the capture start. Both rejoin together at 17:10:54–17:11:02 (DHCP), with the second Wi-Fi rejoin and ~1.5 min before the logged switch power cycle (17:12:29). At 14:01 the iPhone still had a session to `.17` (E22). Explained afterwards: the owner had restarted wireless before the capture, and there was no recurrence after a power cycle (`analysis.md` §13.7).',
 '**No Matter sessions at 16:43.** The before snapshot (E78) holds no UDP 5540 session for any IoT device, although the Hue Bridge, SwitchBot hub and Tapo plug were online; the after snapshot (E81) has HomePod sessions to all five Matter devices. The firewall had been reloaded minutes before 16:43 (only ~11k packets through FORWARD in E76). Possible explanation, to confirm: connection tracking was cleared or had expired, and the HomePod re-established the sessions later. The `br52 → br0` DROP rule stayed at 0 packets in both snapshots, so no IoT → main-LAN packet was dropped in the window.',
 '**Router state is bracketed:** before (16:43, E76–E78) and after (17:51, E79–E81). The IPv4 `IOT_TO_WAN_NEW` LOG counter rose 60 → 326 (+266), against 247 entries in E75, so ~19 entries fell into the 17:14:30 → 17:31:07 syslog gap (~1.2/min; the log runs at ~1.5–2/min either side of it). A firewall restart inside the window would need 100+ lost entries (≥6/min), so the delta is valid. The IPv6 LOG counter and both `IOT_TO_LAN_DROP` LOG counters stayed at 0.',
 '**Hue public NTP volume is up:** 185 of the Hue\'s 210 `IOT_TO_WAN_NEW` entries (16:43–17:50; ~50 min of log excluding the gap) are NTP to public servers (Google, Cloudflare, Apple, Alibaba), against 77 in ~3 h of `FW_log_3h.log`. Possible contributors: boot-time sync after the 16:46:04 power cycle, and fallback because its NTP requests to `192.168.107.1` get ICMP port unreachable (`segmentation_report.md` §1.9).',
 '**Tapo firmware update** (16:43:50 → 16:45:36): 13 Pi-hole queries in W4 (1–6 in each earlier window) and 10 `IOT_TO_WAN_NEW` entries in three clusters: update and reboot (16:44–16:45), then each Wi-Fi rejoin (17:03, 17:10). Domains, JA4 and download volume are in `analysis.md` §13.2.',
 '**SwitchBot `255.2.0.0` leak persists** after the reflector filter: 23 of its 27 `IOT_TO_WAN_NEW` entries.'):
    w(f'- {o}')
w('\n## Sanitised bundle plan (after analysis)\n')
for o in (
 '**Never include:** `Settings_RT-BE88U.CFG`, `nvram_flat.txt`, raw nvram dumps, `pihole_export.csv`, raw conntrack (`router_states/*/conntrack_iot_*.txt`, which contain the WAN IPv4).',
 '**pcaps:** drop VLAN-tagged frames (`not vlan`). Keep only frames to/from IoT MACs and the router (removes main-LAN hosts\' multicast and hostnames from the flat capture). Remap `<PD>` and the WAN IPv4 (`tcprewrite`). Truncate main-LAN controller flows to headers if needed. The flat and segmented `eth7` pcaps contain the Hue `sso` token in cleartext HTTP (port 80): drop or truncate those payloads.',
 '**nvram:** share as redacted diffs (`segmentation_report.md` section 2) or with `*_psk`, `*_security`, `http_passwd`, `acc_list`, `wan0_ipaddr` and prefix keys removed.',
 '**Logs (`firewall_logs/`) and rule counters:** keep as-is apart from replacing the WAN IPv4, `<PD>` and `<WAN-RA>` if present (also in zero-padded IPv6 form, e.g. in `FW_hardening.log`). In `router_states/hardening_before_and_after/`, `nat4_prerouting_*` carry the WAN IPv4 and `ipv6_addr_*` carry `<PD>`/`<WAN-RA>`. Device MACs may stay (own devices).',
 '**Zeek logs:** redact the Hue `sso` token in `http.log`; drop main-LAN host names from the flat-state logs.',
 '**Repo:** it stays local. If scripts go into the bundle, include `firewall-start`, `dnsmasq-sdn.postconf`, `avahi-daemon.postconf`, `iot-capture.sh` and the VLAN helpers, and leave `ddns-start` out (or redact it).',
 '**Bundle integrity:** produce a fresh `SHA256SUMS` for the bundle, and record in it the hash of each raw source file it was derived from.',
 '**Team bundle (built 2026-10-12, internal):** `team_bundle/`, made by `tools/make_team_bundle.py` (not hashed: it holds the real values; never share it). Lighter redactions for teammates\' analysis: public addresses remapped to documentation ranges, the Hue token overwritten, VLAN-tagged frames dropped, the roommate router MAC remapped, checksums recomputed. Internal addresses, MACs and host names stay. Secrets, nvram, the full Pi-hole export, `ddns-start` and the git history are left out. It has its own `SHA256SUMS` and `PROVENANCE.tsv` (source file, source SHA-256, transformation). Rebuilt 2026-10-14 in the submission layout (below) and frozen read-only. The submission bundle still follows the stricter redaction plan above.',
 '**Submission layout (team bundle now, final bundle later):** the bundle is an overlay of the main project repo (`01-Subject Report/`, `02-Code/`, `03-Result/`, `04-Contribution Table/`, `05-Work Summary/`) and only adds this part\'s subfolder `IoT-Segmentation/` under `02-Code/` and `03-Result/`. `02-Code/IoT-Segmentation/` holds `tools/` and the router repo export `asuswrt-configs/` (with `GIT_LOG.txt`). `03-Result/IoT-Segmentation/` holds the bundle\'s `README.md`, `SHA256SUMS` (paths relative to the repo root) and `PROVENANCE.tsv`, the intermediate reports (`segmentation_report.md`, `analysis.md`, this manifest) and all evidence with their working-folder paths, so the evidence paths in the reports resolve inside it. The intermediate reports never go into `01-Subject Report/`, which holds the team\'s main report.'):
    w(f'- {o}')
w('\n## Appendix: full SHA-256\n')
w('```')
for f, hh in sums.items(): w(f'{hh}  {f}')
w('```')
w(f'\nGit repo `asuswrt-configs`: HEAD `{HEAD}`.')
tmp = 'evidence_manifest.md.tmp'
open(tmp, 'w').write('\n'.join(out) + '\n'); os.replace(tmp, 'evidence_manifest.md')
print('rows', len(rows), 'ids', len(EID), 'files', len(sums))
