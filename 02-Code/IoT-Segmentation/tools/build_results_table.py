#!/usr/bin/env python3
"""Render results_to_evidence.md: one row per result, in plain words, with the deciding numbers,
the evidence IDs (E-IDs from evidence_manifest.md) and the analysis section that explains it.

Report tooling (not evidence). Fails if a cited E-ID isn't in the manifest or a cited section
doesn't exist, so the table can't drift from the documents it summarises.

  python3 tools/build_results_table.py      # after tools/build_manifest.py
"""
import os, re, sys, time

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def read(p):
    for _ in range(20):
        try:
            return open(p, encoding='utf-8').read()
        except BlockingIOError:
            time.sleep(0.5)
    raise SystemExit(f'cannot read {p}')

manifest, analysis, report = read('evidence_manifest.md'), read('analysis.md'), read('segmentation_report.md')
EIDS = set(re.findall(r'^\| (E\d+) \|', manifest, re.M))
def heads(s): return set(re.findall(r'^#{2,4} (\d+(?:\.\d+)*)[ .]', s, re.M))
A_SECT, R_SECT = heads(analysis), heads(report)
NFILES = sum(1 for l in read('SHA256SUMS').splitlines() if l.strip())

# (result in plain words, deciding numbers, [(E-ID, what it is)], where explained)
# where: '§x.y' = analysis.md, 'report x.y' = segmentation_report.md
GROUPS = [
 ('Metric 1: every planned test scenario was run at least once', [
  ('All planned scenarios ran: 24 h recordings before and after segmentation, app use, a firmware update, '
   'device restarts, scans in both directions, three simulated attacks and the final function check.',
   'Recordings and tests from 2026-10-06 to 2026-11-02',
   [('E16', 'action log'), ('E90', 'scan from the IoT network'), ('E108', 'upload test run files'), ('E110', 'function checklist')],
   '§9, §16.7'),
 ]),
 ('Baselines and encrypted traffic (contract: at least two device baselines)', [
  ('"Normal" behaviour is recorded for five devices, before and after segmentation.',
   '24 h each; the Hue checks in with its cloud ~436 times a day; the Matter switches never touch the internet',
   [('E01', 'flat recording, Wi-Fi'), ('E02', 'flat recording, Hue port'), ('E06', 'segmented recording, Wi-Fi'),
    ('E07', 'segmented recording, Hue port'), ('E24', 'Pi-hole DNS extract')],
   '§3'),
  ('The traffic is encrypted, but its metadata was enough: no finding needed decryption.',
   'Domain names, server names, addresses, timing, volume and TLS fingerprints',
   [('E06', 'segmented recording'), ('E07', 'segmented recording, Hue port'), ('E24', 'Pi-hole DNS extract')],
   '§4, §12.2'),
 ]),
 ('Metric 2: suspicious behaviour detected by transparent rules (contract: at least 3)', [
  ('**Real:** the SwitchBot hub leaks Matter identifiers to the internet because of a firmware bug (rule R4).',
   '949 packets a day to the invalid address 255.2.0.0; an ISP router answered 25 times, so they left the house',
   [('E06', 'segmented recording'), ('E17', '3 h firewall log')], '§5.1'),
  ('**Real:** the Hue Bridge keeps retrying a diagnostics domain that Pi-hole blocks (R5).',
   '2.4 → 44 blocked lookups per hour after segmentation',
   [('E24', 'Pi-hole DNS extract'), ('E07', 'segmented recording, Hue port')], '§5.2'),
  ('**Real:** the Hue downloads a firmware update from a server it never used before (R1 + R3).',
   '14.37 MB in one minute from `otau.meethue.com`',
   [('E07', 'segmented recording, Hue port')], '§5.3'),
  ('**Real:** a Tapo firmware update is caught as "new behaviour after a change" (R1 + R3).',
   '3 new domains; 1.59 MB in 34 s, against ~5 kB a day normally',
   [('E70', 'update recording'), ('E16', 'action log'), ('E75', 'firewall log')], '§13.2'),
  ('**Real (weakness):** the Hue sends a fixed token over unencrypted HTTP (R10).',
   '4 requests a day, the same token every time',
   [('E02', 'flat recording, Hue port'), ('E07', 'segmented recording, Hue port')], '§12.3'),
  ('**Real (weakness):** the VFD clock looks up the home\'s approximate location over unencrypted HTTP (R10).',
   'At every boot: time zone, latitude and longitude from `ip-api.com`',
   [('E101', 'clock boot recording')], '§16.6'),
  ('**Real (configuration defect, fixed):** the router stopped advertising IPv6 to the IoT network after a Wi-Fi restart (R11).',
   '0 adverts for 50 min; fixed in state D, still fine after restarts in state E',
   [('E71', 'update recording, Hue port'), ('E93', 'state E re-test')], '§13.6, §15.2'),
  ('**Simulated:** a lateral scan from the IoT network is blocked and logged (R2).',
   '58,771 packets dropped; 254 of 256 household addresses showed nothing',
   [('E88', 'firewall log'), ('E89', 'router counters'), ('E90', 'scan output')], '§14.2'),
  ('**Simulated:** a DNS bypass (asking an outside DNS server) is detected in state D and prevented in state E (R7).',
   'D: answered by `1.1.1.1`, logged. E: answered by Pi-hole instead, DNS-over-TLS times out',
   [('E88', 'firewall log, D'), ('E90', 'test output, D'), ('E91', 'firewall log, E'), ('E93', 'test output, E')],
   '§14.4, §15.4'),
  ('**Simulated:** bulk data theft, a 100 MB upload to cloud storage (R3, R1).',
   '143 MB in 4 minutes, 70× the volume threshold',
   [('E96', 'upload recording'), ('E107', 'router counters'), ('E108', 'run files and cloud folder listing')], '§16.4'),
  ('**Simulated:** slow data theft, 30 small files over 30 minutes. It stays under the network-wide volume threshold, '
   'as predicted, but per-device volume (R3) and connection counting (R6) catch it.',
   '1.11 MB in 43 min (threshold 2.06 MB/h); up to 63 connections per 10 min to one server',
   [('E96', 'upload recording'), ('E108', 'run files'), ('E109', 'evaluation tool')], '§16.4, §16.5'),
  ('False alarms are explained and the rules tuned: Matter status messages (R2) and a stale baseline for the Tapo (R3).',
   'Matter: 60 drops before the fix, 0 after; Tapo flagged at 26× an out-of-date baseline',
   [('E19', 'Matter drop log'), ('E29', 'settings after the fix'), ('E110', 'function checklist')],
   '§5.4, §16.4, §17.3'),
 ]),
 ('Metric 3: unauthorised access between networks is blocked', [
  ('Segmentation removed the shared network: IoT devices no longer see or get probed by household computers.',
   'Visible neighbours 26 → 8; roommate traffic on the Hue port 89,336 frames → 0',
   [('E01', 'flat recording'), ('E06', 'segmented recording')], '§6.1'),
  ('IoT → household computers: blocked, except DNS to Pi-hole and ping (both on purpose).',
   '254 of 256 addresses fully filtered; IPv6 likewise',
   [('E89', 'router counters'), ('E90', 'scan output')], '§14.2'),
  ('IoT → the router itself: locked down in state E.',
   'Before: SSH, DNS, media server and proxy reachable. After: only DHCP, time, mDNS and ping; SSH times out',
   [('E91', 'firewall log'), ('E92', 'router counters'), ('E93', 're-test output')], '§14.3, §15.3'),
  ('All IoT DNS is forced through Pi-hole; DNS-over-TLS is blocked.',
   'IPv4 and IPv6, UDP and TCP, any destination; even a non-existent address gets Pi-hole\'s answer',
   [('E93', 're-test output'), ('E94', 'router counters'), ('E95', 'firewall log')], '§15.4'),
  ('The fibre modem\'s admin page can\'t be reached from the IoT network any more.',
   'Connection times out; drop counter 23 → 49; still reachable from the main network',
   [('E93', 're-test output'), ('E94', 'router counters'), ('E95', 'firewall log')], '§15.6'),
 ]),
 ('Metric 4: required device functions still work after segmentation', [
  ('Matter status messages are no longer dropped, fixed without opening a new firewall hole.',
   '60 drops before; 0 after raising a router timeout from 180 s to 1800 s',
   [('E19', 'drop log, before'), ('E29', 'router settings, after'), ('E22', 'live connections, after')],
   '§5.4 (report 1.7)'),
  ('Every control in the apps works across the network boundary, and app use makes devices contact nothing new.',
   'Apple Home, Eve, Hue and SwitchBot apps, 7 minutes with a written action log',
   [('E11', 'app recording, Wi-Fi'), ('E12', 'app recording, Hue port'), ('E16', 'action log')], '§7'),
  ('A 28-point function checklist in the final state passes, including control from outside the house and recovery after a router reboot.',
   '28 / 28; all 7 devices back 3.5 min after a reboot',
   [('E110', 'filled checklist'), ('E111', 'screenshots')], '§17'),
 ]),
 ('Metric 5: every result is backed by reproducible evidence', [
  ('Every evidence file and analysis tool is fingerprinted, so any change is detectable; derived files can be regenerated from them.',
   f'{NFILES} files in `SHA256SUMS`; `sha256sum -c SHA256SUMS` passes',
   [('E66', 'main analysis tool'), ('E62', 'Zeek runner'), ('E109', 'upload evaluation tool')], '§1.2'),
  ('The Splunk pipeline rebuilds every result from the raw files and shows it on a dashboard; rebuilt independently, it gives the same numbers as the analysis.',
   '64,721 events; e.g. Hue median upload 206,309 B/h and the 935 / 1,966 Hue DNS queries, identical; the rules find the same events (deliberate differences, e.g. no Tapo false alarm, in §18.3)',
   [('E112', 'pipeline'), ('E113', 'detection rules and dashboard'), ('E118', 'dashboard screenshots')], '§18'),
  ('Independent sources agree with each other.',
   'Recording vs Pi-hole DNS counts identical (935 / 1,966); cloud listing = reconstructed upload size to the byte; router counter vs recording within 3 %',
   [('E02', 'flat recording, Hue port'), ('E24', 'Pi-hole DNS extract'), ('E107', 'router counters'), ('E108', 'cloud folder listing')],
   '§1.2, §16.2'),
 ]),
]

RULES = [
 ('R1', 'A device contacts a domain it has never used before'),
 ('R2', 'An IoT device tries to start a connection into the main network (blocked and logged)'),
 ('R3', 'A device sends or receives more than 10× its normal hourly volume'),
 ('R4', 'A device sends to an address that can\'t exist on the internet'),
 ('R5', 'A device keeps retrying a domain that Pi-hole blocks (> 5× its normal rate)'),
 ('R6', 'More than 10 connection attempts to one server within 10 minutes'),
 ('R7', 'A device asks a DNS server other than Pi-hole'),
 ('R8', 'A device that should be local-only (the Matter switches) talks to the internet'),
 ('R9', 'A device\'s encryption "fingerprint" (JA4) changes'),
 ('R10', 'A device sends unencrypted web traffic to the internet'),
 ('R11', 'The router stops advertising the IoT network\'s IPv6 settings'),
 ('R12', 'A device uses an outdated encryption version (below TLS 1.2)'),
]

GLOSSARY = [
 ('Main network / IoT network', 'The household computers and phones (`192.168.0.x`) vs the smart-home devices (`192.168.107.x`, Wi-Fi `I0N_IoT`). Separating the two is the "segmentation".'),
 ('VLAN', 'A separate network on the same router and cables. The IoT network is VLAN 107; the roommate\'s is VLAN 114 (out of scope).'),
 ('States A–E', 'The router\'s configuration over time: A everything on one network, B IoT VLAN created, C fully segmented, D fixes from testing, E router locked down (final).'),
 ('Controller', 'The HomePod, iPhone or Mac that sends commands to the devices. Controllers may start connections into the IoT network; devices may only reply.'),
 ('Matter', 'The smart-home standard the devices use to be controlled locally (UDP port 5540), without going through a cloud.'),
 ('Pi-hole', 'The household DNS server. It answers "which address is this name?" for every device and blocks known tracking domains, which makes every lookup visible.'),
 ('Recording (capture, pcap)', 'A full copy of the network traffic taken at the router, analysed afterwards with Zeek and tshark.'),
 ('Firewall log entries', '`IOT_TO_WAN_NEW` new IoT → internet connection (logged, allowed); `IOT_TO_LAN_DROP` IoT → main network (blocked); `IOT_TO_ROUTER_DROP` IoT → router service (blocked); `IOT_DNS_REDIRECT` DNS sent to Pi-hole instead.'),
 ('Baseline', 'A device\'s normal behaviour over 24 h: who it talks to, how often, how much. Rules flag departures from it.'),
 ('True / false positive', 'A rule fired on something real (TP) or raised a false alarm (FP). Both are recorded; false alarms lead to tuning.'),
 ('E-ID (E01 … E111)', 'The ID of an evidence file in `evidence_manifest.md`, where its location, time window, sensitivity and hash are listed.'),
 ('Hash (SHA-256)', 'A fingerprint of a file. If even one byte changes, the fingerprint changes, so `SHA256SUMS` proves the evidence is unmodified.'),
]

errors = []
def check_where(w):
    for ref in re.findall(r'§(\d+(?:\.\d+)*)', w):
        if ref not in A_SECT: errors.append(f'analysis §{ref} missing')
    for ref in re.findall(r'report (\d+(?:\.\d+)*)', w):
        if ref not in R_SECT: errors.append(f'report {ref} missing')

out = []
w = out.append
w('# Results and their evidence\n')
w('**Project:** *A Low-Cost Workflow for Detecting and Visualizing Suspicious Network Behaviour in Smart-Home IoT Devices*  ')
w('**What this is:** a one-page map from each result to the evidence that proves it. One row per result, in plain words, with the numbers that decide it, the evidence IDs and the section of `analysis.md` that explains it.  ')
w('**How to use it:** read the "Result" column for the story. To check a result, look up its E-IDs in `evidence_manifest.md` (file, time window, hash), then read the section listed. The rules (R1–R12) and terms are explained at the end.  ')
w('**Status:** all five Learning Contract metrics are met.\n')
w('*Generated by `tools/build_results_table.py`; every E-ID and section reference below is checked against the current documents.*\n')
n = 0
for title, rows in GROUPS:
    w(f'## {title}\n')
    w('| # | Result | Deciding numbers | Evidence | Explained in |')
    w('|---|---|---|---|---|')
    for res, nums, ev, where in rows:
        n += 1
        for eid, _ in ev:
            if eid not in EIDS: errors.append(f'row {n}: {eid} not in manifest')
        check_where(where)
        evs = '<br>'.join(f'{e} ({d})' for e, d in ev)
        w(f'| {n} | {res} | {nums} | {evs} | {where} |')
    w('')
w('## The detection rules in one line each\n')
w('All rules are simple thresholds on router logs, Pi-hole and traffic summaries, so anyone can check why a rule fired. Full table: `analysis.md` §8.\n')
w('| Rule | Fires when |')
w('|---|---|')
for r, d in RULES: w(f'| {r} | {d} |')
w('')
w('## Glossary\n')
w('| Term | Meaning |')
w('|---|---|')
for t, d in GLOSSARY: w(f'| {t} | {d} |')
w('')
check_where('§8')
if errors:
    sys.exit('results table: ' + '; '.join(errors))
text = '\n'.join(out)
for _ in range(20):
    try:
        with open('results_to_evidence.md.tmp', 'w', encoding='utf-8') as fh: fh.write(text)
        os.replace('results_to_evidence.md.tmp', 'results_to_evidence.md'); break
    except BlockingIOError:
        time.sleep(0.5)
print('rows', n, 'eids', len({e for _, rows in GROUPS for r in rows for e, _ in r[2]}))
