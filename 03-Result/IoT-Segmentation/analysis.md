# IoT Segmentation: Evidence Analysis

**Project:** *A Low-Cost Workflow for Detecting and Visualizing Suspicious Network Behaviour in Smart-Home IoT Devices* (Industry Stream, Topic A)
**Scope of this document:** analysis of the raw evidence catalogued in `evidence_manifest.md` (captures, firewall logs, Pi-hole extract, router state), structured along the Learning Contract's research questions and evaluation metrics.
**Companion documents:** `results_to_evidence.md` (one-page map from each result to its evidence, with a glossary), `segmentation_report.md` (configuration and change record, states A–E), `evidence_manifest.md` (artefacts and hashes).
**How to read this document:** each section starts with an *In short* box in plain language. The detail below it is for checking and reproducing the work.
**Status:** analysis of raw evidence, seventh pass. The first pass used dependency-free Python tools. The second pass added **Zeek 8.0**, **tshark 4.4 (JA4/JA3)** and **active main-LAN → IoT tests (nmap, HTTP)** (§12). The third pass covers the **state D verification capture**: a Tapo firmware update and two power cycles, recorded after the NTP and mDNS-reflector changes (§13). The fourth pass is the **active test from the IoT VLAN** (§14), which also ran two of the simulated scenarios (lateral scan, DNS bypass). The fifth pass is the **state E re-test** from the same host after the router hardening (§15). The sixth pass is the **simulated volume-upload scenario** (exfiltration to cloud storage, §16). The seventh pass is the owner's **function checklist** in state E, which closes metric 4 (§17). The eighth pass is the **Splunk pipeline and dashboard**, which rebuilds every result from the raw evidence and closes metric 5 (§18).

Times are AEDT (UTC+11). Addresses are internal ones, or public cloud endpoints; the WAN address and delegated prefix are redacted throughout.

---

## 1. Method

> **In short:** We recorded the IoT devices' traffic at the router in several sessions between 6 October and 2 November 2026: 24-hour recordings before and after segmentation, plus shorter test runs. Router firewall logs and the Pi-hole DNS log were saved alongside. Free tools (our own Python scripts, Zeek, tshark) turned the recordings into per-device summaries. No recording lost packets, and independent tools agreed on the counts.

### 1.1 Data used

| Data | Window | Use |
|---|---|---|
| Flat capture (E01–E02), state A | 2026-10-06 21:53 → 10-07 21:53 (24 h) | Pre-segmentation baseline and exposure |
| Segmented capture (E06–E07), states C → D | 2026-10-10 00:28 → 10-11 00:28 (24 h) | Post-segmentation baseline; Matter drop period 12:12–12:48 |
| App-interaction capture (E11–E12), state D + WAN logging | 2026-10-11 13:45:42 → 13:52:46 (7 min) | Scenario execution with ground truth (E16) |
| Tapo capture (E70–E71), state D at `d0c3085` | 2026-10-11 16:43:39 → 17:53:42 on `eth7` (70 min); `wl0.2` only until 17:03:11 | verification of the NTP and reflector changes; firmware-update and power-cycle scenarios with ground truth (E16) |
| `firewall_logs/FW_log_3h.log`, `FW_log_app_interaction.log` (E17–E18) | 10-11 10:27 → 13:52 | Transparent-rule output (`IOT_TO_WAN_NEW`) |
| `firewall_logs/FW_tapo_capture.log` (E75) | 10-11 16:43 → 17:50 (syslog gap 17:14:30–17:31:07) | Transparent-rule output (`IOT_TO_WAN_NEW`) |
| `firewall_logs/FW_matter-5540-iot-lan-drop.log` (E19) | 10-10 12:12 → 12:48 | Transparent-rule output (`IOT_TO_LAN_DROP`) |
| Router counters and conntrack (E20–E22, E76–E81) | 10-11 14:01; 16:43 and 17:51 (before/after the tapo capture) | Firewall rule hit counts, live session state |
| `derived/pihole_iot_trimmed.csv` (E24) | W1–W4 (export ends 10-11 17:51:28) | Domain-level DNS evidence, blocked queries |
| Active test from the IoT VLAN (E90), router counters (E89), `firewall_logs/FW_iot_active.log` (E88) | 10-11 21:57 → 22:12 | IoT → main-LAN/router reachability; simulated lateral scan and DNS bypass |
| Re-test from the IoT VLAN, state E (E91–E95) | 10-11 23:55 → 10-12 01:01 | Router containment, DNS enforcement, ONT (§15) |
| Upload capture (E96–E100), router counters (E107), `firewall_logs/FW_upload.log` (E106), run files (E108) | 10-31 17:26:58 → 18:28:22 (log from 17:59:45) | Simulated volume upload (§16) |
| VFD clock boot capture (E101–E105) | 10-31 18:43:53 → 18:44:33 | New device, first observation (§16.6) |
| Function checklist (E110) with screenshots (E111) | 11-02 00:17 → 01:21 | Required device functions in state E, incl. remote access, wireless restart and router reboot (§17) |
| Splunk pipeline (E112–E117) run over all of the above; dashboard screenshots (E118–E119) | 11-03 | Events, detection rules and dashboard in Splunk (§18) |

All twelve pcaps recorded **0 kernel drops**, and hardware offload (`fc`, `runner`) was disabled for each run (`run.log`). The tapo capture's `wl0.2` tcpdump ended early when its interface disappeared (§13.1). The packet counts can therefore be treated as complete for traffic that passes through the capture interfaces.

### 1.2 Tooling

The analysis uses small, dependency-free Python tools so any reviewer can re-run it from the raw files. That fits the contract's emphasis on low cost and reproducibility [1].

| Tool | Output |
|---|---|
| `tools/pcap_inventory.py` | Packet counts, time spans, VLAN tags, MAC → IP map (`derived/pcap_inventory.json`) |
| `tools/analyze_pcaps.py` | Per-device flows (`derived/analysis/flows_*.csv`, Splunk-ingestible), DNS queries/answers, TLS SNI, mDNS exposure, hourly volumes (`summary_*.json`) |
| `tools/summarize_flows.py` | Per-device baselines (`derived/analysis/baselines.json`) |
| `tools/trim_pihole.py` | IoT-only Pi-hole extract |
| `tools/run_zeek.sh` + `tools/zeek/iot-local.zeek` | Zeek 8.0 logs per capture in JSON (`derived/zeek/<capture>_<iface>/`): `conn` (with MACs), `dns`, `ssl`, `x509`, `http`, `dhcp`, `ntp`, `notice`, `weird`, `known_services`. BPF `not vlan`. |
| `tools/tls_fingerprints.sh` | tshark JA4/JA3 + SNI of every TLS ClientHello (`derived/tls/clienthello_fingerprints.tsv`) |
| `nmap` / `curl` from the analysis terminal | Active main-LAN → IoT service exposure (`derived/active/`) |
| `tools/setup_env.sh` | Re-installs the toolchain (tshark, Zeek, nmap, jq) after a terminal reset |

The tool outputs under `derived/` are regenerable from the hashed captures and tools, so they aren't hashed; `evidence_manifest.md` lists the command for each. The Pi-hole extract and the active-test results are the exceptions: they are hashed evidence.

**Measurement rules**
- Each device is measured **only on its own capture interface**: the Hue Bridge on `eth7`, every other device on `wl0.2`. No packet is counted twice.
- VLAN-tagged frames (VLAN 114, the roommate's network, present on `eth7` in the flat capture) are **skipped**. They're out of scope: only owned or authorised devices may be tested [1].
- A "session" is a 5-tuple whose packets are less than 120 s apart. Volumes are IP-layer bytes.

**Cross-checks:**
- The DNS query counts the parser extracts from the pcaps match Pi-hole's own records exactly for the Hue Bridge: 935 (flat) and 1,966 (segmented) in both sources.
- Zeek and tshark independently reproduce the parser's TLS counts: Zeek `ssl.log` has 417 / 434 `data.meethue.com` sessions vs the parser's 417 / 434 SNI; tshark finds 854 + 1 ClientHellos from the Hue Bridge across both captures.

---

## 2. Device inventory

> **In short:** Five smart-home devices are analysed: a Philips Hue Bridge, a SwitchBot Hub 2, a Tapo smart plug and two Matter wall switches. A HomePod and an iPhone on the main network control them. Two devices that joined later (a Meross plug and a VFD clock) are observed but not baselined.

| Device | MAC | Transport / ecosystem | Cloud | Local control path |
|---|---|---|---|---|
| Hue Bridge | `ec:b5:fa:bc:52:10` | Ethernet (`eth7`), Zigbee to bulbs; Matter bridge + HomeKit | Philips/Signify (`*.meethue.com`) | Matter (UDP 5540), local HTTPS API (TCP 443) |
| SwitchBot Hub 2 | `0c:4e:a0:30:22:54` | Wi-Fi, BLE to SwitchBot Bots; Matter bridge (IPv4) | AWS IoT Core MQTT/TLS (`*.iot.us-east-1.amazonaws.com:8883`) | Matter (UDP 5540) |
| Tapo smart plug **P110M** (DHCP host name) | `7c:f1:7e:10:03:a0` | Wi-Fi; Matter | TP-Link (`n-aps1-device-api.tplinkcloud.com`) | Matter (UDP 5540); local HTTP on TCP 80 (`Server: SHIP 2.0`) |
| Matter switch ×2 (likely Zemismart) | `8c:87:d0:09:0d:6b` / `…:6e` | Wi-Fi; Matter only | **none observed** | Matter (UDP 5540) |
| Eve Room | (Thread) | Thread via the HomePod border router | none | **never on the IoT VLAN**: routed by the HomePod on the main LAN |

**Controllers on the main LAN:** the HomePod (`192.168.0.22`, home hub) and the iPhone (`192.168.0.221`, a direct Matter controller while the Home app is open).

**Joined after the analysis windows** (not in any analysed data so far): Meross smart plug `c4:e7:ae:20:54:57` (`192.168.107.2`) and LGL VFD clock VCK 0658-L `d8:f1:5b:90:ee:b3` (`192.168.107.22`). First observed in the upload-scenario capture (§16.6); not baselined.

---

## 3. Device baselines (contract: at least two)

> **In short:** For each device we recorded what "normal" looks like over 24 hours: which internet services it talks to, how often and how much. The Hue Bridge is the chattiest (a cloud check-in about every 3.4 minutes); the Matter switches never contact the internet at all. The detection rules compare against these baselines.

The contract defines a baseline as destinations and domains, protocols and ports, connection frequency, volume, duration, and DNS/TLS metadata [1]. Five devices are baselined below. The Hue Bridge and SwitchBot Hub 2 are the primary baselines (richest cloud behaviour); the Tapo plug and Matter switches are secondary.

### 3.1 Summary, 24 h each

| Device | State | Total bytes | Cloud bytes out / in | Cloud endpoints (IPs) | DNS queries (all to Pi-hole) | Cloud ports |
|---|---|---|---|---|---|---|
| Hue Bridge | flat | 124.9 MB | 4.5 MB / 1.9 MB | 11 | 935 | TCP 443, TCP 80, UDP 123 |
| Hue Bridge | segmented | 127.8 MB | 6.0 MB / **16.5 MB** | 12 | **1,966** | TCP 443, TCP 80, UDP 123 |
| SwitchBot Hub 2 | flat | 1.20 MB | 224 kB / 139 kB | 23 | 29 | TCP 8883, UDP 123 |
| SwitchBot Hub 2 | segmented | 1.05 MB | 237 kB / 149 kB | 21 | 41 (pcap) / 29 (Pi-hole) | TCP 8883, UDP 123 |
| Tapo smart plug | flat | 6.04 MB | 2 kB / 5 kB | 4 | 6 | TCP 443, UDP 123 |
| Tapo smart plug | segmented | 5.77 MB | 2 kB / 5 kB | 5 | 5 | TCP 443, UDP 123 |
| Matter switch ×2 | flat | 1.43 / 1.30 MB | **0 / 0** | 0 | **0** | none |
| Matter switch ×2 | segmented | 0.61 / 0.63 MB | **0 / 0** | 0 | **0** | none |

**DNS:** in both states, 100 % of the DNS queries observed from every device went to Pi-hole (`192.168.0.8`). No device used a hardcoded resolver, DNS-over-TLS (853) or DNS-over-HTTPS to a non-Pi-hole address.

### 3.2 Hue Bridge (primary baseline)

| Characteristic | Flat | Segmented | Notes |
|---|---|---|---|
| **Domains** (DNS + SNI) | `data.meethue.com`, `diag.meethue.com` (blocked), `diagnostics.meethue.com`, `ws.meethue.com`, `broker-eu-03.iot.meethue.com` | same, **plus `otau.meethue.com`** | `otau` = over-the-air update service |
| **Telemetry beacon** | ~419 TLS handshakes/day to `data.meethue.com` (3 AWS IPs, round-robin) | ~436/day | One new TLS connection every ~3.4 min. Stable across states, so it's a reliable baseline feature. |
| **Persistent sessions** | 1 long-lived TLS session each to `diagnostics/ws` (34.117.13.189) and `broker-eu-03` (MQTT-over-TLS, 35.233.55.222) | same | 24 h duration, a few hundred kB |
| **Plain HTTP** | 4 short TCP 80 sessions/day to 34.117.13.189 | 4/day | Unencrypted; worth noting, though the content wasn't inspected |
| **NTP** | Router (`192.168.0.1`, DHCP option 42) + Google (216.239.35.0/.4) | Router unanswered ×158; falls back to 6 public servers (Google, Alibaba) | See §5.6 |
| **Hourly cloud upload** | mean 180 kB/h, max 316 kB/h (max/median 1.9) | mean 242 kB/h, max 684 kB/h (3.3) | |
| **Blocked DNS** (Pi-hole status 1) | `diag.meethue.com` ×58 (≈2.4/h, steady) | ×1,066 (≈44/h, bursty) | See §5.2 |
| **Multicast** | mDNS ≈ 103,000 packets/day per IP family (≈108 MB/day); SSDP 239.255.255.250 | same (≈97 MB/day) | The chattiest device by far. Most of its "total bytes" is local multicast, not cloud. |
| **Local control** | Matter over link-local IPv6 to the HomePod; TCP 80 from two main-LAN hosts (§6.1) | Matter over ULA/IPv4 to the HomePod; local HTTPS from the iPhone's Hue app | |

### 3.3 SwitchBot Hub 2 (primary baseline)

| Characteristic | Flat | Segmented | Notes |
|---|---|---|---|
| **Domains** | `a2alhn2dfztqv9.iot.us-east-1.amazonaws.com` (AWS IoT Core), `pool.ntp.org` | same | Cloud in the US-East region |
| **Cloud session** | MQTT over TLS, TCP 8883: one long-lived session. **77 SYNs to 2 broker IPs in bursts** (reconnect storms) | 4 SYNs total, stable sessions | Connection stability differs between states (§5.5) |
| **Volume** | ≈9.0 kB/h up (max/median 1.7) | ≈9.5 kB/h (2.0) | Very regular keep-alive profile; a good anomaly baseline |
| **NTP** | `pool.ntp.org`, ~hourly | same | |
| **mDNS** | Responds to IPv6 mDNS queries **with IPv4 packets to 255.2.0.0 / 254.128.0.0** | 949 packets to 255.2.0.0 in 24 h | **Anomaly, see §5.1** |
| **Local control** | Matter (IPv4) to HomePod / iPhone | Matter (IPv4, UDP 58688 ↔ 5540) to the HomePod | IPv4-only Matter stack |

### 3.4 Secondary baselines

- **Tapo smart plug:** almost silent to the cloud. One TLS session per day to `n-aps1-device-api.tplinkcloud.com` (≈2 kB up / 4 kB down), plus NTP. Its traffic is overwhelmingly local Matter to the HomePod (≈2.7 MB/day). Any meaningful cloud volume from it would be an immediate outlier, and the firmware update on 10-11 was exactly that (§13.2). On 10-11 the plug also held a session to `aau1-device-cloudgateway.iot.i.tplinknbu.com` (already open before the update) and, after the update, contacted `security.iot.i.tplinknbu.com` and the cloud gateway on every (re)join.
- **Matter switches:** **no cloud and no DNS at all**, in every window. Their whole footprint is Matter (UDP 5540) to the HomePod/iPhone, mDNS, ND and DHCP. That's the ideal low-risk IoT profile, and it gives a hard rule: *any* WAN connection from these MACs is anomalous.

---

## 4. Which characteristics still work when the payload is encrypted? (RQ 2)

> **In short:** Almost all device traffic is encrypted, so its contents can't be read. The "envelope" still tells a lot: which name a device looks up, which server it connects to, when, how often and how much. Every finding in this document was made from that metadata alone.

All cloud traffic observed is TLS (443/8883) apart from NTP, Hue's short TCP-80 sessions and DNS. Without decryption, the following characteristics were enough to build every finding in this document:

| Characteristic | Source | What it gave us |
|---|---|---|
| **DNS query names + Pi-hole status** | Pi-hole, pcap | Domain per device; blocked-telemetry retry storm (§5.2); "no DNS = no cloud" for the Matter switches |
| **TLS SNI** (ClientHello) | pcap | Domain even without DNS context (e.g. `otau.meethue.com`, the AWS IoT endpoint on 8883) |
| **Destination IP / port / protocol** | pcap, firewall log | Cloud vs local; MQTT (8883) vs HTTPS; Matter (5540); bogus destinations (§5.1) |
| **Connection frequency / periodicity** | pcap, firewall log | Hue's 3.4-minute beacon; SwitchBot reconnect bursts |
| **Volume and direction** | pcap | 14.4 MB OTA download (§5.3); per-hour upload baselines |
| **Duration** | pcap | Long-lived MQTT/TLS sessions vs short beacons |
| **Unencrypted local protocols** (mDNS, DHCP, SSDP) | pcap | Root cause of the SwitchBot anomaly (Matter records in the leaked packets); stale NTP server (DHCP option 42) |
| **ICMP errors from upstream** | pcap | Proof that leaked packets left the home network (§5.1) |

**Limits:** Matter payloads (CASE-encrypted) and TLS contents can't be inspected, so the **intent** of a connection (what data was uploaded) stays unknown. Conclusions are about *who, where, when and how much*, not *what*.

---

## 5. Findings and detections

> **In short:** The baselines turned up real, unstaged problems. The SwitchBot hub leaks Matter identifiers to the internet because of a firmware bug; the Hue Bridge keeps retrying a blocked diagnostics domain; the Hue downloaded a 14 MB update from a new server. Each was caught by a simple, documented rule. One problem, dropped Matter status messages, was caused by our own firewall and was fixed.

### 5.1 SwitchBot Hub 2 leaks Matter mDNS records to the internet via a bogus destination (**anomaly, real**)

- **Observation:** the hub sends UDP 5353 packets to **`255.2.0.0`**: 949 in the segmented 24 h, 7 in the flat capture, 91 in the 3 h firewall log and 9 during app interaction. The flat capture also has 15 packets to **`254.128.0.0`**. Neither is a valid unicast, multicast or broadcast address; both fall in the reserved `240.0.0.0/4` range.
- **Root cause, from the packet contents:** `255.2` = `0xff02` and `254.128` = `0xfe80`, i.e. the **first 32 bits of the IPv6 addresses** `ff02::fb` (mDNS multicast) and `fe80::/10` (link-local). The hub answers **IPv6** mDNS queries by building **IPv4** packets whose destination is the truncated IPv6 address. That's a firmware bug in its (IPv4-only) network stack. The payloads are `_matter._tcp.local` PTR records (Matter operational instance names: compressed fabric ID + node ID).
- **Why it got worse after segmentation:** the avahi reflector (`use-ipv6=yes`) repeats main-LAN IPv6 mDNS queries onto the IoT VLAN (31,949 IPv6 mDNS packets from the router in 24 h), so the hub answers far more often (7 → 949/day).
- **Impact:** `255.2.0.0` isn't on-link, so the hub sends the packets to its default gateway. The router **forwards them to the WAN**: `IOT_TO_WAN_NEW … OUT=eth1`, and the FORWARD policy accepts them. An upstream ISP router (`8.245.134.21`) answered 25 times with **ICMP type 3 code 1 (host unreachable)** quoting `255.2.0.0`, proving the packets left the house. Matter fabric/node identifiers were therefore exposed to the ISP path. Severity is **low** (identifiers only, no credentials), but it's a clear integrity/privacy defect.
- **Detection:**
  - *Rule R4, "IoT → WAN to a non-routable destination"*: any `IOT_TO_WAN_NEW` entry with `DST` in `0.0.0.0/8`, `127.0.0.0/8`, `224.0.0.0/3` (multicast + reserved) or RFC 1918. Fires on 100 of 226 WAN log entries.
  - Corroborated by inbound ICMP unreachable messages from external hosts.
- **Mitigation:** egress-filter bogon/reserved destinations from the IoT bridge (`-i br52 -o eth1 -d 240.0.0.0/4 -j DROP`, likewise `224.0.0.0/4`). Optionally restrict the reflector to Matter/HomeKit services (§6.2) or to IPv4. Report the bug to SwitchBot.
- **Status (final): closed as a vendor firmware bug, with a documented workaround that isn't deployed** (`segmentation_report.md` open item 6).
  - The leak persists in every state, including after the reflector filter (§13.5), because avahi doesn't filter queries.
  - R4 keeps detecting it.
  - The owner will report it to SwitchBot after the project.
  - This is an additional finding of the analysis: a vendor network-stack defect, discovered only because segmentation plus the reflector amplified it.

### 5.2 Hue Bridge: retry storm against a blocked telemetry domain (**anomaly, real**)

- **Observation:** `diag.meethue.com` is blocked by Pi-hole (status 1) in every window. Query rate: **flat ≈ 2.4/h (steady, 1 A + 1 AAAA per hour)**, **segmented ≈ 44/h** (1,066/day, bursty, 2–95/h), W3 ≈ 34/h. The **allowed** domains' query volumes are unchanged between states (e.g. `data.meethue.com` 803 vs 827).
- **Timing:** the rate was already elevated at the start of the segmented capture (42/h at 00:00 on 10-10), **before** the firmware download (§5.3). So the OTA isn't the trigger.
- **Most likely cause (hypothesis):** a changed failure condition after segmentation. The Hue Bridge keeps its old NTP server `192.168.0.1` (DHCP option 42 from the main LAN; the IoT DHCP doesn't hand out option 42) and gets **158 unanswered NTP requests/day** (§5.6). Repeated diagnostic upload attempts would be consistent with the bridge reporting this error. To test: hand out a reachable NTP server on the IoT VLAN and check whether the diag rate returns to ~2/h.
- **Detection:**
  - *Rule R5, "blocked-domain retry storm"*: Pi-hole status-1 queries per device per hour > 5× that device's baseline median. Fires for the Hue Bridge in W2 and W3.
- **Update (W4, tapo capture):** 84 blocked queries in 70 min (≈72/h): 108/h right after the Hue's power cycle, decaying to 24/h by 17:40. The test above still can't be run: option 42 now points the bridge at `192.168.107.1`, but the router doesn't serve NTP on `br52`, so the bridge's local NTP keeps failing (§13.4).
- **Assessment:** benign telemetry attempt, successfully blocked. It's a useful demonstration that **DNS filtering produces measurable, explainable signals**. Unblocking is a policy decision, not a security requirement.

### 5.3 Hue Bridge: new destination + 14.4 MB download (**new connection after a change, real; assessed benign**)

- **Observation:** on 2026-10-10 at 15:14 the bridge resolved `otau.meethue.com` (SNI confirmed) and downloaded **14.37 MB** from 35.241.40.143 in a single 1-minute TLS session. That domain doesn't appear in the flat baseline, and that hour's cloud volume (684 kB/h up, plus the download) is the maximum of the whole dataset.
- **Detection:**
  - *Rule R1, "new destination domain/SNI not in the device baseline"*: fires once (`otau.meethue.com`).
  - *Rule R3, "inbound volume > 10× the device's hourly median"*: fires for the same hour.
- **Assessment:** consistent with a firmware or Zigbee accessory OTA download. Firmware was current on 10-11, matching the app check (§7). This is the contract's scenario of *new connections appearing after a configuration change* [1], detected by two transparent rules. It's labelled a **true positive for "change", benign in intent**.

### 5.4 Matter subscription reports dropped at the segment boundary (**policy side effect, fixed**)

- **Observation:** 60 `IOT_TO_LAN_DROP` entries (UDP source port 5540 → the HomePod) from 4 devices on 10-10 between 12:12 and 12:47, in bursts of 5 (Matter MRP retransmissions).
- **Cause:** the 180 s UDP connection-tracking timeout was shorter than the interval between Matter reports.
- **Fix:** `ct_udp_timeout="30 1800"`. After the fix, conntrack shows the HomePod/iPhone ↔ IoT Matter sessions with remaining lifetimes of 892–1,674 s (consistent with 1800 s), and the IPv4/IPv6 `IOT_TO_LAN_DROP` counters show **0 packets** since the last firewall restart.
- **Detection:** *Rule R2, "IoT-initiated connection to the main LAN"* (`IOT_TO_LAN_DROP`) fired as designed. It was classified as a **false positive caused by policy**, and the timeout was tuned rather than adding an exception. Full write-up in `segmentation_report.md` §1.7.

### 5.5 SwitchBot MQTT reconnect bursts (flat only)

In the flat capture the hub sent **77 SYNs to two AWS IoT broker IPs** in short bursts (sessions < 120 s apart), against 4 SYNs in the segmented 24 h.

**Zeek `conn.log` clarifies it:**
- 22 connection attempts in state **`S0`** (SYN sent, never answered), in three bursts at about 05:01, 05:10 and 06:24 on 10-07. Each burst is a retry roughly every 6 s.
- Each burst ended with a successful session (`SF`/`S1`), and that session then lasted 1.3–15 h.

So the broker or the path was unreachable for a few minutes at a time; it wasn't the hub misbehaving. In the segmented capture every session completed.

*Rule R6, "connection-attempt burst" (> 10 SYNs to one destination within 10 min; in Zeek terms, ≥ 5 `S0` connections)* flags this. It's classified as an **availability anomaly** (cloud/path outage), not a security event.

### 5.6 Configuration drift: stale NTP server (functional finding)

The flat DHCP lease gave the Hue Bridge **option 42 = `192.168.0.1`**. The IoT VLAN's lease has no option 42, but the bridge kept the old server and sent **158 unanswered NTP requests/day** to `192.168.0.1`. That traffic is addressed to the router itself, so it isn't visible in the FORWARD logs. Time sync still works through public NTP fallbacks, so there's **no functional break**, but it may drive §5.2. **Fix:** add `dhcp-option=42,192.168.107.1` to the IoT block of `dnsmasq-sdn.postconf` and accept UDP 123 on `br52` (INPUT), or deliberately keep public NTP.

**Status (D, `75807a2`):** option 42 is now delivered and used, and the INPUT rule admits the requests. But the router's NTP daemon is bound to `br0`, so each request gets ICMP port unreachable (§13.4). Partly fixed.

**Status (D, `a738f35`):** a second ntpd instance per VLAN bridge now serves NTP on the IoT VLAN. It's confirmed running on the router (`segmentation_report.md` §1.10).

### 5.7 Negative results (rules that didn't fire)

| Rule | Result | Meaning |
|---|---|---|
| DNS bypass (DNS/853/DoH to anything other than Pi-hole) | 0 hits in all windows | Every device honours DHCP-assigned DNS |
| Any WAN traffic from the Matter switches | 0 hits | Local-only behaviour confirmed |
| IoT IPv6 to WAN | 0 packets (IPv6 `IOT_TO_WAN_NEW` counter and NAT6 counters) | IoT devices use IPv4 only for cloud traffic |
| New destination during app interaction | 0 hits | Interaction produced no new endpoints (§7) |

---

## 6. Visibility and exposure before vs after segmentation (RQ 3)

> **In short:** Before segmentation the IoT devices shared a network with every household computer: they could see 26 other devices and two Windows PCs probed them. Afterwards they see only the router and the controllers, the roommate's traffic is gone from their port, and every attempt to reach the main network is blocked and logged. What was left over (the mDNS service list) was later cut from 38 to 5–7 service types.

### 6.1 What an IoT device could see and reach

| Indicator (24 h) | Flat (A) | Segmented (C/D) | Change |
|---|---|---|---|
| Distinct L2 senders visible on `wl0.2` / `eth7` | 26 / 23 | 8 / 7 | Main-LAN hosts no longer share the broadcast domain |
| Main-LAN hosts sending mDNS onto the IoT link | 14 | 1 (the router's reflector) | |
| mDNS **service types** advertised to IoT devices | 53 | **55** | **Unchanged.** The reflector re-advertises the main LAN's catalogue (§6.2). After the reflector filter (`d0c3085`): 38–43 types still *mentioned* (queries are reflected), only 5–7 types *answered* (§13.5) |
| Thread/border-router ULA packets (`fd05:37e5:64c4::/48`) on the IoT link | 4,776 | 0 | Thread mesh routing no longer visible to IoT devices |
| VLAN 114 frames on the IoT port (`eth7`) | 89,336 | 0 | The Hue port no longer carries the roommate VLAN (access port) |
| Main-LAN hosts initiating to IoT devices (other than the controllers) | Hosts `.16` / `.17` (**Windows PCs**, identified by Zeek `http.log` user agents: Valve Steam Client and Chrome on Windows 10, plus `DAFUPnP`, the Windows device-association UPnP client): 40 `GET /description.xml` to the Hue Bridge (21 from `.16`, 19 from `.17`) over plaintext HTTP (UPnP discovery); `.17` also sent **UDP probes to every Wi-Fi IoT device** (answered with ICMP port unreachable). The Mac mini Server (`.13`) also fetched the Hue description. The Hue Bridge sent 1,656 UDP packets to R2 (homelab host). | **None observed.** Only the HomePod, iPhone, Pi-hole and router appear as peers | |
| IoT-initiated connections to the main LAN | Unrestricted (same L2 domain) | Blocked and logged; only DNS to Pi-hole, ICMP echo, and replies allowed. 0 drops after the timeout fix | |
| IoT access to router services | DHCP, DNS, NTP | DHCP only (plus DNS via Pi-hole); NTP to `192.168.0.1` unanswered | D (`75807a2`): NTP to `192.168.107.1` reaches the router but is refused (ICMP port unreachable, §13.4). Later in D (`a738f35`): served by a per-VLAN ntpd instance (`a738f35`). **E:** only DHCP, NTP, mDNS and ICMP (`IOT_INPUT`); DNS to any router address is redirected to Pi-hole (§15.3) |

**Interpretation**
- Segmentation removed **layer-2 adjacency**: shared broadcast and multicast, Thread border-router traffic, VLAN 114 on the IoT port, and unsolicited probing/HTTP access from arbitrary main-LAN hosts.
- It also enforces a **one-way** policy at layer 3: only the controllers initiate; IoT can only reply, query DNS and ping.
- Before segmentation, a main-LAN host was observed actively **probing every IoT device** (UDP to a closed port, ICMP replies) and two hosts reached the Hue Bridge's **plaintext HTTP API**. That's exactly the kind of lateral reachability the segmentation is meant to remove [1].

### 6.2 Residual exposure introduced by the mDNS reflector

The reflector (`avahi-daemon.postconf`) is needed for HomeKit/Matter discovery, but as configured it reflects **all** services. IoT devices still receive the main LAN's service catalogue: `_ssh._tcp`, `_smb._tcp`, `_rfb._tcp` (VNC), `_afpovertcp._tcp`, `_adb._tcp` / `_adb-tls-connect._tcp` (Android debugging), `_webdav(s)._tcp`, printers/scanners, AirPlay and Apple device-pairing services, among others.
- **Reachability** to those services is blocked by the firewall.
- **Information exposure** (hostnames, service inventory) remains, and it also amplifies the SwitchBot leak (§5.1).
- **Recommendation:** add `reflect-filters=_hap._tcp,_hap._udp,_matter._tcp,_matterc._udp` (avahi ≥ 0.8) and re-measure the mDNS service types on `wl0.2`. The expected result is ≤ 4 service types.
- **Implemented in D (`d0c3085`)**, with `_matterd._udp` and `_hue._tcp` added. Result (§13.5): service types in reflected answers 38 → 5–7. Queries are still reflected (avahi doesn't filter them), so the SwitchBot trigger (§5.1) remains.

### 6.3 Firewall evidence (post-interaction counters, IPv4)

| Rule | Packets | Meaning |
|---|---|---|
| `IOT_TO_WAN_NEW` LOG | 300 | New IoT → WAN connections since the firewall restart |
| main LAN → IoT ACCEPT | 742 | Controller-initiated traffic (Matter, Hue app) |
| IoT → main LAN ESTABLISHED/RELATED | 483 | Replies |
| IoT → Pi-hole DNS (UDP) | 272 | All IoT DNS |
| IoT → main LAN echo-request | 0 | |
| `IOT_TO_LAN_DROP` LOG / DROP | 0 / 0 | No blocked lateral attempts after the Matter fix |

The IPv6 counters follow the same pattern: 593 controller-initiated packets, 661 replies, 0 drops. The NAT6 rules for the IoT ULA show 0 packets. *Limitation:* no "before" snapshot, so these are cumulative since the last firewall restart. The tapo capture is bracketed by before/after snapshots; the deltas are in §13.8.

---

## 7. Scenario execution: app interaction (13:45–13:52)

> **In short:** We used each vendor app for a few minutes while recording, with a written log of every action. All controls worked across the network boundary, because commands go straight from the HomePod or iPhone to the device. No device contacted anything new. "Check for updates" happens in the phone apps, not on the devices.

Ground truth comes from `interaction_timeline.txt` (E16; app-session start times). Actions in each app: version/update checks (no updates were available), "add new device" page, and toggling devices (Apple Home).

| App window | IoT-side traffic observed | Interpretation |
|---|---|---|
| **Apple Home** (13:45:51–13:47:55) | The iPhone **and** the HomePod open Matter sessions (UDP 5540) to the Hue Bridge, SwitchBot hub, Tapo plug and a Matter switch. The Hue Bridge pushes state to `data.meethue.com` (2 new TLS connections logged). SwitchBot MQTT traffic. 1 bogus mDNS packet. | Toggling is executed **locally over Matter**. Cloud traffic is the vendors' state sync after the change, not part of the control path. |
| **Eve** (13:47:55–13:49:44) | No Eve traffic on the IoT VLAN (expected: Thread via the HomePod). **6 SwitchBot packets to `255.2.0.0`** while the app browses for accessories. Background Matter/cloud traffic. | The app's mDNS browsing directly triggers the §5.1 leak. |
| **Hue** (13:49:44–13:51:08) | **iPhone → Hue Bridge local HTTPS (TCP 443)**: 378 packets, 94 kB. Bridge ↔ `diagnostics/ws` 59 kB. **No `otau` contact.** | The Hue app talks to the bridge locally. The version check isn't done by the bridge itself in this window. |
| **SwitchBot** (13:51:08–13:52:46) | Only small MQTT keep-alive traffic (11 packets); 1 bogus mDNS packet; Hue background beacon. | App actions go phone → cloud. The hub barely reacts; "add device" uses BLE (not visible on IP). |

**Findings**
- **No new destinations** were contacted by any IoT device during the interaction, so R1 stayed silent (correct negative).
- **Version/update checks are performed by the phone apps against the vendor clouds, not by the devices.** They're invisible on the IoT VLAN. Capturing them would mean capturing the phone on the main LAN, which is outside the IoT-centric scope.
- Every toggle produced local Matter traffic, and the devices' cloud reports followed immediately. Required control functions **work across the segment boundary** (metric 4).

---

## 8. Transparent rule set

> **In short:** Twelve simple rules (R1–R12), each a one-sentence condition with a fixed threshold, cover everything we detected. Each is computed from router logs, Pi-hole or the traffic summaries, so it can be rebuilt in Splunk. The table records what each rule fired on, and whether that was a real problem (true positive) or a false alarm (false positive).

All rules are documented, threshold-based and computable from router logs, Pi-hole or flow summaries, so they can be implemented directly as SPL searches in Splunk.

| ID | Rule | Data source | Threshold / logic | Fired on | Classification |
|---|---|---|---|---|---|
| R1 | New destination domain/SNI for a device | Pi-hole, SNI | domain ∉ device baseline (flat + first 24 h) | `otau.meethue.com` (§5.3); Tapo `ota-download.tplinkcloud.com`, `security.iot.i.tplinknbu.com`, `aau1-device-cloudgateway…` (§13.2); Hue boot-time NTP/time names (§13.3); MEGA cloud storage in the upload scenario (§16) | TP (change), benign; Hue reboot = FP; **TP** (simulated) |
| R2 | IoT-initiated connection to the main LAN | `IOT_TO_LAN_DROP` | any | Matter reports (§5.4); simulated lateral scan from the IoT VLAN (§14.2) | FP (policy), tuned; **TP** (simulated) |
| R3 | Volume spike | flows | hourly in/out > 10× device median | Hue, 10-10 15:00 (§5.3); Tapo 1.59 MB OTA, 10-11 16:44 (§13.2); simulated 100 MiB upload to MEGA (§16, TP); Tapo plug at ~2 kB/h vs a pre-update 76 B/h median (§16, FP) | TP (change), benign; **TP** (simulated); FP (Tapo, stale baseline) |
| R4 | IoT → WAN to a non-routable/reserved destination | `IOT_TO_WAN_NEW` | DST in 0/8, 127/8, 224/3, RFC 1918 | SwitchBot 255.2.0.0 (§5.1); still 23 of 247 entries in the tapo capture (§13.5); vendor bug, router workaround documented but not deployed (`segmentation_report.md` open item 6) | **TP, anomaly** |
| R5 | Blocked-domain retry storm | Pi-hole status 1 | per hour > 5× device baseline median | Hue `diag.meethue.com` (§5.2) | **TP, anomaly** (benign intent) |
| R6 | Connection-attempt burst | flows (SYN) | > 10 SYNs to one destination in 10 min | SwitchBot MQTT, flat (§5.5); slow upload: ~13 connections per 16 KiB file, up to 63 SYNs per 10 min to one storage node (§16, TP) | Anomaly, cause unknown; **TP** (simulated slow upload) |
| R7 | DNS bypass | flows / firewall | DNS/853 to anything other than Pi-hole | none from IoT devices; simulated `1.1.1.1` UDP 53 and TCP 853 from the test host (§14.4). State E: DNS is redirected (`IOT_DNS_REDIRECT`), and DoT attempts are still logged before the drop (§15.4) | TN (devices); **TP** (simulated) |
| R8 | Any WAN traffic from a local-only device | `IOT_TO_WAN_NEW` | Matter switch MACs | none | TN |
| R9 | New TLS client fingerprint for a device | tshark / Zeek (JA4) | JA4 ∉ device's baseline set (§12.2) | none across states A/C/D (the OTA download reused the `data.meethue.com` JA4). After the Hue's power cycle: 2 new JA4s (TLS 1.0 boot handshake, first-seen broker handshake, §13.3). The Tapo kept its JA4 through a firmware update | TN; Hue reboot = FP |
| R10 | Cleartext HTTP from an IoT device to the internet | Zeek `http.log` | any request to a non-RFC 1918 host | Hue `POST /v2/diagnostics/report` (§12.3); VFD clock looks up its time zone and location from `ip-api.com` over HTTP (§16.6) | **TP, weakness** |
| R11 | Router stops advertising the IoT prefix | pcap (ICMPv6 RA), router state | no RA for > 3× the normal interval (~8 s), or router ULA absent | RAs and the router's ULA stop at 17:03:11 (§13.6) | **TP, config defect** |
| R12 | Legacy TLS from an IoT device | Zeek `ssl.log` | negotiated version < TLS 1.2 | Hue boot handshake to `time.meethue.com`, TLS 1.0 (§13.3) | **TP, weakness** |

**Metric 2 (≥ 3 suspicious-behaviour scenarios detected by transparent rules [1]):** met with **real, unstaged** behaviour: R4 (bogus-destination leak), R5 (blocked telemetry storm), R1 + R3 (new destination + volume after a change) and R10 (cleartext telemetry carrying a persistent token). R2 adds a policy-related detection and R6 an availability anomaly. The tapo capture adds a second, independent *change* detection (Tapo firmware update: R1 + R3) and two new detections: R11 (lost IPv6 prefix after a wireless restart) and R12 (TLS 1.0 at boot). Two of the planned **simulated** scenarios were executed from a test host on the IoT SSID (§14): the lateral scan (R2 and the DROP counters) and the DNS bypass (R7), both detected. The volume-upload scenario (§16) was then run as well: bulk upload caught by R3 and R1, slow upload by the per-device R3, R1 and R6.

---

## 9. Evaluation against the Learning Contract metrics [1]

> **In short:** All five Learning Contract metrics are met. The table gives the evidence for each and the remaining caveats; for example, hosts in the roommate's network were deliberately not tested. `results_to_evidence.md` maps every result to its evidence IDs on one page.

| # | Metric | Status | Evidence | Gap |
|---|---|---|---|---|
| 1 | All documented test scenarios executed at least once | **Met** | Baseline captures A/C (24 h each); segmentation change; Matter fix; app interaction; WAN logging window; the state D verification capture with a **firmware update** and **power-cycle recovery** (§13); **active tests in both directions** (§12.4, §14); simulated **lateral scan** and **DNS bypass** (§14); **state E re-test** of router access, DNS enforcement and bridge rebuilds (§15); **simulated volume upload** (bulk and slow, §16) | — |
| 2 | ≥ 3 suspicious-behaviour scenarios detected by transparent rules | **Met** (real events) | §5.1–5.3, §8 (R4, R5, R1+R3; R2); tapo capture: R1+R3 on the Tapo update, R11, R12 (§13); simulated scenarios all detected: lateral scan (R2), DNS bypass (R7), volume upload (R3, R1, R6; §16) | — |
| 3 | All unauthorised inter-segment reachability tests blocked after segmentation | **Met** (within scope) | **IoT → main-LAN hosts blocked** (v4 and v6) apart from the documented DNS and echo exceptions (§14.2), also via hairpin NAT (§15.5); **IoT → router contained in state E**: only DHCP, NTP, mDNS and ICMP answer on every router address, SSH dropped (§15.3); **IoT → ONT management blocked** (`904f54d`, §15.6); DNS forced to Pi-hole on both address families (§15.4); passive evidence (§6.1, §13.8); main LAN → IoT open by design (§12.4) | VLAN 114 hosts not tested (scope); the roommate VLAN's SSH and ONT drops are in place but can't be exercised without an owned host there |
| 4 | All documented required device functions continue after segmentation | **Met** | **Written function checklist in state E (§17, E110–E111): 28 of 28 checks passed**, covering local Matter/HomeKit control of every IP device, scenes, automations, the Eve Room via the HomePod, all vendor apps, **remote control through the HomePod over cellular**, recovery after a wireless restart and a router reboot, NTP, DNS and firmware-update checks. Earlier evidence: Matter control from the HomePod and iPhone to all 5 IP devices (§7); Matter report drops fixed (§5.4); Tapo firmware update through the segment and power-cycle recovery (§13); functions after the state E bridge rebuild (§15.2, §15.6) | Two remarks, neither a lost function: the Tapo plug stopped switching once after the wireless restart until it was power-cycled (device side, like the switches in §13.7), and Matter reports were briefly dropped right after the router reboot and once more 10 min later (self-healing, R2 policy false positives; §17.3). Single run |
| 5 | Every result backed by reproducible evidence | **Met** | Hash-verified raw evidence and first-order extracts (`SHA256SUMS`), dependency-free tools; Zeek logs, JA4 table, flow CSV/JSON regenerable with the commands in `evidence_manifest.md`; nmap output. **Splunk stage (§18):** the pipeline (E112–E117) regenerates all 64,721 events from the hashed raw evidence and reproduces the analysis' numbers; the dashboard shows every detection with its source (E118–E119); `results_to_evidence.md` maps each result to its evidence | — |
---

## 10. Recommendations

> **In short:** 23 concrete follow-ups. Struck-through items are done, with where they were implemented and verified. Of the rest, 5 and 20–22 belong to the Splunk stage (how the rules should be tuned), and the others are documented options, tooling improvements or vendor issues.

1. **Egress-filter reserved/bogon destinations from the IoT VLAN** (stops the §5.1 leak at the router) and keep R4 as a detection rule. **Workaround documented, not deployed** (`segmentation_report.md` open item 6, closed); R4 stays the detection.
2. ~~Restrict the mDNS reflector~~ **Done in D (`d0c3085`):** reflected answer types 38 → 5–7 (§13.5). Queries are still reflected, so recommendation 1 is still needed for the SwitchBot leak.
3. ~~Provide NTP on the IoT VLAN~~ **Done in D.** The INPUT rule is in place (`75807a2`), and option 42 now advertises the main-LAN router address `192.168.0.1` (`0416f8d`). `ntpd` is bound to `br0`, and `sntp` from a laptop on `I0N_IoT` confirmed neither address answers. **`a738f35`** therefore adds a serve-only `ntp -l -I <bridge>` on every VLAN bridge, including `br52`. It starts and stops with the firmware ntpd and its "Enable local NTP server" switch (`segmentation_report.md` §1.10). It's confirmed running on the router (the extra instances start with the firmware ntpd). The §5.2 hypothesis (Hue diag rate back to ~2/h with working local NTP) needs a new capture or Pi-hole window to test.
4. ~~Run the active reachability matrix and the three simulated scenarios~~ **Done:** reachability in both directions (§12.4, §14, §15) and all three simulated scenarios: lateral scan (§14.2), DNS bypass (§14.4) and volume upload (§16). Metrics 1 and 3 are met.
5. ~~Ingest into Splunk~~ **Done (§18):** the pipeline (`pipeline/iotpipe.py`, E112) turns the captures, Zeek logs, JA4 fingerprints, firewall logs and Pi-hole export into 11 sourcetypes, loaded over HEC. R1–R12 run as SPL macros behind the dashboard deliverable [1].
6. **Snapshot router counters before and after** each experiment window (done for the tapo capture), record end times as well as start times, and log unplanned events too: the two wireless restarts at 17:03 and ~17:10 aren't in the timeline.
7. Report the SwitchBot IPv6→IPv4 mDNS bug to the vendor. **The owner will contact SwitchBot after the project** (evidence: §5.1, `FW_log_3h.log`, the segmented capture).
8. **Narrow main LAN → IoT to the controllers.** The current `br0 → br52 ACCEPT` lets *any* main-LAN host reach the IoT services found in §12.4, including the unauthenticated Hue `/api/0/config` and the Matter switches' unidentified TCP 3000 service. Restrict it to the HomePod and iPhone (DHCP reservations; MAC or IP match), plus anything else that truly needs it (e.g. a Hue integration on the homelab), and log everything else.
9. **Hue cleartext diagnostics (§12.3):** unblocking `diag.meethue.com` won't fix it. Treat it as a vendor weakness, document it, and consider blocking `diagnostics.meethue.com` port 80 at the router if the Hue still works without it (test first).
10. ~~Re-add the ULA addresses after wireless restarts~~ **Done in D (`1b36092`, §13.6).** Keep R11 as a health check.
11. ~~Remove the STP delay on the IoT bridge~~ **Done in D (`d119636`):** STP is off on the IoT bridge (§13.3).
12. **Supervise each tcpdump in `iot-capture.sh`** and restart it when its interface disappears (§13.1).
13. ~~Find the cause of the Matter switch outage before relying on metric 4 for the switches~~ **Resolved (§13.7):** the owner had restarted wireless before the capture and the switches didn't rejoin until a later restart; no recurrence after a power cycle. The function checklist later confirmed both switches (§17).
14. ~~Restrict router access from the VLANs (§14.3)~~ **Done in state E (`5b0e391`), verified (§15.3):** in `firewall-start`, for each VLAN bridge, accept only what clients need on INPUT (DHCP 67, NTP 123, mDNS 5353 on the IoT bridge; DHCPv6 547 on the roommate bridge) and drop the rest: SSH, router DNS, DLNA 8200, 81/444/60000. Identify those last three first (`netstat -tlnp`).
15. ~~Drop SSH from the VLANs~~ **Done in state E (`5b0e391`), verified from the IoT VLAN (§15.3):** dropped on every VLAN bridge; the roommate bridge's rule is in place but can't be exercised (no owned host). WAN SSH stays enabled on purpose; the owner keeps it secured.
16. ~~Enforce DNS (§14.4)~~ **Done in state E (`5b0e391`), verified for IPv4 and IPv6, UDP and TCP, and DoT on both families (§15.4):** DNAT IoT-bridge UDP/TCP 53 that isn't addressed to Pi-hole over to Pi-hole, and drop TCP 853 from the IoT bridge to the WAN. Keep R7 as the detection for anything that gets past it (DoH can't be blocked by port).
17. ~~Account for the unidentified clients on `I0N_IoT`~~ **Resolved (§14.5):** the owner's own Apple devices. In the state E re-test the **HomePod** itself had joined `I0N_IoT` (§15.6). **Remove the IoT network from iCloud Keychain** (or give it a passphrase that isn't synced), and alert when a controller MAC shows up on `br52`. **Done 2026-10-28:** `I0N_IoT` removed from iCloud Keychain; no Apple device on the IoT SSID.
18. ~~Check the IPv6 TCP DNS redirect~~ **Done (§15.4):** `dig +tcp` over IPv6 to Cloudflare and to the router got Pi-hole's block answer (v6 TCP DNAT +2), and DoT over IPv6 timed out.
19. ~~Block IoT → ONT management~~ **Done (`904f54d`), verified (§15.6):** the ONT was reachable from the IoT VLAN; now `nc` times out and the `br52` drop counts, while the main LAN keeps access. The roommate VLAN gets the same drop.
20. **Give the per-device R3 a floor and re-baseline after firmware updates (§16.4).** The Tapo plug's 76 B/h median (5 active hours, pre-update) makes 10× meaningless: use e.g. `max(10 × median, 10 kB/h)`, or a high percentile instead of the median, and rebuild a device's baseline after every firmware change (R1/R3 already flag the change itself). *Status:* the floor is built into the dashboard's R3 (§18.3), which removes the Tapo false positive; re-baselining after a firmware change is still a manual step.
21. ~~Run volume and connection-count rules together~~ **Done in the dashboard (§18.3):** R3 and R6 both run per device, attributed by MAC, and their findings sit side by side in the detail table (§16.5). Scheduled alerts weren't set up; the dashboard is the review tool.
22. ~~Classify Matter reports in R2~~ **Done in the dashboard (§18.3):** a blocked message from source port 5540 to a known controller is labelled *info* ("Matter status message blocked (expected)"); every other R2 hit stays critical (§17.3).
23. **Treat a wireless restart as a maintenance event (§17.2).** Twice now a device didn't come back cleanly from one (the Matter switches in §13.7, the Tapo plug in §17.2), while the router side was fine. After any `restart_wireless` or router change, re-run checks A1–A5 of the function checklist and power-cycle any device that misbehaves.

---

## 11. Limitations

> **In short:** What the evidence can't show: encrypted contents, traffic between two devices on the same Wi-Fi, weekly patterns (the recordings are 24 h), and a few gaps where the router's log rotated. Each test pass lists its own caveats here.

- **Visibility:** unicast between two Wi-Fi clients on the same SSID can be bridged inside the Wi-Fi driver and miss the capture. Thread devices (the Eve Room) are never on the IoT VLAN. Phone-side cloud traffic (update checks) is outside the IoT captures.
- **Encryption:** TLS and Matter payloads weren't decrypted; findings are metadata-based (§4).
- **Small sample:** 24 h per state and one 7-minute interaction window. The baselines show daily behaviour but not weekly cycles.
- **Attribution in the flat window:** in state A the devices used dynamic main-LAN addresses. Attribution relies on MAC → IP mapping from the same capture.
- **Main-LAN hosts `.16` / `.17`** were identified as Windows PCs running Steam and Chrome, whose UPnP/SSDP discovery explains the Hue `description.xml` requests (§6.1). The cause of `.17`'s UDP probes to the Wi-Fi IoT devices wasn't confirmed; it's most likely a discovery feature of the same software.
- **Active tests ran from a NAT'd terminal on the main LAN:** they show what any main-LAN host can reach in the IoT VLAN, not what an IoT device can reach.
- **The rate-limited WAN log** (30/min) is an alert channel, not a complete record. The 3 h window was well under the limit.
- **Tapo capture coverage:** `wl0.2` stopped at 17:03:11, so Wi-Fi unicast for the last 50 min (including the Matter switches' recovery) is visible only through flooded broadcast/multicast on `eth7`, router state and logs. The window is 70 min right after deployment and two reboots, so NTP and diag rates aren't steady state.
- **Router state:** the conntrack snapshots contain IPv4 entries only. `FW_tapo_capture.log` lost ~19 entries to a syslog rotation gap (§13.8). The Pi-hole export ends at 17:51:28, 2 min before the tapo capture.
- **Active test from the IoT VLAN (§14):** `--min-rate 2000` with one retry left 29,625 router ports `filtered` that a slower scan would probably show as closed. UDP `open|filtered` means no answer, so it can't distinguish dropped from silent. The firmware INPUT sub-chains (`SDN_FI`, `PTCSRVWAN`) weren't dumped, so the exact rule behind each router result is inferred.
- **State E re-test (§15):** the saved log starts at 23:58:01, so r1 and the first ~2 min of r2 are covered only by nmap output and counters (most likely a syslog rotation after the wireless restart; cf. §13.8). LOG rules are rate-limited, so some probes (e.g. r4 TCP 22/53/80) have no log line. `terminal_history.txt` holds outputs only; the commands come from the nmap XML and the re-test plan. The owner's app check is a statement without an artefact. The IPv6 DNS follow-up has no router counters or timestamps beyond the file time. In the second follow-up (E94, E95) the IPv6 TCP 853 DROP counter fell outside the dumped lines; the log and the timeout cover it.
- **Volume-upload scenario (§16):** one run with one test host, a laptop that's noisier than any IoT device even when quieted; the MEGA folder listing was recorded after the run, not during it; the firewall log lost its first 33 minutes to syslog rotation; Run A's end time comes from the capture, not the timeline. The thresholds were fixed beforehand, but R6 was evaluated after the fact.
- **Splunk stage (§18):** the dashboard was reviewed by the owner on Splunk Enterprise 10.6.1.1. The expected result of every rule was computed separately in Python from the same events (`pipeline_guide.md` section 7.5). It was compared with the dashboard's counters and visible findings, not row by row. Three rules deliberately differ from §8 (§18.3): R1 only covers baselined devices, R3 has a floor, and R5 compares with the first baseline recording.
- **Function checklist (§17):** one run, by the owner; most results are visual confirmations, backed by screenshots for 10 rows. The counter rise in check E1 is the owner's reading (final value 21), and the `IOT_INPUT` snapshot was taken a little after the run. The FORWARD snapshot was taken just before the last drop burst (15 v4 drops counted, 20 v4 entries logged). A8 used the existing occupancy automation rather than a time-based one; it is executed by the HomePod either way.

---

## 12. Second pass: Zeek, tshark and active tests

> **In short:** We re-ran the recordings through Zeek and tshark to confirm the counts, examined the quality of each device's encryption, and scanned the devices from the main network. Each device has a stable encryption "fingerprint"; the Tapo uses weak encryption without forward secrecy; the Hue sends a fixed token over unencrypted HTTP. The scan showed that every main-network computer, not just the controllers, can reach the devices' services (recommendation 8).

### 12.1 Zeek corroboration

Zeek 8.0 was run over all eight pcaps (JSON logs, `mac-logging`, BPF `not vlan`).

| Capture | conn | dns | ssl | http | x509 | notice | weird |
|---|---|---|---|---|---|---|---|
| flat `wl0.2` / `eth7` | 45,707 / 39,726 | 273,872 / 269,939 | 4 / 421 | 0 / 50 | 3 / 1 | 4 / 63 | 36 / 36 |
| seg `wl0.2` / `eth7` | 6,407 / 8,030 | 186,209 / 187,179 | 5 / 438 | 0 / 4 | 3 / 2 | 4 / 62 | 108 / 107 |
| app `wl0.2` / `eth7` | 84 / 71 | 768 / 765 | 0 / 8 | 0 / 0 | 0 / 2 | 0 / 3 | 2 / 2 |
| tapo `wl0.2` (20 min) / `eth7` (70 min) | 78 / 707 | 2,834 / 5,625 | 4 / 33 | 0 / 0 | 4 / 3 | 3 / 5 | 8 / 19 |

Most of the `dns` volume is mDNS. The drop in `conn` between flat and seg (≈ −83 %) is another measure of the lost layer-2 adjacency (§6.1).

**DHCP-derived identity.** `dhcp.log` host names: `SwitchBot-Hub-2-302254`, **`P110M`** (Tapo), and `wlan0` for the Matter switches (generic, so not identifying).

**`weird.log`: the reflector forwards malformed mDNS.** In the segmented captures, Zeek flags `EDNS_truncated_option` (79), `DNS_label_too_long`, `DNS_label_len_gt_pkt` and `DNS_label_forward_compress_offset`, all with the **router's IoT-side addresses** (`192.168.107.1`, `fd00:d:e:6b::1`) as source. None of these appear with the router as source in the flat capture. The avahi reflector re-emits main-LAN mDNS packets that it has truncated or mangled. It's harmless for HomeKit/Matter in practice, but it's another reason to restrict the reflector (§6.2).

### 12.2 TLS posture and fingerprints (RQ 2)

The TLS handshake metadata visible without decryption, per device. All server-certificate chains come from vendor-private or incomplete CAs, so Zeek's certificate validation fails for all of them; for IoT devices pinning vendor roots, that's expected.

| Device | TLS versions / negotiated cipher | Server cert subject (cleartext in TLS 1.2) | JA4 (client stack) |
|---|---|---|---|
| Hue Bridge → `data.meethue.com`, `otau.meethue.com` | TLS 1.2, ECDHE-ECDSA-AES128-GCM (otau: ECDHE-ECDSA-CHACHA20) | `CN=data.meethue.com, O=Signify Netherlands B.V.` (private chain) | `t12d350600_9d4c96c0953b_0a9c83bf8b96` |
| Hue Bridge → `ws.meethue.com` | TLS 1.3, CHACHA20-POLY1305 | (encrypted in TLS 1.3) | `t13d051000_30218df08eda_5ac7197df9d2` |
| Hue Bridge → `data.meethue.com` addresses, no SNI (once a day, 19:25) | TLS 1.2 | | `t12i280600_d943125447b4_3c5a66c06c35` |
| Hue Bridge → `broker-eu-03.iot.meethue.com` (first handshake seen: after the power cycle) | TLS 1.3, CHACHA20-POLY1305 | (encrypted) | `t13d031000_102f0cf501bc_5ac7197df9d2` |
| Hue Bridge → `time.meethue.com` (boot only, no SNI) | **TLS 1.0**, ECDHE-RSA-AES128-CBC-SHA | `CN=time.meethue.com` (Google Trust Services WR3; validates) | `t10i090500_c491f621fb4c_195413a0cc0f` |
| SwitchBot Hub 2 → AWS IoT (8883) | TLS 1.2, ECDHE-RSA-AES128-GCM | `CN=*.iot.us-east-1.amazonaws.com` | `t12d490700_4b815dab2718_7b0ba9b4cf08` |
| Tapo P110M → TP-Link | TLS 1.2, **`TLS_RSA_WITH_AES_128_CBC_SHA256`** | `CN=*.tplinkcloud.com, O=TP-LINK GLOBAL INC.` (self-signed chain); OTA host `ota-download.tplinkcloud.com`: DigiCert chain, validates. After the update the cloud gateway negotiates `TLS_RSA_WITH_AES_256_CBC_SHA256` | `t12d090500_30597426f5bb_8027956694ec` (unchanged through the firmware update) |
| iPhone (Hue app) → Hue Bridge (local, 443) | TLS 1.2 | `CN=ecb5fafffebc5210, O=Philips Hue` (bridge ID) | `t13d171000_5b57614c22b0_78e6aca7449b` |

**Findings**
- **JA4 is a stable, per-device feature.** Each device kept its JA4 set across both 24 h captures, and the 14.4 MB OTA download reused the Hue's `data.meethue.com` fingerprint. A previously unseen JA4 from a device would indicate a new client stack (firmware change or injected software). That's rule **R9**, a strong encrypted-traffic feature that needs no decryption. Two caveats from the tapo capture (§13.2–13.3): the Tapo kept its JA4 through a firmware update (JA4 tracks the TLS library, not the firmware version), and a reboot exposes handshakes that a 24 h capture never sees, so baselines need a boot sample.
- **The Tapo plug negotiates RSA key exchange with CBC** (no forward secrecy). That's weaker than every other device and worth noting in the threat discussion: the content of past sessions could be recovered if TP-Link's server key ever leaked.
- **TLS 1.2 exposes certificate subjects** (vendor, organisation, bridge ID) to anyone on the path, while TLS 1.3 sessions (Hue `ws`) hide them.

### 12.3 Hue Bridge sends diagnostics over cleartext HTTP, with a persistent token (**weakness, real**)

Zeek `http.log` shows **`POST http://diagnostics.meethue.com/v2/diagnostics/report?report_type=iot_connection&sso=<200-hex-char token>&auth=<hash>&i=<id>`** (user agent `ureq/2.12.1`), 4 times per 24 h in both states.
- The **`sso` value is identical in every request in both captures** (value redacted). It's a persistent identifier or credential sent in a URL over **plain HTTP**.
- The `auth`/`i` values change per request.

This is the "TCP 80" traffic noted in §3.2: the Hue Bridge's only cleartext cloud traffic. Anyone on the network path (ISP, a hostile Wi-Fi uplink, an upstream MITM) can read and replay the token. The real-world impact depends on what the token authorises, which can't be established passively. It's detected by **R10**. Note that `diagnostics.meethue.com` (allowed) is a different host from the blocked `diag.meethue.com` (§5.2).

### 12.4 Active test: what the main LAN can reach in the IoT VLAN

**Setup:** run from the analysis terminal on 2026-10-11 between 15:29 and 15:31 (NAT'd, main LAN), against the 5 IoT devices only (owned devices [1]).
- TCP: `nmap -sT -Pn --top-ports 1000 -sV --version-light`
- UDP: `nmap -sU` on 123, 1900, 5353, 5540, 6666, 6667, 9999, 20002
- HTTP: `curl` on the open ports

Results are in `derived/active/`.

| Device | Open TCP | UDP (open / open\|filtered) | Notes |
|---|---|---|---|
| Hue Bridge `.26` | 80, 443 (nginx), 8080 (HTTP 501) | 1900 (SSDP), 5353, 5540 | **`GET /api/0/config` answers unauthenticated** with model `BSB002`, `swversion 1978418030`, `apiversion 1.78.0`, bridge ID and MAC (`derived/active/hue_api0_config.json`); `description.xml` likewise. That's standard Hue behaviour, but it's information disclosure to the whole main LAN. |
| Tapo P110M `.23` | 80 (`Server: SHIP 2.0`) | 5353, 5540, 20002 (Tapo discovery) | Local control API |
| Matter switches `.17`, `.20` | **3000** (tcpwrapped, no HTTP response) | 5353, 5540 | Unidentified service on both switches. Worth identifying (vendor OTA/local API?). |
| SwitchBot Hub 2 `.15` | none | 5353, 5540 | Smallest attack surface |

**Interpretation:** this is the **main LAN → IoT** row of the reachability matrix. It's open by design (controllers must initiate) and the results confirm it works. They also show that the rule currently grants **every** main-LAN host, not just the controllers, access to these services (recommendation 8). Combined with §6.1 (Windows PCs fetching Hue descriptions in state A), restricting this direction would remove the remaining lateral path *into* the IoT VLAN. The **IoT → main LAN** row needs a test host on `I0N_IoT` (§9).

**Device versions recorded:** Hue Bridge v2 (`BSB002`), firmware `1978418030`, API `1.78.0`; Tapo `P110M`. This is supporting evidence for the "no updates available" note in the app timeline. It's consistent with the OTA download on 10-10 (§5.3) having already brought the Hue up to date.

---

## 13. Third pass: state D verification capture at `d0c3085` (firmware update and power cycles)

> **In short:** A 70-minute recording during a Tapo firmware update and two device restarts, after the time-server and mDNS changes. The rules caught the update as a change (new domains plus a 1.59 MB download), and the Hue worked again within 2 minutes of a restart. The recording also exposed two router defects, IPv6 lost after a Wi-Fi restart and a 30-second delay for wired devices, both fixed afterwards.

### 13.1 Capture, timeline and coverage

The capture `20261011-164338_tapo` (E70–E74) was taken after deploying `75807a2` (NTP for the IoT VLAN) and `d0c3085` (reflector filter); see `segmentation_report.md` §1.9.
- `eth7`: 16:43:39 → 17:53:42, 17,401 packets.
- `wl0.2`: 16:43:39 → **17:03:11**, 8,694 packets. tcpdump then reported `pcap_loop: The interface disappeared`; the last frames are Broadcom driver events (EtherType `0x886c`) from the router.
- 0 kernel drops on both.

After 17:03:11, the Wi-Fi devices are visible only through broadcast/multicast flooded to `eth7` (DHCP, ARP, ND, mDNS), the firewall log and the router snapshots.

| Time | Event | Source |
|---|---|---|
| 16:43:50 | Tapo update started in the app | E16 |
| 16:44:28 → 16:45:02 | Tapo resolves `ota-download.tplinkcloud.com` and downloads the firmware | pcap, Pi-hole |
| 16:45:15 | Tapo reboots and rejoins: gratuitous ARP for a stale `192.168.1.80`, then DHCP (`.23`), RS | pcap |
| 16:45:16–18 | Tapo: NTP, `security.iot.i.tplinknbu.com`, cloud gateway | pcap, E75, Pi-hole |
| 16:45:36 | Update success, plug reachable | E16 |
| 16:46:04 | Hue Bridge power cycle | E16 |
| 16:46:22 | Hue link up: RS and DHCP DISCOVER, unanswered | pcap |
| 16:46:37 | Hue self-assigns `169.254.11.47` | pcap |
| 16:46:52–55 | `eth7` reaches STP forwarding (topology-change flag in the router's BPDUs); Hue leases `.26` with option 42 | pcap |
| 16:47:04 | HomePod Matter sessions resume: SwitchBot 16:47:04, Hue 16:48:00, Tapo 16:55:16 | pcap |
| 16:47:11 | Hue cloud: `time.meethue.com` (TLS 1.0), broker, `ws` | pcap |
| 16:54:09 | iPhone Hue app talks to the bridge locally (functional check) | pcap |
| **17:03:11** | `wl0.2` torn down; **router RAs and the router's ULA stop** (§13.6). *Not in the timeline* | pcap |
| 17:03:26 | SwitchBot and Tapo rejoin | pcap |
| 17:10:45–51 | Tapo and SwitchBot rejoin again (second wireless restart). *Not in the timeline* | pcap |
| 17:10:54–17:11:02 | **Both Matter switches appear for the first time** (DHCP) | pcap |
| 17:12:29 | Zemismart switch power cycle logged; the timeline notes both switches had failed to reconnect after the earlier router restart | E16 |
| 17:51 | HomePod Matter sessions to all five Matter devices | E81 |

### 13.2 Scenario: Tapo firmware update (new connections after a change)

| | Before (W1–W3, incl. 2 × 24 h) | Update window (W4) |
|---|---|---|
| Domains | `n-aps1-device-api.tplinkcloud.com` (≈1/day), `time.nist.gov` / `pool.ntp.org` | **`ota-download.tplinkcloud.com`**, **`security.iot.i.tplinknbu.com`**, **`aau1-device-cloudgateway.iot.i.tplinknbu.com`**, `pool.ntp.org` |
| Pi-hole queries | 1–6 per window | 13 in 70 min |
| Cloud volume | ≈2 kB up / 5 kB down per day | **1.59 MB down in 34 s** from `ota-download` (18.67.93.58, CloudFront) |
| `IOT_TO_WAN_NEW` | 1 entry in 3 h | 10 entries in three clusters: update and reboot (16:44–16:45), then each Wi-Fi rejoin (17:03, 17:10) |
| TLS | RSA key exchange, AES-CBC (§12.2) | same; JA4 unchanged |

- **Sequence:** a session to the cloud gateway (54.206.12.92, AWS Sydney) was already open when the capture started. The server pushed TLS records at 16:43:51–16:44:23, which fits the update command being relayed from the app. Five seconds later the plug resolved the OTA host and downloaded. After the reboot, every (re)join (16:45, 17:03, 17:10) ran the same sequence: NTP → `security` → cloud gateway. `n-aps1-device-api` wasn't contacted in the 20 min of `wl0.2` coverage.
- **Detection:** R1 fires on the three new domains. R3 fires: 1.59 MB inbound against a ≈5 kB/day baseline. R9 doesn't fire: JA4 tracks the TLS library, which the update didn't change.
- **Classification:** true positive (change), benign. It matches the ground truth (E16). The OTA host presents a public DigiCert chain that validates; the other two endpoints use TP-Link's self-signed chain, as before.
- **Unresolved:** whether `security` and the cloud gateway are new with this firmware or normal on any join can't be told; no pre-update rejoin was captured. The plug still has no forward secrecy after the update (`TLS_RSA_WITH_AES_256_CBC_SHA256` to the gateway).

### 13.3 Hue Bridge power cycle: recovery and boot-only behaviour

**STP adds a 30 s blackout.**
- The Hue's DHCP DISCOVERs from 16:46:22 went unanswered.
- The router's BPDUs on `eth7` carry the topology-change flag from 16:46:53. That means the port entered forwarding only after STP listening + learning (2 × 15 s). The offer followed at 16:46:52.
- Meanwhile the bridge self-assigned `169.254.11.47` and even ARPed for a cloud address (34.117.13.189) from it.
- `firewall-start` turns STP on for every VLAN bridge (`1b52b80`). On `br52`, which has one wired port and so no possible loop, it only costs time. Any wired IoT device would see the same delay after a reboot. **Fixed later in D (`d119636`):** STP is off on the IoT bridge.

**Full function returned within about 2 minutes of power-on:**
- lease at 16:46:55
- cloud at 16:47:11
- HomePod Matter at 16:47:47: first an IPv6 attempt, which the not-yet-ready bridge answered with ICMPv6 errors, then IPv4 from 16:48:00
- the iPhone's local Hue-app session at 16:54:09

**Boot-only features.** None of these appear in either 24 h baseline, because the bridge never rebooted during them:
- **DNS for its time sources:** nine names, the NTP pool host names plus `time.meethue.com`, so R1 fires. The NTP set is now 8 servers (Google ×4, Alibaba ×2, Apple, Cloudflare), against 6 before.
- **A TLS 1.0 handshake without SNI to `time.meethue.com`** (34.117.13.23): ECDHE-RSA-AES128-CBC-SHA, 0.4 s, and the certificate validates (Google Trust Services). It looks like an HTTPS time bootstrap before NTP. TLS 1.0 is deprecated (RFC 8996), and the server still accepts it. **R12** (new) fires, and so does R9 (new JA4).
- **The first observed handshake of the long-lived broker session** (TLS 1.3, with SNI). Its JA4 is new only because neither 24 h capture saw that session open. §12.2 is corrected accordingly: the no-SNI TLS 1.2 fingerprint belongs to a daily 19:25 job to `data.meethue.com` addresses, not to the broker.
- **Elevated polling:**
  - blocked `diag.meethue.com` queries peak at 108/h (§5.2)
  - public NTP runs at 167 requests/h, against 12.5/h over the 24 h segmented capture. The rate decays from 136 Zeek NTP messages in the first 10 minutes to 16–23 per 10 minutes after 17:20. The segmented capture started with the same shape after its network change (62 messages/h in the first hours, ~14/h from 09:00).

**Lesson for the rule set:** R1 and R9 fire on every reboot unless the baseline includes a boot sample, or a reboot signature suppresses them for a few minutes. Useful signatures here are a DHCP DISCOVER from a known MAC, a link-local IPv4 address, or a `time.meethue.com` handshake. Here they are classified as false positives, explained by the ground truth.

### 13.4 NTP after `75807a2`

- The Hue sends NTP to `192.168.107.1` throughout the capture: 20 requests, 16:44:06 → 17:50:59. It had already picked up option 42 at a lease renewal before the power cycle, and the 16:46:55 ACK confirms it. It sends none to `192.168.0.1`, against 158/day before `75807a2`.
- The router answers each request with **ICMP port unreachable** (20). Its NTP daemon is bound to `br0` (`segmentation_report.md` §1.9).
- Public fallbacks answer (183 exchanges), so time sync works.
- **Status:** partly effective. The §5.2 hypothesis still can't be tested until something serves NTP on `br52`.
- **Later in D (`0416f8d`):** option 42 now advertises the main-LAN router address `192.168.0.1`. BusyBox `ntpd -I br0` binds its socket to `br0` with `SO_BINDTODEVICE`, so requests arriving on `br52` are refused here too. `sntp` from a laptop on `I0N_IoT` confirmed it: neither `192.168.107.1` nor `192.168.0.1` answered. **`a738f35`** adds an ntpd instance on every VLAN bridge, including `br52`. It serves the system clock (no peers, never sets the clock), and only runs while the firmware ntpd is up and synced (`segmentation_report.md` §1.10).

### 13.5 mDNS reflector after `d0c3085`

- **Service types in reflected *answers*:** 38 → 5 (`wl0.2`, 20 min) / 7 (`eth7`, 70 min). The remaining types are HomeKit, Matter and Hue, plus the router's own `_alexa._tcp`.
- **Service types *mentioned* at all, including queries:** 55 → 38 / 43. Queries are still reflected, because avahi doesn't filter them.
- Zeek's `weird.log` still flags malformed reflected mDNS from the router (`EDNS_truncated_option`, label errors), as in §12.1.
- **SwitchBot `255.2.0.0`:** 5 packets in 20 min on `wl0.2`, and 23 of the window's 247 `IOT_TO_WAN_NEW` entries. R4 still fires; the egress filter (recommendation 1) is still needed. No ISP ICMP replies were seen this time.

### 13.6 IPv6 router advertisements stop after a wireless restart (**finding, real: configuration defect**)

**Before 17:03:11:**
- The router sent an RA every ~8 s (median), with prefix `fd00:d:e:6b::/64` and RDNSS.
- The router's ULA `fd00:d:e:6b::1` was the source of 546 reflected mDNS packets.

**From 17:03:11 to the end of the capture (50 min):**
- The change happened in the same second that `wl0.2` disappeared.
- The router sent **0 RAs, and 0 packets came from `fd00:d:e:6b::1`**. Meanwhile its link-local address (1,641 packets) and IPv4 address (2,747 packets) carried on.
- Router Solicitations from the Tapo, the SwitchBot and both switches at 17:10–17:11 went unanswered.

**Effect:**
- Devices that joined after 17:03 got no ULA. Switch `…:6b` advertises only IPv4 and link-local in mDNS (it advertised its ULA in the app capture), and the Tapo stopped advertising its ULA after the 17:10:45 rejoin.
- The Hue kept its existing address, which stays valid until its lifetime runs out.
- Nothing broke functionally, because Matter ran over IPv4 (§13.7).

**Most likely cause, from the repo:**
- The VLAN ULA is added to the bridge only on `dnsmasq` start/restart (`service-event`) and in `dhcpc-event`.
- The wireless restart rebuilt the IoT SSID's interface and evidently removed the address from `br52`.
- dnsmasq's `constructor:br52` RA then had no prefix to advertise.
- The same code path serves the roommate VLAN, which wasn't tested (out of scope).
- To confirm: `ip -6 addr show br52` before and after a `service restart_wireless`.

**Detection:** R11 (RA silence, or router ULA missing).

**Confirmed and fixed:** on the router, `restart_wireless` removes the static ULAs from all three bridges (`br0`, `br56`, `br52`), not just the IoT one. **`1b36092`** (later in D) moves the assignment into an idempotent helper (`ula_assign.sh`), which `service-event-end` now also runs after network/wireless/LAN restarts. dnsmasq picks the addresses up again through netlink. It's verified by a router-side check, not a new capture (`segmentation_report.md` §1.10).

### 13.7 Matter control after the change

**Controller sessions:**
- No Matter traffic at all from 16:43:39 to 16:47:04, and the 16:43 conntrack snapshot holds no Matter session (E78).
- The HomePod re-established sessions to the SwitchBot (16:47:04), the Hue (16:48:00) and the Tapo (16:55:16, 10 min after its reboot).
- At 17:51 it held sessions to all five Matter devices (E81).
- No IoT → main-LAN packet was dropped (§13.8), so the §5.4 timeout fix holds.

**Transport moved from IPv6 to IPv4.**
- In the segmented and app captures, the HomePod reached the Hue, Tapo and switches over the ULA (segmented: 9,400 / 30,740 / 2,754 packets).
- In the tapo capture, everything is IPv4 (Hue 850, Tapo 132, SwitchBot 36 packets), apart from the Hue's failed 5-packet IPv6 attempt.
- The shift starts before the RA loss: the Tapo still advertised its ULA when the HomePod chose IPv4 at 16:55. So §13.6 doesn't explain it on its own, but it does stop IPv6 Matter from coming back for any device that rejoins. The HomePod's address choice after re-subscribing is the open question.

**Matter switches offline at capture start (open).**
- Neither switch sent a frame on either interface until 17:10:54. Both rejoined together during the second Wi-Fi rejoin, ~1.5 min before the logged power cycle.
- At 14:01 the iPhone still had a session to `.17` (E22). The outage began between 14:01 and 16:43, a span with no capture or firewall log.
- Candidate cause: the switches lost their association during the deployment's service restarts and didn't rejoin until a later wireless restart. The router syslog for that afternoon would settle it (recommendation 13).
- This is the open gap for metric 4.
- **Resolved (owner's account, now also recorded in the action log, E16):** the owner had restarted wireless before the capture, and the switches didn't rejoin until a later restart. After a power cycle they haven't dropped again. It was a one-off reconnection failure after a wireless restart, not an effect of the D changes.

### 13.8 Firewall evidence and log completeness (tapo capture)

| Rule (FORWARD) | 16:43 (E76/E77) | 17:51 (E79/E80) | Δ |
|---|---|---|---|
| `IOT_TO_WAN_NEW` LOG, IPv4 | 60 | 326 | +266 |
| IoT → Pi-hole DNS (UDP) | 79 | 258 | +179 |
| main LAN → IoT ACCEPT, IPv4 | 79 | 1,135 | +1,056 |
| IoT → main LAN ESTABLISHED/RELATED, IPv4 | 0 | 1,283 | +1,283 |
| `IOT_TO_LAN_DROP` LOG / DROP, IPv4 and IPv6 | 0 / 0 | 0 / 0 | 0 |
| main LAN → IoT / replies, IPv6 | 0 / 0 | 5 / 5 | +5 / +5 |
| `IOT_TO_WAN_NEW` IPv6; NAT6 for the IoT ULA | 0 | 0 | 0 |

- **Before snapshot:** only ~11k packets had passed through FORWARD in total at 16:43, so the firewall had been reloaded minutes earlier. The deltas therefore describe the capture window almost exactly.
- **Log completeness:** E75 holds 247 entries against the +266 delta, so ~19 entries fell into the 17:14:30–17:31:07 syslog gap (~1.2/min, against ~1.5–2/min either side of it). A firewall restart inside the window would need 100+ lost entries, so the delta is valid.
- **Entries by source:** Hue 210 (185 NTP, 25 TCP 443), SwitchBot 27 (23 to `255.2.0.0`, 3 MQTT, 1 NTP), Tapo 10. All IPv4.
- **Rate limit:** the log ran at up to 74 entries per 5 min during the Hue's boot, under the 30/min limit.

---

## 14. Fourth pass: active test from the IoT VLAN

> **In short:** A laptop on the IoT Wi-Fi played a compromised device and scanned the network. Household computers were unreachable apart from DNS and ping, and the scan was logged. But the router itself was too open (SSH and other services answered), and a device could bypass Pi-hole by asking another DNS server. Both were fixed in state E.

### 14.1 Setup

- **Test host:** a MacBook joined to `I0N_IoT` (E90, `wifi.txt`): `192.168.107.8`, ULA `fd00:d:e:6b:4b0:2628:1856:4090`, private MAC `b2:1c:d7:ba:85:9d`. It got Pi-hole as its DNS server for both address families (`context.txt`).
- **Window:** 2026-10-11 21:57:08 → 22:11:48. Router counters were snapshotted just before and after (E89), and the firewall log was saved (E88).
- **State:** D as deployed then (up to `a86c9e2`), i.e. before `6d35945` changed option 42 to each VLAN's own gateway address.
- **Scope:**
  - main LAN, router, and the router's own VLAN 114 address (`192.168.114.1`)
  - no host in VLAN 114 was scanned
  - no capture was running
- **Commands** (`terminal_history.txt`):

| Step | Target | nmap |
|---|---|---|
| 1 | main LAN /24 | `-sn -PE` (ICMP echo only) |
| 2 | main LAN /24 | `-Pn -sS -T4 --top-ports 100 --max-retries 1 --min-rate 1000` |
| 3 | `.1 .2 .8 .13 .22` | `-sU -p 53,123,137,161,1900,5353,5540` |
| 4 | `192.168.107.1`, `192.168.0.1` | `-sS -p- --min-rate 2000 -sV --version-light`; `-sU` on 53, 67, 123, 161, 1900, 5351, 5353 |
| 5 | router + main-LAN ULAs | `-6 -sS --top-ports 100` |
| 6 | `192.168.114.1` (router only) | `-sS --top-ports 100` |
| 7 | internet | `dig @1.1.1.1`, `nc -vz 1.1.1.1 853` (DNS bypass) |

### 14.2 Results: IoT → main LAN (contained)

| Test | Result | Policy |
|---|---|---|
| ICMP echo sweep | **11 hosts answer** (`.1 .2 .8 .9 .10 .13 .14 .15 .20 .22 .225`) | Allowed on purpose (`a3673d9`). It exposes the main-LAN host inventory to any IoT device. |
| TCP top-100, 256 addresses | **254 addresses fully filtered**. Open: only `192.168.0.8:53` (Pi-hole) and `192.168.0.1:22` (router, see 14.3) | `br52 → br0` DROP +58,771 packets; `IOT_TO_LAN_DROP` logged 155 of them (10/min limit) |
| UDP on key hosts | Only Pi-hole 53 answers (plus router NTP, 14.3); everything else `open\|filtered` (no response) | Same DROP rule |
| IPv6, main-LAN ULAs (`::1 ::2 ::8 ::13`) | All 100 ports filtered on every host. `ping6 fd00:d:e:f::8` answers (echo allowed) | v6 DROP +598. The router accepted 2 TCP-53 SYNs to Pi-hole's ULA (rule 3), but Pi-hole didn't answer TCP/53 over IPv6 (Pi-hole side; UDP works). **Later shown to be an nmap artefact:** `dig +tcp` over IPv6 gets answered (§15.4). |

Lateral reachability from the IoT VLAN to main-LAN **hosts** is blocked, apart from the two documented exceptions (DNS to Pi-hole, ICMP echo). The pre-segmentation exposure (§6.1) is gone.

### 14.3 Results: IoT → router (not contained) (**finding, real**)

Traffic to the router's own addresses goes through the INPUT chain, which the FORWARD policy (`firewall-start`) doesn't cover.

| Router address | Open TCP | UDP |
|---|---|---|
| `192.168.107.1` (IoT gateway) | **22**, 53, 81, **8200**, 60000. 35,905 ports closed (RST); 29,625 filtered. The filtered ones are mostly a side effect of `--min-rate 2000` with one retry (nmap hit its retransmission cap). | 53 DNS, 67 DHCP, 123 NTP, 5353 mDNS open; 161, 1900, 5351 closed |
| `192.168.0.1` (main-LAN address) | **22 only**, everything else filtered | **123 only** |
| `192.168.114.1` (roommate gateway) | **22**, 53, 81, 444 (top-100); 96 ports closed (RST), so not dropped | not tested |
| `fd00:d:e:6b::1` (IPv6) | none in top-100 (all filtered) | not tested |

- **SSH is reachable from the IoT VLAN on every router address.**
  - `sshd_enable=1` is the web UI's "LAN & WAN" setting. Merlin then adds an interface-less `-A INPUT -p tcp --dport 22 -j ACCEPT` (`rc/firewall.c`). That's INPUT rule 13 in E89, +24 packets during the test.
  - `sshd_pass=1` also allows password logins.
  - So SSH is reachable from both VLANs and, by the same rule, from the WAN (not tested; out of scope). The firmware's brute-force protection (`PTCSRVWAN`) is the only gate.
- **Other router services reachable from the IoT VLAN:**
  - DNS on the router itself (`192.168.107.1:53`, TCP and UDP): a resolver that isn't Pi-hole
  - the DLNA media server (`dms_enable=1`, port **8200**)
  - haproxy on 81, 60000 and (via `.114.1`) 444, identified by the owner. Version detection reported `tcpwrapped` for all of them.
  - The web UI (80/8443) isn't reachable.
- **Why the three addresses differ:**
  - `192.168.0.1` drops everything except SSH and NTP (`firewall-start` rule).
  - `192.168.114.1` resets closed ports, so its traffic is accepted further down INPUT.
  - The deciding rules sit in firmware sub-chains (`SDN_FI`, `PTCSRVWAN`) that the counter snapshots don't expand.
- **The NTP fix (`a738f35`) works from the client side:** `sntp 192.168.107.1` and `sntp 192.168.0.1` both answered (offset −0.013 s), and INPUT UDP 123 on `br52` counted +33.

### 14.4 Results: DNS bypass (simulated scenario)

- `dig @1.1.1.1 example.com` resolved and `nc -vz 1.1.1.1 853` (DoT) connected. Nothing forces IoT DNS through Pi-hole: any device with a hardcoded resolver or DoT would bypass the DNS filter.
- **Detected:** both probes appear in `FW_iot_active.log` as `IOT_TO_WAN_NEW` (`DST=1.1.1.1 … UDP DPT=53` and `TCP DPT=853`, 22:11:48). That's **R7 firing on a controlled test**; it had no true positives before (§5.7).
- The IoT devices themselves still never bypassed DNS in any capture (§3.1).

### 14.5 Other observations

- **Two more clients on `I0N_IoT`** (E88), both with randomised (locally administered) MACs. **Identified:** they're the owner's other Apple devices, which got the IoT passphrase through iCloud Keychain sync.
  - `1e:b2:de:92:90:28` at `192.168.107.18` (ULA `…:0c69:9d0d:a992:3aeb`). It was present from the router's boot until the end of the log: 245 WAN connections (v4 and v6) and 11 dropped attempts to main-LAN services (e.g. TCP 7000, AirPlay, on the HomePod and `.2`). That's typical of an Apple phone or tablet.
  - `c2:c0:9a:ec:14:36` at `.19`, seen once at 21:52.
  - Neither is in the device inventory (§2), and they weren't analysed further. **Side finding:** Keychain sync silently puts general-purpose devices onto the IoT SSID. Those devices get IoT-level restrictions, and their traffic mixes into the IoT logs (here 245 `IOT_TO_WAN_NEW` entries). Removing the IoT network from Keychain, or giving it a separate passphrase, keeps the IoT logs clean.
- **First IPv6 IoT-VLAN → WAN traffic:** the test host and `.18` used NAT6 (`IOT_TO_WAN_NEW` v6 +152; NAT6 rules +1,142 / +1,188). The negative result in §5.7 ("IoT IPv6 to WAN: 0") still holds for the IoT devices themselves.
- **The log's first 20 entries are stamped `Jan 1`:** they were written after a reboot, before NTP had set the router clock. Syslog timestamps from early boot can't be trusted.

### 14.6 Assessment

| Path | Result |
|---|---|
| IoT → main-LAN hosts (v4, v6) | **Blocked**, except the documented DNS-to-Pi-hole and ICMP-echo exceptions. Detected by R2 (`IOT_TO_LAN_DROP`) and the DROP counters: the simulated lateral scan is a true positive. |
| IoT → router | **Not contained in D:** SSH (all addresses), router DNS, DLNA and haproxy (81/444/60000). **State E** (`5b0e391`) restricts the IoT bridge to DHCP/NTP/mDNS/ICMP and drops SSH on every VLAN; **verified in §15.3** (recommendations 14, 15). |
| IoT → VLAN 114 | Only the router's own address was tested; it exposes the same class of router services. VLAN 114 hosts weren't tested (scope). |
| IoT → internet DNS | **Not blocked in D**, but detected (R7). **State E** redirects it to Pi-hole (logged as `IOT_DNS_REDIRECT`) and drops DoT/DoQ; **verified in §15.4**, including IPv6 TCP in the second follow-up (recommendations 16, 18). |

---

## 15. Fifth pass: state E re-test from the IoT VLAN

> **In short:** The same laptop repeated the tests after the router was locked down (state E). The router now answers only the four services devices need, every DNS query is forced through Pi-hole over IPv4 and IPv6, and the fibre modem's admin page can't be reached from the IoT network. No real device was affected.

### 15.1 Setup

- **State:** E as deployed (repo `6aa7835`), after a router reboot. Same test host as §14: `192.168.107.8`, ULA `fd00:d:e:6b:4b0:2628:1856:4090`, private MAC `b2:1c:d7:ba:85:9d`.
- **Evidence:** the firewall log (E91), router snapshots before and after (E92), and the test outputs plus the router-side restart check (E93).
- **Sequence** (router clock, AEDT):

| Time | Step | Evidence |
|---|---|---|
| 23:55:10 | Router snapshot "before" (state after boot) | E92 `hardening_before/*_2355.txt` |
| 23:55–23:56 | `service restart_wireless`, then STP, IoT ULA and rule check | E93 `router_term_out.txt` |
| 23:56:10–14 | r1: router TCP select ports on `192.168.107.1`, `192.168.0.1`, `192.168.114.1` (`-sS`) | E93 `r1_router_tcp.*` |
| 23:56:14–00:02:13 | r2: all 65,535 TCP ports on `192.168.107.1` (`--min-rate 1000 --max-retries 2`) | E93 `r2_router_alltcp.*` |
| 00:02:16–21 | r3: UDP 53, 67, 123, 1900, 5351, 5353 on `192.168.107.1` | E93 `r3_router_udp.*` |
| 00:02:21–22 | r4: IPv6 TCP 22, 53, 80, 8200 on `fd00:d:e:6b::1` | E93 `r4_v6.*` |
| 00:02:23–30 | DNS probes, `nc` to `1.1.1.1:853` and `192.168.0.1:22`, `sntp`, `ping` | E93 `terminal_history.txt`, E91 |
| 00:02:36 | Router snapshot "after" | E92 `hardening_after/*_0002.txt` |

- **Commands:** `terminal_history.txt` holds outputs only. The nmap commands come from each XML file's `args`; the rest follow the re-test plan and match the logged packets. One output isn't in the plan: two A records (`104.20.23.154`, `172.66.147.243`). These are the current addresses of `example.com`, so this was a control lookup. It doesn't appear in the redirect counters, so it went straight to Pi-hole through the default resolver.
- **Scope:** as in §14. Only the router's own VLAN 114 address was probed; no host in VLAN 114 was scanned.

### 15.2 Bridge rebuild: STP, ULAs and rule survival

| Check | After boot (23:55) | After `restart_wireless` (E93) | After the test (00:02) |
|---|---|---|---|
| `stp_state` `br0` / IoT `br52` / roommate `br56` | 1 / 0 / 1 | 1 / 0 / 1 | 1 / 0 / 1 |
| IoT ULA `fd00:d:e:6b::1` on `br52` | present | present | present |
| `br56` / `br0` ULAs | present | not dumped | present |
| `ntpd_vlan` cron job | present | not dumped | present |

- **The bridges really were rebuilt:** the ifindex of `br52` went from 91 to 121, `br56` from 80 to 110, and every `wl*` interface was renumbered; `br0` stayed at 32. That matches the earlier observation that `restart_wireless` rebuilds the VLAN bridges but not `br0`.
- **STP:** `bridge_stp.sh` restored STP on `br0` and the roommate bridge, and the IoT bridge stayed off. This confirms that rebuilt bridges come up with STP off. The SDN bridge setup isn't in the open-source tree, so this observation is the evidence for it.
- **ULAs:** `ula_assign.sh` restored all three router ULAs (`1b36092`), so the §13.6 condition (R11) didn't recur.
- **The hardening survives the rebuild without a firewall reload.** The `IOT_INPUT` counters kept rising across the restart (380 → 705 → 133k packets), so the filter table wasn't reloaded. The firmware rebuilt its own `SDN_FI` chain (its counters reset), but `IOT_INPUT` stayed at INPUT position 1 for both v4 and v6, so the firmware rules never see IoT traffic.

### 15.3 Results: IoT → router (contained)

| Router address / probe | D (§14.3) | E |
|---|---|---|
| `192.168.107.1`, all TCP | **22**, 53, 81, **8200**, 60000 open; 35,905 closed (RST) | **All filtered** except 53, which **Pi-hole** answers through the redirect (reply TTL 63, against 64 for the router's own replies) |
| `192.168.0.1`, select TCP | **22** open | All filtered; 53 redirected to Pi-hole |
| `192.168.114.1`, select TCP | **22**, 53, 81, 444 open | All filtered; 53 redirected to Pi-hole |
| `192.168.107.1`, UDP | 53, 67, 123, 5353 open; 1900, 5351 closed | 53 redirected (TTL 63); 67 DHCP and 123 NTP from the router (TTL 64); 5353 mDNS (TTL 255); 1900 and 5351 now **dropped and logged** (`IOT_TO_ROUTER_DROP`) |
| `fd00:d:e:6b::1`, TCP 22/53/80/8200 | top-100 all filtered | all filtered |
| `192.168.0.1:22` | open (§14.3; `sshd_enable=1`) | **timeout**, logged as `IOT_TO_ROUTER_DROP` (00:02:26) |
| `sntp 192.168.107.1`, `ping 192.168.107.1` | answered | answered (offset +0.001 s; 2/2 echo replies) |

- **Counters (E92):**
  - `IOT_INPUT` v4 DROP: 43 → ~131k packets, mostly r2. LOG: 12 → 92 (10/min limit).
  - v6 DROP: 25 → 178.
  - Accepts during the window: mDNS +727, DHCP +15, NTP +14, ICMP +13, IGMP +4.
- **No real IoT device hit the drop.** Every `IOT_TO_ROUTER_DROP` entry (48 v4, 49 v6) comes from the test host. None comes from `.15`, `.17`, `.20`, `.23` or `.26`, so the devices only use services that `IOT_INPUT` accepts.
- **SSH rules:** the per-bridge SSH DROP on `br52` counts 0 because `IOT_INPUT` handles that bridge first; it stays as a backstop. The roommate bridge's rule is in place (in4 rule 3, in6 rule 4) but wasn't exercised, since there's no owned host in VLAN 114.

### 15.4 Results: DNS enforcement

| Probe | Result | Evidence |
|---|---|---|
| `dig @1.1.1.1 diag.meethue.com` | `0.0.0.0` (Pi-hole's block answer) | `IOT_DNS_REDIRECT` 00:02:23; v4 UDP DNAT +3 for the run |
| `dig @192.168.107.1 diag.meethue.com` | `0.0.0.0` | `IOT_DNS_REDIRECT` 00:02:23 |
| `dig AAAA @2606:4700:4700::1111 diag.meethue.com` | `::` | `IOT_DNS_REDIRECT` (v6) 00:02:23; v6 UDP DNAT +1 |
| TCP 53 to the three router IPv4 addresses (r1, r2) | answered by Pi-hole | v4 TCP DNAT +19; FORWARD TCP 53 to Pi-hole +38 |
| `nc 1.1.1.1 853` (DoT) | **timeout** | FORWARD TCP 853 DROP +3; still logged as `IOT_TO_WAN_NEW` ×3, so R7 keeps firing |
| TCP 53 to `fd00:d:e:6b::1` (r4) | **filtered, not redirected** | v6 TCP DNAT 0; v6 FORWARD TCP 53 to Pi-hole 0 |

- **IPv4 DNS is fully enforced**: UDP and TCP, to internet resolvers and to every router address. **IPv6 UDP to an internet resolver is redirected too.** The §14.4 bypass is closed for these paths.
- **Gap in this run (resolved by the second follow-up below): the IPv6 TCP redirect never fired.** For the router's own address this fails closed: `IOT_INPUT` drops the SYN. But IPv6 TCP 53 and DoT to *internet* resolvers weren't tested. If the IPv6 TCP DNAT doesn't work at all, `dig +tcp @2606:4700:4700::1111` would leave through NAT6, because IoT IPv6 to the WAN is accepted (fw6 rule 12). That would be a bypass.
  - Pi-hole didn't answer TCP/53 over IPv6 in §14.2, so a working redirect can also end in a timeout. The check therefore has to read the counters, not just the answer.
  - Follow-up: recommendation 18.
- **Follow-up run** (E93 `hardening_dns6_retest.txt`, file time 2026-10-12 00:28; `nslookup diag.meethue.com <server>` from the test host). Every query returned Pi-hole's block answers (`0.0.0.0` and `::`):

  | Server | Meaning |
  |---|---|
  | `fd00:d:e:f::8` (Pi-hole) | control: direct, allowed path |
  | `2606:4700:4700::1111` (Cloudflare) | internet resolver: redirected (repeats §15.4) |
  | `fd00:d:e:f::1` (router, main-LAN ULA) | router address: redirected |
  | `fd00:d:e:f::1234` (**no such host**) | answered anyway, so the query was intercepted. A client on the main LAN would get no answer, because the address is on-link there and neighbour discovery fails. So the answer also proves the queries came from the IoT VLAN. |

  - **IPv6 UDP DNS is therefore redirected for any destination.**
  - **IPv6 TCP was still untested at this point** (closed by the second follow-up below). `nslookup` uses UDP, and this run has no router counters, so it doesn't exercise the TCP DNAT that stayed at 0 in r4. DoT over IPv6 wasn't tested either.
  - **Practical risk is low.** A resolver is only reached over TCP after a truncated UDP answer, and UDP is redirected, so only a client that uses TCP-only DNS or DoT over IPv6 could slip past. Such a client would still be logged by R7 (`IOT_TO_WAN_NEW`, v6).
- **Second follow-up: closed** (E93 `hardening_dns6_ont_test_2.txt`; router counters just before and after in E94; firewall log E95):

  | Probe | Result | Router counter |
  |---|---|---|
  | `dig +tcp AAAA @2606:4700:4700::1111 diag.meethue.com` | `::`, `aa` flag, **EDE 15 "Blocked (gravity)"**: Pi-hole's answer, not Cloudflare's | v6 nat TCP 53 DNAT 2 → 4 (+2 for the two queries), LOG +2 |
  | `dig +tcp AAAA @fd00:d:e:6b::1 diag.meethue.com` | same Pi-hole block answer | (included above) |
  | `nc -6 -vz 2606:4700:4700::1111 853` (DoT) | **timeout** | E95: 9 SYNs logged as `IOT_TO_WAN_NEW` (01:00:09 → 01:01:16, retransmissions), none answered. The v6 TCP 853 DROP counter row wasn't in the dump (the suggested `head -4` cut it off) |

  - **The IPv6 TCP redirect works**, to an internet resolver and to the router's own address. Pi-hole also answers TCP over IPv6.
  - So the two earlier negatives were artefacts of nmap's raw IPv6 SYN probes, not of the rules or of Pi-hole: no DNAT in r4, and no answer from Pi-hole in §14.2. The exact cause wasn't determined; real TCP clients behave as intended.
  - **DoT over IPv6 is blocked:** the connection times out, and the log shows the SYN being retransmitted for a minute without an answer. That fits the v6 853 DROP rule, which sits below the LOG rule.
  - **Timeline from E95:**
    - 00:48:31: an ICMP check to the ONT.
    - 00:58:24: an earlier run of the same DNS/DoT commands (output not saved). These are the 2 v6 TCP DNATs already in the "before" counters.
    - 00:58:54–00:59:29: the saved run's `nc` to the ONT, 10 SYNs.
    - 01:00:09: the saved run's `dig +tcp` ×2, both logged as `IOT_DNS_REDIRECT` (v6, TCP), then `nc -6 … 853`.
  - **IoT DNS enforcement is complete:** IPv4 and IPv6, UDP and TCP, to any destination, and DoT dropped on both families.
- **No real device was redirected:** all 6 `IOT_DNS_REDIRECT` entries come from the test host. The devices already use Pi-hole (§3.1).

### 15.5 Results: IoT → main LAN (rules unchanged; incidental evidence)

- **Hairpin through the public address doesn't bypass segmentation.** From 00:00:04 an app on the test host repeatedly tried to reach a main-LAN service that the router port-forwards on TCP 38443:
  - **IPv4:** 45 `IOT_TO_LAN_DROP` to `192.168.0.13:38443`. If the app used the public address, NAT loopback (`VSERVER`) rewrote the destination to `.13` before FORWARD, where the IoT → main-LAN drop caught it. The log can't show whether it used the public or the private address; it was dropped either way.
  - **IPv6:** 48 `IOT_TO_ROUTER_DROP` to the router's WAN-side address (`<WAN-RA>` /64). The IPv6 port forwards (`IPv6_PF.sh`) DNAT only on `-i eth1`, so from inside the packet goes to INPUT, and `IOT_INPUT` drops it.
- **SSH to Pi-hole** (`192.168.0.8:22`, 00:00:03, 3 SYNs; not in the plan): dropped and logged.
- **`.18`** (the owner's Apple device, §14.5): AirPlay (TCP 7000) attempts to `.13` and `.2`, dropped, as in D.
- FORWARD `br52 → br0` DROP: v4 +572, v6 0.

### 15.6 Device functions and other observations

- **Devices after the bridge rebuild:**
  - The after snapshot holds conntrack entries for all five IoT devices: `.15`, `.17` and `.20` (IGMP/mDNS), `.23` (DNS via Pi-hole, cloud gateway `54.206.12.92:443`) and `.26` (3 established TLS sessions to its cloud).
  - Main LAN → IoT accepts rose +1,277 (v4) / +434 (v6) in 7 minutes, so the controllers kept talking to the devices.
  - **Owner check (statement, no artefact):** all smart-home apps (Home, Hue, Tapo, SwitchBot) still work, with the HomePod back on the main LAN.
- **Hue public NTP:** 17 logged NTP flows to 8 public servers in 4 minutes after the rebuild (Google ×4, Alibaba ×2, Apple, Cloudflare). This looks like the same resync pattern as §13.3. The `IOT_INPUT` NTP accepts (+14) include the test host's `sntp`, so whether the Hue also used `192.168.107.1` can't be told from this evidence. The §5.2 hypothesis still needs a capture.
- **Client `192.168.107.13` was the HomePod** (`ac:bc:b5:d3:d1:dd`, owner-confirmed), normally at `192.168.0.22` on the main LAN. It had joined `I0N_IoT`, where it talked only to Apple and CDN endpoints. The owner moved it back after the test.
  - **Finding (configuration drift, real):** the home hub, which is also the Matter controller and the Thread border router (§2), silently moved into the restricted segment, presumably through the Keychain-synced IoT passphrase (§14.5).
  - While it was there, its traffic to the IoT devices stayed inside the VLAN, so it doesn't show in the FORWARD counters. Its own connections to the main LAN fell under the IoT restrictions, which is a functional risk for a hub.
  - **Effect on this test:** the "main LAN → IoT +1,277" figure above reflects other main-LAN clients (e.g. the iPhone), not the hub.
- **Test host background:** pings every ~10 s to `192.168.1.1`, `192.168.1.18`, `fd01:d:e:f::1` and `fd01:d:e:f::18`. None of these is a local network, so they leave through the WAN and are logged as `IOT_TO_WAN_NEW`. This is the laptop's own traffic, not device behaviour.
- **WAN-side IPv6:** `eth1` holds a SLAAC address from the ISP's RA (`<WAN-RA>` /64) with preferred lifetime 0 (deprecated) and a 2 h valid lifetime (E92 `ipv6_addr_*`). So the router does learn the WAN link prefix (`segmentation_report.md` open item 5).
- **IoT → ONT management (finding, real):** `ONT_Route.sh` adds an explicit accept only for `br0 → 192.168.255.0/30`, plus a route and SNAT for that subnet out of `eth1`. IoT → WAN is allowed in general, so the ONT's management address was reachable from the IoT VLAN; the owner confirmed it after this pass. Blocked from every VLAN in `904f54d` (recommendation 19).
  - **Verified** (E93 `hardening_dns6_ont_test_2.txt`, E94): `nc 192.168.255.1 80` from the test host **times out**. The `br52` ONT DROP rose 23 → 49 (+26) over the window, the roommate rule stayed at 0, and the main-LAN accept kept counting (26 → 55), so main-LAN access still works.
  - **Attribution (E95):** every logged ONT attempt comes from the test host (`b2:1c:d7:ba:85:9d`): an ICMP check at 00:48:31 (only its first echo is logged, the rest share its conntrack entry) and the `nc` SYNs at 00:58:54–00:59:29. No IoT device tried to reach the ONT.

### 15.7 Assessment

| Path | D (§14) | E (this pass) |
|---|---|---|
| IoT → main-LAN hosts | Blocked (DNS and echo exceptions) | Still blocked, including a hairpin via the public address and SSH to Pi-hole |
| IoT → router | **Not contained**: SSH, DNS, DLNA, haproxy | **Contained**: only DHCP, NTP, mDNS and ICMP answer, on every router address, v4 and v6 |
| IoT → internet DNS | **Bypass possible**, detected (R7) | **Redirected to Pi-hole** for IPv4 and IPv6, UDP and TCP, to any destination; DoT dropped on both families and still logged (R7) (§15.4, both follow-ups) |
| IoT → ONT management | reachable (untested then; owner-confirmed later) | **Blocked** (`904f54d`): `nc` times out, `br52` drop counter rising; main LAN keeps access (§15.6) |
| STP / ULAs after a wireless restart | STP reset on VLAN bridges; ULAs lost | Restored automatically (`bridge_stp.sh`, `ula_assign.sh`) |
| Real IoT devices | – | None in any drop or redirect log; all five present after the rebuild; apps work (owner) |

**Metric 3 is met within scope:** every unauthorised inter-segment path tested from the IoT VLAN is blocked. The IoT → ONT path found afterwards is closed too (`904f54d`), and DNS is enforced on both address families.

---

## 16. Sixth pass: simulated volume-upload scenario (exfiltration to cloud storage)

> **In short:** We simulated data theft: the laptop uploaded 100 MB to a cloud-storage account in one go, then 30 small files slowly. The bulk upload was caught at once, 70× over the volume threshold. The slow drip stayed under the network-wide volume threshold, as predicted, but the per-device volume rule and the connection-count rule caught it. The cloud folder listing confirms exactly what was sent.

### 16.1 Setup and deviations from the run sheet

The run sheet (`planning/volume_upload_runsheet.md`) fixed the method and the detection criteria before the run.

- **Test host:** the MacBook on `I0N_IoT`, standing in for a compromised IoT device.
  - It now has a **new private MAC, `42:e3:fe:60:6c:d9`**, IPv4 **`192.168.107.13`** and ULA `fd00:d:e:6b:44e:444d:a1f5:d496` (E108 `wifi.txt`, `dnsmasq-1.leases`).
  - In §15, `.13` was the HomePod, so everything here is attributed **by MAC**.
- **Target:** the owner's own MEGA account (MEGAcmd `mega-put`), carrying random data only. Cloud storage such as MEGA is a documented staging point for stolen data, which makes the target realistic.
- **Start state:** clean. The IoT network was out of iCloud Keychain, and no Apple device other than the test host was on it. The lease file lists exactly the five baselined devices, the Meross plug (`.2`), the VFD clock (`.22`) and the test host.
- **Quieting:** iCloud Keychain off, Low Power Mode on, and 4 background apps and 14 launchd jobs stopped, including the iStat ping monitor (E108 `disabled_services.txt`).
- **Capture:** E96–E100, 17:26:58 → 18:28:22, `wl0.2` 206,146 and `eth7` 24,364 packets, **0 kernel drops**, offload disabled.
  - It was started in the foreground and stopped by hand, so not with `-d 60m`. The window is the same.
- **Timeline** (E108 `timeline.txt`):
  - quiet period 17:27:08–17:37:33;
  - Run A 17:37:33 → transfer end 17:41:31 (the logged "Run A end" of 17:40:50 came 41 s before the transfer finished; Zeek `conn.log` gives the real end);
  - Run B 17:46:07–18:17:02.
- **Deviations:**
  - The MEGA folder listing (E108 `mega-ls.txt`, `mega-ls -l`) was recorded after the run, not during it. It is checked against the capture in 16.2.
  - **The firewall log (E106) starts at 17:59:45.** Another syslog rotation; the quiet period, Run A and the first 13 minutes of Run B aren't in it. The counters (E107) cover the whole window.
  - The VFD clock was power-cycled at about 17:41:44 (no timeline entry; seen from its Wi-Fi re-association) and again in a separate capture (E101–E105, 18:43:53–18:44:33). Both are covered in 16.6.
- **Tools:**
  - New tool `tools/volume_eval.py` (E109): IP-layer bytes per device per minute from the pcaps, counted on each device's home interface. MEGA flows are matched by every address a `*mega*` name resolved to, or that carried a MEGA SNI, in this capture's Zeek logs (16 addresses). Output: `derived/analysis/upload_eval.json`.
  - Zeek 8.0.11 (the toolchain was re-installed with `tools/setup_env.sh`).

### 16.2 What was actually sent (ground truth from the capture)

| Run | Connections | IP bytes on the wire | Of which | Payload check |
|---|---|---|---|---|
| **A: bulk** (100 MiB file) | **8 parallel TLS connections** over IPv6 to one storage node (`gfs302n501.userstorage.mega.co.nz`, `2a0b:e41:1::11`), 17:37:50 → 17:41:31 (221 s) | **143.39 MB** | **30.72 MB TCP retransmissions** (23,856 segments; the 2.4 GHz uplink was the bottleneck) | unique TCP payload **104,985,483 B** = the 104,857,600 B file + 0.12 % TLS/HTTP overhead |
| **B: slow** (30 × 16 KiB) | an upload roughly every 62 s, each using **~13 short TCP connections** (329 to storage nodes, 12 to the API) | **1.10 MB** MEGA-attributed | — | 491,520 B of payload, so **2.2× wire overhead**: the planned 0.96 MB/h became 2.1 MB/h on the wire |

- **Cross-check:** the frames sent by Wi-Fi clients in the capture total 154.11 MB. The router's `wl0.2` receive counter rose 149.86 MB between its snapshots. Those agree within 3 %; the capture counts Ethernet framing, and the windows differ by about a minute.
- **Listing (E108 `mega-ls.txt`):** the account's `upload_run/` folder holds exactly the planned 31 files, so every upload landed and nothing extra did.
  - **Sizes:** `bulk.bin` is 104,857,600 B, the same figure the payload reconstruction arrived at independently. `s_1.bin` … `s_30.bin` are 16,384 B each, 491,520 B in total.
  - **Times:** the dates of `s_1` … `s_30` run 17:46:11 → 18:15:52, about 61 s apart. Each file's upload data shows up in the capture **0.3–1.5 s after its listed time**, so all 30 slow uploads can be matched one to one. 24 used a fresh set of 8–9 parallel connections. The other 6 (`s_9`, `s_12`, `s_15`, `s_18`, `s_22`, `s_30`) went over only 1–3 connections, mostly ones that were already open.
  - `bulk.bin` is dated 02:37:00. That is the file's own modification time (MEGA keeps it), i.e. when the test file was generated, not when it was uploaded; Run A's transfer starts at 17:37:50 in the capture.
- **MEGA in DNS** (Pi-hole, E108): `g.api.mega.co.nz` and the storage nodes `gfs302n501` / `gfs302n551.userstorage.mega.co.nz`, all from the test host. MEGA's telemetry host `reqstat.api.mega.co.nz` is **blocked by gravity**; it didn't affect the upload.

### 16.3 Volumes per window (test host; `upload_eval.json`)

| Window | Minutes | Host total | MEGA-attributed | Host rate | MEGA rate |
|---|---|---|---|---|---|
| quiet (17:27–17:37) | 10 | 283 kB | 9 kB (MEGAcmd session) | **1.70 MB/h** | 0.05 MB/h |
| Run A (17:37–17:42) | 5 | 144.18 MB | 143.40 MB | — | — |
| gap (17:42–17:46) | 4 | 79 kB | 2 kB | 1.18 MB/h | 0.03 MB/h |
| Run B (17:46–18:17) | 31 | 2.07 MB | 1.10 MB | 4.00 MB/h | **2.13 MB/h** |
| tail (18:17–18:28) | 12 | 270 kB | 8 kB | 1.35 MB/h | 0.04 MB/h |
| **after Run A (17:46–18:28)** | 43 | **2.34 MB** | **1.11 MB** | — | — |
| clock hour 17:00 (33 min captured) | | 145.57 MB | 143.93 MB | | |
| clock hour 18:00 (28 min captured) | | 1.31 MB | 0.58 MB | | |

**Background:** with the laptop quieted, its own traffic still ran at **1.35–1.70 MB/h**, i.e. 66–82 % of the R3-seg threshold. DNS shows the same thing: 2,044 queries in 61 minutes (48 % blocked), led by Datadog browser telemetry, Microsoft, Adobe and Apple.

### 16.4 Detection results against the pre-registered criteria

| Run | Rule | Pre-registered expectation | Result | Verdict |
|---|---|---|---|---|
| A | **R3-seg** (> 2.06 MB/h) | fires | 143.4 MB MEGA-attributed in one 60-minute window (70× the threshold) | ✅ **TP** |
| A | **R3-dev** (> 760 B/h) | fires | ~189,000× | ✅ **TP** |
| A | **R1** (new domain/SNI) | fires | `*.mega.co.nz` appears in no earlier IoT capture, Zeek log or Pi-hole extract | ✅ **TP** |
| A | `IOT_TO_WAN_NEW` | logged | in the counters (v4 LOG +699, v6 +267 over the window) but **not in the saved log** (rotation) | ⚠️ counted, entries lost |
| B | **R3-seg**, MEGA-attributed | **doesn't fire** | **1.11 MB** in the 43 minutes after Run A, < 2.06 MB for any 60-minute window | ✅ as predicted |
| B | R3-seg, MEGA, as a rate | — | extrapolating the 31-minute run gives 2.13 MB/h, **just above** 2.06 MB/h, because of MEGA's 2.2× per-upload overhead | ⚠️ thin margin |
| B | **R3-dev** | fires | ~1,450× | ✅ **TP** |
| B | **R6** (> 10 SYNs to one destination in 10 min) | not pre-registered | up to **63 per 10 min** to one storage-node address (≈ 120 per 10 min to the node over IPv4 and IPv6 together) | ✅ **TP**: the slow drip is louder in connections than in bytes |
| B | R3-seg, **host total** | — | **2.34 MB** in 43 min > 2.06 MB | fires: background plus the drip |
| B | R1, `IOT_TO_WAN_NEW` | logged | 165 new MEGA connections logged from 18:01:32 (E106) | ✅ |

**Controls** (the five baselined devices, same window, extrapolated hourly rates):

| Device | Baseline median (B/h) | This window | Ratio | R3-dev |
|---|---|---|---|---|
| Hue Bridge | 206,309 | ~385,000 | 1.9× | silent |
| SwitchBot Hub 2 | 8,716 | ~9,800 | 1.1× | silent |
| Matter switches ×2 | 0 | 0 | — | silent (R8 silent too) |
| **Tapo plug** | **76** | **~2,000** | **26×** | ❌ **fires: false positive** |

- **The Tapo false positive:** its baseline comes from only 5 non-zero hours in the segmented capture (10-10), *before* its firmware update (§13.2). Now it holds a TLS session to `54.253.6.87` (AWS) and sends about 2 kB/h, which is harmless but 26× its old median.
- **Lesson:** for very quiet devices, a 10× median has no headroom. A per-device R3 needs a **floor**, and devices need **re-baselining after firmware updates** (recommendation 20).
- **Meross plug** (`c4:e7:ae:20:54:57`): no baseline yet, ~4.5 kB/h. It uses one TLS session to `52.2.244.206` (AWS), and NTP to `time.windows.com` (`52.148.114.188`) instead of the router: it ignores DHCP option 42.

### 16.5 Interpretation

- **Bulk exfiltration is caught easily,** by volume (R3-seg/R3-dev), destination novelty (R1) and the connection log. 100 MiB stands out from even the busiest IoT device by two orders of magnitude.
- **Slow exfiltration evades the segment-wide volume rule, as designed,** but only by a thin margin, because real upload tools add overhead. It's still caught by the per-device volume rule, by R1, and by **R6**: a tool that opens many short connections per small upload is very visible in connection counts. Layered rules are needed; volume alone isn't enough.
- **General-purpose hosts don't belong on an IoT VLAN, from a detection point of view too.** The quieted laptop alone came close to R3-seg, and its host total crossed it during the slow run. An IoT-tuned volume rule therefore flags laptops more or less permanently. This supports keeping them off the IoT SSID (recommendation 17, done 2026-10-28) and ties in with the Keychain finding (§14.5, §15.6).
- **Per-device baselines are fragile for quiet devices** (the Tapo false positive). A floor and re-baselining after firmware changes are needed.
- **Segmentation still contained the test host towards the main LAN.** It retried SMB to the Mac mini (`192.168.0.13` and its ULAs, TCP 445/139, 81 SYNs each) and a few connections to the iPhone. These are the +184 `IOT_TO_LAN_DROP` packets in the counters (E107); the log entries fell into the rotation gap.

### 16.6 New devices: first observations (outside the analysis scope)

- **VFD clock** (`d8:f1:5b:90:ee:b3`):
  - **Failed DHCP in the upload capture.** After its power cycle at ~17:41:44, it sent **46 DHCP Discovers** in two rounds (17:41–17:52, 18:01–18:27). The router answered **every one with an Offer** (`192.168.107.22`, option 42 = `192.168.107.1`), but the clock never sent a Request and fell back to link-local `169.254.180.238`, so it had no traffic beyond mDNS and ARP.
  - The power cycle at 18:43 (E101–E105) worked first time, with identical Offers. The cause isn't established (possibly Wi-Fi delivery to the ESP8285, or its DHCP client).
  - **Boot behaviour (E101–E105):**
    - DHCP, then NTP to **`192.168.107.1`**, which honours option 42. The router answered with **stratum 1**, confirming the side discovery in `segmentation_report.md` section 5.
    - Then a **cleartext HTTP GET to `ip-api.com`** (`/json?fields=status,message,timezone,offset,lat,lon`) to look up its time zone and **approximate location**. That fires **R10** (cleartext HTTP to the internet). Anyone on the path can read the household's coarse location, and could spoof the time-zone offset.
    - It also advertises `_http._tcp` over mDNS and serves NTP itself (stratum 2, reference `192.168.107.1`). The owner's Mac Studio (`192.168.0.2`, main LAN) queried it during the boot capture.
- **Meross plug:** see 16.4. It uses its own public NTP server rather than the router.

### 16.7 Assessment

**Metric 1 is met:** every planned scenario, including the simulated volume upload, has now been executed. **Metric 2 is strengthened:** all three simulated scenarios (lateral scan, DNS bypass, volume upload) were detected by the transparent rules, and the slow variant showed why the rules have to work in layers.

---

## 17. Seventh pass: function checklist (state E)

> **In short:** The owner ran a 28-point checklist of everything the smart home must still do in the final state, including control from outside the house and recovery after a router reboot. All 28 checks passed. One plug needed a power cycle after a Wi-Fi restart, and some status messages were briefly blocked right after the reboot; neither stopped anything working.

### 17.1 Setup

- **What:** the written function checklist from the run sheet (`planning/function_checklist_template.md`), filled in by the owner during the run (**E110**) with 10 screenshots (**E111**, named after the row IDs). The owner completed it afterwards with the counter reading for check E1, the `IOT_INPUT` snapshot and the overall result ("metric 4 met").
- **When:** 2026-11-02 00:17 → 01:21, router uptime 113,154 s at the start (no reboot since the upload scenario), state E (`904f54d`).
- **Preconditions (P1–P4), all passed:**
  - the HomePod is on the main LAN (`192.168.0.22`, ULA `fd00:d:e:f::61`);
  - all seven IoT devices hold their usual IoT leases: Hue `.26`, SwitchBot `.15`, Tapo `.23`, switches `.17` / `.20`, Meross `.2`, VFD clock `.22`;
  - no other personal device is on `I0N_IoT`;
  - `IOT_INPUT` is present, with 2 `IOT_DNS_REDIRECT` rules.
- **Phone:** the iPhone was on the main Wi-Fi, except in section C (Wi-Fi off, cellular only; the C1 screenshot shows 5G).

### 17.2 Results

| Section | Checks | Result | Key evidence |
|---|---|---|---|
| **A: local control** (Apple Home / Matter) | Hue, SwitchBot Bot, Tapo, both Matter switches; status reports with the app closed ≥ 5 min (the §5.4 fix); a scene; an automation; the Eve Room (Thread, via the HomePod) | **9/9 pass** | Visual confirmation; A6: **0** `IOT_TO_LAN_DROP` entries for port 5540 in its window; screenshots A1, A7–A9 |
| **B: vendor apps** | Hue local control and bridge status; Tapo control and energy data; SwitchBot hub and Bot | **4/4 pass** | Screenshots B1–B4. The Hue Bridge reports software **6.3.1978545030**, i.e. it has updated since the earlier captures |
| **C: remote access** (the gap named in §9) | Home app control of a Hue light, the Tapo plug and a Matter switch over cellular, via the HomePod; remote status; Hue, Tapo and SwitchBot apps remotely | **4/4 pass** | Screenshot C1: the HomePod listed as the home hub, Hue Bridge and SwitchBot Hub as bridges, phone on 5G |
| **D: resilience** | D1 `service restart_wireless`; D2 router reboot; D3 Matter sessions afterwards | **3/3 pass, D1 with a remark** | D1: STP `br0` 1 / `br52` 0 / `br56` 1 and the IoT ULA present after the rebuild. D2: reboot at 00:59:30, web UI back at 01:01:38, **all seven devices leased again by 01:02:59** (3.5 min after the reboot). D3: 12 Matter conntrack entries (≥ 5 expected) |
| **E: background services** | VLAN NTP daemon; DNS through Pi-hole; firmware-update checks in the Hue, Tapo and SwitchBot apps; the newer devices | **4/4 pass** | Check E1: `ntp -n -l -I br52` running, and the `IOT_INPUT` NTP accept counter rose (21 at 01:07, 22 in the end snapshot). Check E2 (screenshot): 1,955 queries from `192.168.107.` in the Pi-hole log, the Hue and Tapo cloud names answered (forwarded or cached), `diag.meethue.com` blocked as before (§12.3). Check E3: all apps report up to date. Check E4: Meross plug works, VFD clock synced |

**Total: 28 of 28 checks passed** (P 4, A 9, B 4, C 4, D 3, E 4).

**Remark on D1 (Tapo plug):**
- After the wireless restart the plug first answered, then stopped switching. The Home app kept showing it as responding, and the relay didn't click.
- A power cycle cleared it, and it didn't recur, including after the router reboot in D2.
- The router side was fine at the same moment: STP, the ULA and the other three devices in the check worked. So this is a **device-side recovery fault**, the same kind as the Matter switches' failure to rejoin after a wireless restart (§13.7). Recommendation 23.

### 17.3 Firewall evidence during the run

The run's `IOT_TO_LAN_DROP` entries (25: 20 IPv4, 5 IPv6) are all **Matter reports** (UDP source port 5540) from IoT devices to the two Apple controllers. Nothing else from the IoT VLAN was dropped, and there are no `IOT_TO_ROUTER_DROP` entries.

| Time | From | To | Entries |
|---|---|---|---|
| 01:02:31–01:02:35 | Hue Bridge `.26` | HomePod `192.168.0.22:62864` | 5 |
| 01:02:50–01:02:54 | Matter switch `.17` (`…0d:6b`) | HomePod `192.168.0.22:62864` | 5 |
| 01:12:32–01:12:48 | Matter switch `.17` | iPhone `192.168.0.221:59430` and the iPhone's ULA, port 55414, alternating | 5 + 5 |
| 01:13:03–01:13:07 | Matter switch `.20` (`…0d:6e`) | HomePod `192.168.0.22:62864` | 5 |

- **Cause:** the same mechanism as §5.4, but triggered by **lost router state** instead of a timeout. The reboot at 00:59:30 emptied the conntrack table, while the HomePod and the devices kept their Matter sessions. The devices' next reports reached the router before the controller had sent anything new, so they counted as new IoT → main-LAN connections and were dropped. The 01:12–01:13 bursts are the same pattern for sessions that hadn't been refreshed yet since the reboot. They coincide with check E3 (firmware-update checks in the apps), which doesn't involve the switches.
- **Effect: none on function.** Each burst lasted 5–17 s and ended once the controller refreshed the session, and A1–A5 passed after the reboot. Each burst logged exactly 5 entries, the LOG rule's burst size. Up to the FORWARD snapshot the LOG and DROP counters agree (15 / 15), so the log is complete for that period.
- **Detection:** R2 fires, and these are **policy false positives**, as in §5.4. Recommendation 22 labels this pattern instead of alerting on it.

**`IOT_INPUT` at the end** (counters since the reboot at 00:59:30): NTP 22 packets, mDNS 7,401, DHCP 0, `IOT_TO_ROUTER_DROP` LOG/DROP **0**. So no IoT device tried a blocked router service after the reboot. The DHCP counter is 0 although all seven devices took new leases at about 01:02. The likely reason is that those exchanges happened before `firewall-start` created the chain, so its counters started later.

### 17.4 Other observations

- **Matter controllers seen in conntrack at the end:**
  - The HomePod holds sessions to the Hue, the SwitchBot and the switch `.20`.
  - The iPhone holds sessions to the Hue, the switch `.20` and the **Meross plug** (`.2`), so the Meross is commissioned into Apple Home over Matter.
  - The owner's **Mac Studio** (`192.168.0.2`, main LAN) holds a Matter session to the **Tapo plug**: the owner had the Home app open on it briefly. Like the iPhone, a Mac acts as a Matter controller directly while the Home app is in use. It is also the host that queried the VFD clock's NTP service in §16.6.
- **WAN sessions at the end:** the Meross to AWS (`:443`), the Hue to its cloud (2 TLS sessions) and NTP to `162.159.200.123`, the SwitchBot to MQTT (`:8883`). These are all known destinations from earlier passes.
- **Hue firmware:** the bridge reports **6.3.1978545030**, newer than in the earlier evidence. By recommendation 20, the Hue baseline should be rebuilt before its R3 threshold is used again.

### 17.5 Assessment

**Metric 4 is met.** Every documented required function works in the final state E. That includes the gap named in §9, remote access through the HomePod while away, plus recovery from a wireless restart and a full router reboot. Neither remark is a lost function. The Tapo's stuck relay was device-side and cleared by a power cycle. The Matter report drops after the reboot were self-healing and are R2 policy false positives, which recommendation 22 removes from the alert stream.

---

## 18. Eighth pass: Splunk pipeline and dashboard

> **In short:** a general, configurable pipeline turns the raw evidence into device-labelled events for Splunk, and a dashboard shows every result in plain words. Rebuilt independently from the raw files, it reproduces the analysis' numbers and finds the same events. Building it uncovered four data-handling traps, all fixed and documented. Metric 5 is met.

### 18.1 What was built

- **Pipeline:** `pipeline/iotpipe.py` (E112), `iotpipe` 0.1, Python standard library only. Everything site-specific (networks, devices by MAC, controllers, which recordings are baselines) lives in `pipeline/site.toml` (E115); `site.example.toml` (E116) is a template for other homes. The household's real public prefixes sit in a separate `site.private.toml`, which is never hashed or shared.
- **From raw files to events:** `zeek` runs Zeek (E114) over every capture. `prepare` reads the pcaps, the Zeek logs, the firewall logs and the Pi-hole export, plus the operator's notes (E117), and writes 11 sourcetypes: connections, DNS, TLS, TLS fingerprints, HTTP, DHCP, per-minute volume, capture health, firewall, Pi-hole and annotations. That is **64,721 events**, all attributed to devices by MAC.
- **Into Splunk:** `app` builds a Splunk app (parsing rules, lookups, the detection macros and the dashboard from `pipeline/dashboard.py`, E113); `send` loads the events over HEC. Both were used on Splunk Enterprise 10.6.1.1.
- **Dashboard:** *IoT Segmentation: Smart-Home Network Overview*, with filters for recording, device, minimum severity and the test host. Screenshots: E118 (cropped, used in the guide) and E119 (originals).
- **Guide:** `pipeline_guide.md`, written for readers with a networking background. It covers collecting the evidence, describing the network, running the pipeline, both ways into Splunk, a guided tour of the dashboard with the screenshots, a field reference, pitfalls and privacy.
- **Reproducibility:** run from scratch (`iotpipe all`, including Zeek), the pipeline regenerates exactly the same event counts.

### 18.2 The pipeline reproduces the analysis

These numbers were produced separately by the analysis tools in `tools/`, and the pipeline arrives at them on its own:

| Check | Pipeline | Analysis |
|---|---|---|
| Hue Bridge DNS queries, flat / segmented recording | 935 / 1,966 | 935 / 1,966 (§1.2) |
| Hue Bridge median internet upload per hour, segmented | 206,309 B | 206,309 B (§16.4) |
| Test laptop upload, bulk run / after it | 144,175,565 B / 2,338,346 B | 144.18 MB / 2.34 MB (§16.3) |
| SwitchBot flows to `255.2.0.0`, segmented | 931 | 949 packets (§5.1) |
| IPv6 router adverts after the 17:03 Wi-Fi restart | 0 for 50 min | stopped (§13.6) |
| Hue Bridge TLS fingerprints | 5 | 5 (§12.2, §13.3) |

### 18.3 The rules in Splunk

Each rule of §8 is a Splunk macro with the same output columns (`pipeline_guide.md` section 7.4). Two extra macros cover router-service drops (FW) and unexpected devices on the IoT side (DEV). With all recordings selected, they find:

| Rule | Findings | Matches |
|---|---|---|
| R1 | the Hue's 9 boot-time time servers; the Tapo's 5 update and cloud domains | §13.3, §13.2 |
| R2 | 20 blocked lateral attempts (test hosts, a Keychain-joined Apple device); the 60 Matter drops of 10 October as *info* | §14.2, §15.5, §5.4 |
| R3 | Hue firmware download, Tapo update, both upload hours; **no Tapo false positive** | §5.3, §13.2, §16.4 |
| R4 | the SwitchBot leak in five recordings (984 flows) | §5.1 |
| R5 | the Hue's retry storm (segmented and tapo recordings) | §5.2 |
| R6 | the slow upload (two storage servers); the SwitchBot reconnect burst | §16.4, §5.5 |
| R7 | the simulated DNS bypass, before and after state E | §14.4, §15.4 |
| R8, R9 | none (correct negatives) | §5.7, §12.2 |
| R10 | Hue diagnostics, the VFD clock's location lookup, the test laptop's own HTTP | §12.3, §16.6 |
| R11 | the 50-minute IPv6 advert gap | §13.6 |
| R12 | the Hue's TLS 1.0 at boot | §13.3 |
| FW, DEV | the state E router probes; the Keychain-joined devices and the HomePod on the IoT side | §15.3, §14.5, §15.6 |

**Deliberate differences from §8**, all from the recommendations or for clarity:
- **R3** has a floor of 10 kB/h (recommendation 20). That's what removes the Tapo false positive of §16.4.
- **R2** labels Matter messages to a controller as *info* (recommendation 22).
- **R3 and R6** run per device, attributed by MAC (recommendation 21).
- **R1** only covers devices with a baseline: a test host has none, so every domain would be "new". In §16 R1 fired on the MEGA domains; the dashboard catches that upload with R3 (critical, 724×) and R6 instead.
- **R5** compares with the first baseline recording, so the post-change storm isn't hidden by its own baseline.

### 18.4 Data-handling traps found while building it

All four were found by checking the pipeline's output against the analysis, and all are fixed in the pipeline (`pipeline_guide.md`, sections 5.1 and 9):

1. **Zeek sometimes reverses a connection.** For UDP from 5353 to 5353 it guessed the wrong side (history flag `^`), so the SwitchBot appeared to *receive* its leaked packets. The flips are undone.
2. **A flat network records the whole household.** In state A, 36,000 connections belonged to other household computers, which is noise and private. Hosts that are neither a listed device nor in the IoT network are dropped, including their DHCP.
3. **Special addresses mislead attribution.** Pi-hole logs its own lookups as client `::`, and IPv6 devices send from `::` while checking their address. So 1,051 of Pi-hole's own lookups were briefly credited to the Tapo plug, ad-tech domains included. Such addresses are never used to identify a device now.
4. **The household's own public addresses turn up in the data:** 37 connections from the flat recording, when devices had public IPv6, and 49 firewall entries of the hairpin test. They're classified separately and masked to documentation ranges in every output.

### 18.5 Assessment

**Metric 5 is met.** Every result now comes with reproducible evidence at two levels. The analysis tools and hashed extracts produced the numbers in this document, and the Splunk pipeline rebuilds them from the same raw files and shows them on a dashboard. `results_to_evidence.md` links each result to its evidence IDs, and the guide explains the workflow so that someone else can repeat it on their own network.
