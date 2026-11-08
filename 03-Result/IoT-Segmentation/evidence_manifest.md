# Evidence Manifest: IoT Segmentation Project

Working folder: `IoT Segmentation/` · Generated 2026-11-03 23:46 AEDT · Status: **raw evidence and first-order extracts; every capture analysed** (`analysis.md`, the tapo capture in §13). The sanitised submission bundle has been built (see "Sanitised bundle plan" at the end).

**Verify integrity:** `sha256sum -c SHA256SUMS` from the working folder. `SHA256SUMS` is the authoritative hash list. It covers every evidence file below: original artefacts, first-order extracts (the trimmed Pi-hole log, the active-test outputs) and the tools; `python3 tools/build_manifest.py --sums` rebuilds it. The git repo is identified by its commit hash instead. Left out on purpose: report documents (`segmentation_report.md`, `analysis.md`, `peer_review_summary.md`, this manifest and its generator `tools/build_manifest.py`), the bundle builders `tools/make_team_bundle.py` and `tools/make_submission_bundle.py` (both hold the real values), the bundles themselves (`team_bundle/`, `submission_bundle/`, each with its own `SHA256SUMS`) and `submission_bundle.obsolete.txt`, the consistency checker `tools/check_consistency.py`, the results table `results_to_evidence.md` and its generator `tools/build_results_table.py`, and `planning/` (checklist template and scenario run sheets; their filled-in results become evidence), the pipeline guide `pipeline_guide.md` (a document), the private overlay of the pipeline, `pipeline/site.private.toml` (the household's real public prefixes), and the regenerable pipeline output `pipeline_out/`, and the outputs of the analysis tools, which are regenerable (see "Regenerable outputs"). The tables show hash prefixes; the appendix lists full hashes.

**Evidence IDs are stable.** E01–E69 come from the first manifest (2026-10-11 15:34); `analysis.md` cites some of them. Files moved since then keep their ID (see "Moved files" below); evidence added later gets the next free ID (E70 onwards). Rows are grouped by type, so IDs aren't in numerical order. Retired IDs (regenerable outputs and the manifest generator, not cited in `analysis.md`; never reused): E31–E51, E69, E82–E87.

**Analysis environment:** a NAT'd terminal on the **main LAN**; it is never on the IoT VLAN. Its only traffic into the IoT VLAN was the active test (E52–E60, 2026-10-11 15:29–15:31), outside every capture window, so it doesn't appear in the IoT captures or firewall logs. A separate **test host on the IoT VLAN** (a MacBook, E90) ran the IoT → main-LAN/router tests on 2026-10-11 21:57–22:12. No capture was running then; its traffic is in E88 and E89. Its DNS queries come from a main-LAN client address and are excluded from the Pi-hole extract by the client filter.

**Time zone:** all times are AEDT (UTC+11, `Australia/Sydney`) unless stated. Router syslog and `run.log` use local time; pcap timestamps are stored in UTC epoch.

## Artefacts

| ID | File | Size | SHA-256 (prefix) | What it is | Window / content | Sensitivity / sanitisation | Supports metric |
|---|---|---|---|---|---|---|---|
| E01 | `20261006-215327_flat/wl0.2_20261006-215327.pcap` | 211.3 MiB | `88be144e5f572788…` | State A (flat): 24 h capture, IoT SSID and Hue port, before segmentation; interface `wl0.2` | 858,199 pkts; 2026-10-06 21:53:27 → 2026-10-07 21:53:28 | Raw. Contains main-LAN broadcast/multicast from every host (hostnames in mDNS, `<PD>` GUA addresses, Thread border-router traffic) and, on `eth7`, VLAN 114 frames (roommate, out of scope). Sanitise: drop VLAN-tagged frames, keep only IoT MACs, remap `<PD>`. | 1, 3, 4, 5 (baselines, before/after) |
| E02 | `20261006-215327_flat/eth7_20261006-215327.pcap` | 226.2 MiB | `e64ae52115b3c30f…` | State A (flat): 24 h capture, IoT SSID and Hue port, before segmentation; interface `eth7` | 958,030 pkts; 2026-10-06 21:53:27 → 2026-10-07 21:53:28; **89,336 VLAN 114-tagged frames** | Raw. Contains main-LAN broadcast/multicast from every host (hostnames in mDNS, `<PD>` GUA addresses, Thread border-router traffic) and, on `eth7`, VLAN 114 frames (roommate, out of scope). Sanitise: drop VLAN-tagged frames, keep only IoT MACs, remap `<PD>`. **The `eth7` pcap also carries the Hue Bridge's `sso` token in cleartext HTTP; redact it.** | 1, 3, 4, 5 (baselines, before/after) |
| E03 | `20261006-215327_flat/run.log` | 2.8 KiB | `4dc4c87985baa7f9…` | capture run log: settings, tcpdump version, offload disable/re-enable, drop counters (0 dropped) | same window as the capture | Low | 5 (capture completeness) |
| E04 | `20261006-215327_flat/wl0.2.log` | 173 B | `a48e61d665f044ea…` | tcpdump stderr / statistics for `wl0.2` | same window as the capture | Low | 5 (capture completeness) |
| E05 | `20261006-215327_flat/eth7.log` | 172 B | `c8b3350e0ba17f5d…` | tcpdump stderr / statistics for `eth7` | same window as the capture | Low | 5 (capture completeness) |
| E06 | `20261010-002759_seg/wl0.2_20261010-002759.pcap` | 141.6 MiB | `a5b3131c4bb48415…` | State C/D (segmented): 24 h capture of the IoT network; includes the Matter drop period (10-10 12:12–12:48); interface `wl0.2` | 434,540 pkts; 2026-10-10 00:28:00 → 2026-10-11 00:28:00 | Raw. IoT devices, router, HomePod/Apple controller addresses; router `<PD>` GUA appears. Sanitise: remap `<PD>`; MACs may stay (own devices). | 1, 3, 4, 5 (baselines, before/after) |
| E07 | `20261010-002759_seg/eth7_20261010-002759.pcap` | 162.9 MiB | `de3b9eacbb0a58ed…` | State C/D (segmented): 24 h capture of the IoT network; includes the Matter drop period (10-10 12:12–12:48); interface `eth7` | 508,423 pkts; 2026-10-10 00:28:00 → 2026-10-11 00:28:00 | Raw. IoT devices, router, HomePod/Apple controller addresses; router `<PD>` GUA appears. Sanitise: remap `<PD>`; MACs may stay (own devices). **The `eth7` pcap also carries the Hue Bridge's `sso` token in cleartext HTTP; redact it.** | 1, 3, 4, 5 (baselines, before/after) |
| E08 | `20261010-002759_seg/run.log` | 2.8 KiB | `8432ebb9500aa1c5…` | capture run log: settings, tcpdump version, offload disable/re-enable, drop counters (0 dropped) | same window as the capture | Low | 5 (capture completeness) |
| E09 | `20261010-002759_seg/wl0.2.log` | 173 B | `318dff6d2e3c2b3a…` | tcpdump stderr / statistics for `wl0.2` | same window as the capture | Low | 5 (capture completeness) |
| E10 | `20261010-002759_seg/eth7.log` | 172 B | `f24a72a2bcb51a5d…` | tcpdump stderr / statistics for `eth7` | same window as the capture | Low | 5 (capture completeness) |
| E11 | `20261011-134542_app_interaction/wl0.2_20261011-134542.pcap` | 741.7 KiB | `1111d5f856d138e2…` | App-interaction capture (Apple Home, Eve, Hue, SwitchBot), stopped manually after 7 min; interface `wl0.2` | 2,435 pkts; 2026-10-11 13:45:42 → 2026-10-11 13:52:46 | Raw. Same content classes as the segmented capture. | 1, 3, 4, 5 (baselines, before/after) |
| E12 | `20261011-134542_app_interaction/eth7_20261011-134542.pcap` | 936.5 KiB | `2a0c9219ce754ce1…` | App-interaction capture (Apple Home, Eve, Hue, SwitchBot), stopped manually after 7 min; interface `eth7` | 3,065 pkts; 2026-10-11 13:45:42 → 2026-10-11 13:52:46 | Raw. Same content classes as the segmented capture. | 1, 3, 4, 5 (baselines, before/after) |
| E13 | `20261011-134542_app_interaction/run.log` | 2.8 KiB | `07ad4528b0f78c07…` | capture run log: settings, tcpdump version, offload disable/re-enable, drop counters (0 dropped) | same window as the capture | Low | 5 (capture completeness) |
| E14 | `20261011-134542_app_interaction/wl0.2.log` | 169 B | `3e39edecae24e244…` | tcpdump stderr / statistics for `wl0.2` | same window as the capture | Low | 5 (capture completeness) |
| E15 | `20261011-134542_app_interaction/eth7.log` | 168 B | `1869c22b81884efe…` | tcpdump stderr / statistics for `eth7` | same window as the capture | Low | 5 (capture completeness) |
| E70 | `20261011-164338_tapo/wl0.2_20261011-164338.pcap` | 3.7 MiB | `ba3877d247a6ebb5…` | State D verification capture (at `d0c3085`: after the `75807a2` NTP and `d0c3085` reflector-filter changes): Tapo firmware update, Hue Bridge and Matter switch power cycles (E16); planned 24 h, stopped manually after 70 min; interface `wl0.2`. **This interface stopped at 17:03:11** (`pcap_loop: The interface disappeared`); `eth7` ran to the end | 8,694 pkts; 2026-10-11 16:43:39 → 2026-10-11 17:03:11 | Raw. Same content classes as the segmented capture. | 1, 2, 4, 5 (state D verification, firmware-update scenario) |
| E71 | `20261011-164338_tapo/eth7_20261011-164338.pcap` | 4.1 MiB | `8d264317c428c8a5…` | State D verification capture (at `d0c3085`: after the `75807a2` NTP and `d0c3085` reflector-filter changes): Tapo firmware update, Hue Bridge and Matter switch power cycles (E16); planned 24 h, stopped manually after 70 min; interface `eth7` | 17,401 pkts; 2026-10-11 16:43:39 → 2026-10-11 17:53:42 | Raw. Same content classes as the segmented capture. | 1, 2, 4, 5 (state D verification, firmware-update scenario) |
| E72 | `20261011-164338_tapo/run.log` | 2.8 KiB | `ccf1e0d8fa3be34a…` | capture run log: settings, tcpdump version, offload disable/re-enable, drop counters (0 dropped); planned 24 h, stopped at 17:53:44 | same window as the capture | Low | 5 (capture completeness) |
| E73 | `20261011-164338_tapo/wl0.2.log` | 215 B | `64da1d9d4dd0e3c7…` | tcpdump stderr / statistics for `wl0.2`; ends with `pcap_loop: The interface disappeared` (17:03:11) | same window as the capture | Low | 5 (capture completeness) |
| E74 | `20261011-164338_tapo/eth7.log` | 170 B | `85006ea310461820…` | tcpdump stderr / statistics for `eth7` | same window as the capture | Low | 5 (capture completeness) |
| E96 | `20261031-172658_upload/wl0.2_20261031-172658.pcap` | 163.8 MiB | `fcad949847cfe29b…` | Simulated volume-upload scenario (state E): test host (MacBook, `42:e3:fe:60:6c:d9`, `.13`) uploads to the owner's own MEGA account; Run A 100 MiB bulk (17:37:50–17:41:31), Run B 30 × 16 KiB slow (17:46:07–18:17:02); timeline in E108; interface `wl0.2` | 206,146 pkts; 2026-10-31 17:26:58 → 2026-10-31 18:28:21 | Raw. IoT devices (incl. the newer Meross plug and VFD clock), the test host's full background traffic (cloud services, mail), MEGA endpoints. Sanitise: as the segmented capture; consider truncating the test host's non-scenario flows. | 1, 2, 5 (volume-upload scenario) |
| E97 | `20261031-172658_upload/eth7_20261031-172658.pcap` | 7.6 MiB | `0dfa4e742065e1c2…` | Simulated volume-upload scenario (state E): test host (MacBook, `42:e3:fe:60:6c:d9`, `.13`) uploads to the owner's own MEGA account; Run A 100 MiB bulk (17:37:50–17:41:31), Run B 30 × 16 KiB slow (17:46:07–18:17:02); timeline in E108; interface `eth7` | 24,364 pkts; 2026-10-31 17:26:58 → 2026-10-31 18:28:21 | Raw. IoT devices (incl. the newer Meross plug and VFD clock), the test host's full background traffic (cloud services, mail), MEGA endpoints. Sanitise: as the segmented capture; consider truncating the test host's non-scenario flows. | 1, 2, 5 (volume-upload scenario) |
| E98 | `20261031-172658_upload/run.log` | 2.8 KiB | `e5fd5d7772074319…` | capture run log: settings, tcpdump version, offload disable/re-enable, drop counters (0 dropped); started in the foreground, stopped manually at 18:28:22 (0 dropped) | same window as the capture | Low | 5 (capture completeness) |
| E99 | `20261031-172658_upload/wl0.2.log` | 173 B | `91d9269ef550ca2c…` | tcpdump stderr / statistics for `wl0.2` | same window as the capture | Low | 5 (capture completeness) |
| E100 | `20261031-172658_upload/eth7.log` | 170 B | `c0f312c9cd3c51db…` | tcpdump stderr / statistics for `eth7` | same window as the capture | Low | 5 (capture completeness) |
| E101 | `20261031-184353_vfd/wl0.2_20261031-184353.pcap` | 26.6 KiB | `5044ba85e681a425…` | VFD clock (LGL VCK 0658-L, `d8:f1:5b:90:ee:b3`) power-cycle capture, 40 s: boot, DHCP, NTP to the router, `ip-api.com` lookup; interface `wl0.2` | 153 pkts; 2026-10-31 18:43:55 → 2026-10-31 18:44:31 | Raw. Small; IoT addresses, one main-LAN host querying the clock's NTP. | 5 (side discovery; new device) |
| E102 | `20261031-184353_vfd/eth7_20261031-184353.pcap` | 96.9 KiB | `f45dc0109500f072…` | VFD clock (LGL VCK 0658-L, `d8:f1:5b:90:ee:b3`) power-cycle capture, 40 s: boot, DHCP, NTP to the router, `ip-api.com` lookup; interface `eth7` | 292 pkts; 2026-10-31 18:43:53 → 2026-10-31 18:44:31 | Raw. Small; IoT addresses, one main-LAN host querying the clock's NTP. | 5 (side discovery; new device) |
| E103 | `20261031-184353_vfd/run.log` | 2.8 KiB | `5b5e4cae44be67ed…` | capture run log: settings, tcpdump version, offload disable/re-enable, drop counters (0 dropped); stopped manually after 40 s | same window as the capture | Low | 5 (capture completeness) |
| E104 | `20261031-184353_vfd/wl0.2.log` | 167 B | `d6c00d20c582228f…` | tcpdump stderr / statistics for `wl0.2` | same window as the capture | Low | 5 (capture completeness) |
| E105 | `20261031-184353_vfd/eth7.log` | 166 B | `ba5021b0266b79d4…` | tcpdump stderr / statistics for `eth7` | same window as the capture | Low | 5 (capture completeness) |
| E16 | `interaction_timeline.txt` | 535 B | `c980a6072040c6bc…` | Action log (ground truth) for the interaction captures. App interaction: start time of each app session (Apple Home 13:45:51, Eve 13:47:55, Hue 13:49:44, SwitchBot 13:51:08); actions were version/update checks (no updates available), the "add new device" page in each app, and toggling several devices in Apple Home. Tapo capture: Tapo firmware update started 16:43:50, update succeeded and plug confirmed reachable 16:45:36, Hue Bridge power cycle 16:46:04, Zemismart (Matter) switch power cycle 17:12:29, annotated: both switches had failed to reconnect after the owner's earlier router/wireless restart. Replaces `app_int_timeline.txt`; its first four lines are byte-identical to that file. **Amended 2026-10-12** (owner): only that annotation was added; previous SHA-256 `ba6897938ff86242…`. | 2026-10-11 13:45:51 → 17:12:29 (event times; app sessions: start times only) | Low | 1, 4, 5 (ground truth for attribution) |
| E17 | `firewall_logs/FW_log_3h.log` | 46.3 KiB | `03ed44db52a10097…` | Router syslog filtered to `IOT_TO_WAN_NEW` (rule `e637e73`) over a ~3 h syslog window: 214 entries. Sources: Hue Bridge `.26` ×119 (77 NTP to public servers, 42 TCP 443), SwitchBot Hub 2 `.15` ×94 (91 of them mDNS to `255.2.0.0`), Tapo smart plug `.23` ×1. All IPv4. | 2026-10-11 10:27:45 → 13:18:56 (first/last entry; file has no trailing newline) | Medium: internal addresses, device MACs, public destinations | 2, 5 |
| E18 | `firewall_logs/FW_log_app_interaction.log` | 2.6 KiB | `e548b20c515f079d…` | Same filter for the app-interaction window: 12 entries (SwitchBot `.15` ×9, all mDNS to `255.2.0.0`; Hue `.26` ×3) | 2026-10-11 13:46:11 → 13:52:33 | Medium | 1, 2, 5 |
| E19 | `firewall_logs/FW_matter-5540-iot-lan-drop.log` | 14.7 KiB | `eb7fc30c9075b358…` | `IOT_TO_LAN_DROP` entries for Matter subscription reports (UDP source port 5540) to the Apple controller, before the UDP timeout fix: 60 entries from 4 devices | 2026-10-10 12:12:02 → 12:47:59 | Medium: internal addresses incl. HomePod ULA | 3, 4, 5 (Matter case study) |
| E75 | `firewall_logs/FW_tapo_capture.log` | 53.4 KiB | `33db6f96e6c18f52…` | Same filter for the tapo capture: 247 entries, no `IOT_TO_LAN_DROP`. Sources: Hue Bridge `.26` ×210 (185 NTP to public servers, 25 TCP 443), SwitchBot Hub 2 `.15` ×27 (23 mDNS to `255.2.0.0`, 3 TCP 8883, 1 NTP), Tapo smart plug `.23` ×10 (7 TCP 443, 3 NTP). All IPv4. Two syslog segments joined by a blank line (line 214): **gap 17:14:30 → 17:31:07** where syslog rotated; the counter delta in E76/E79 puts the loss at ~19 entries. | 2026-10-11 16:43:51 → 17:50:07 (first/last entry; no trailing newline) | Medium | 1, 2, 4, 5 |
| E20 | `router_states/after_app/fw4_counters_1401.txt` | 2.9 KiB | `733a29ef5124dad3…` | IPv4 FORWARD rule counters (`iptables -vnL FORWARD`). Snapshot taken **after** the app interaction only (no "before" snapshot for that window), so counters are cumulative since the last firewall restart. | 2026-10-11 14:01 (from filename) | Medium | 2, 3, 4, 5 |
| E21 | `router_states/after_app/fw6_counters_1401.txt` | 5.7 KiB | `8a9fdba993d4c8e4…` | IPv6 FORWARD rule counters (`ip6tables -vnL FORWARD`); the IPv6 `IOT_TO_WAN_NEW` LOG rule shows 0 packets. Snapshot taken **after** the app interaction only (no "before" snapshot for that window), so counters are cumulative since the last firewall restart. | 2026-10-11 14:01 (from filename) | Medium | 2, 3, 4, 5 |
| E22 | `router_states/after_app/conntrack_iot_1401.txt` | 1.8 KiB | `a65198aebb6eff25…` | Connection-tracking entries involving the IoT network (`/proc/net/nf_conntrack`, 9 entries). Snapshot taken **after** the app interaction. Matter sessions (UDP 5540): iPhone → `.15`, `.17`, `.26`; HomePod → `.15`. | 2026-10-11 14:01 (from filename) | High: contains the WAN IPv4 address | 2, 3, 4, 5 |
| E76 | `router_states/before_tapo_capture/fw4_counters_1643.txt` | 2.9 KiB | `933aa8e9fcef3b77…` | IPv4 FORWARD rule counters (`iptables -vnL FORWARD`). Snapshot taken just **before** the tapo capture. The firewall had been restarted shortly before (`IOT_TO_WAN_NEW` LOG counter at 60), so before/after deltas cover the capture window. | 2026-10-11 16:43 (from filename) | Medium | 2, 3, 4, 5 |
| E77 | `router_states/before_tapo_capture/fw6_counters_1643.txt` | 5.7 KiB | `0b3c30e1ba46f3b7…` | IPv6 FORWARD rule counters (`ip6tables -vnL FORWARD`); the IPv6 `IOT_TO_WAN_NEW` LOG rule shows 0 packets. Snapshot taken just **before** the tapo capture. The firewall had been restarted shortly before (`IOT_TO_WAN_NEW` LOG counter at 60), so before/after deltas cover the capture window. | 2026-10-11 16:43 (from filename) | Medium | 2, 3, 4, 5 |
| E78 | `router_states/before_tapo_capture/conntrack_iot_1643.txt` | 8.9 KiB | `a728f02ca3e1319f…` | Connection-tracking entries involving the IoT network (`/proc/net/nf_conntrack`, 47 entries). Snapshot taken just **before** the tapo capture. **No Matter (UDP 5540) session for any IoT device**; 45 of the entries are the Hue Bridge's. | 2026-10-11 16:43 (from filename) | High: contains the WAN IPv4 address | 2, 3, 4, 5 |
| E79 | `router_states/after_tapo_capture/fw4_counters_1751.txt` | 2.9 KiB | `8e5d3f8db6d2a883…` | IPv4 FORWARD rule counters (`iptables -vnL FORWARD`). Snapshot taken **after** the tapo capture; `IOT_TO_WAN_NEW` LOG counter 326 (+266 since 16:43). | 2026-10-11 17:51 (from filename) | Medium | 2, 3, 4, 5 |
| E80 | `router_states/after_tapo_capture/fw6_counters_1751.txt` | 5.7 KiB | `95e3c91279d0a951…` | IPv6 FORWARD rule counters (`ip6tables -vnL FORWARD`); the IPv6 `IOT_TO_WAN_NEW` LOG rule shows 0 packets. Snapshot taken **after** the tapo capture; `IOT_TO_WAN_NEW` LOG counter 326 (+266 since 16:43). | 2026-10-11 17:51 (from filename) | Medium | 2, 3, 4, 5 |
| E81 | `router_states/after_tapo_capture/conntrack_iot_1751.txt` | 2.6 KiB | `1ff1e9f12c40b455…` | Connection-tracking entries involving the IoT network (`/proc/net/nf_conntrack`, 13 entries). Snapshot taken **after** the tapo capture. HomePod Matter sessions (UDP 5540) to all five Matter devices: `.15`, `.17`, `.20`, `.23`, `.26`. | 2026-10-11 17:51 (from filename) | High: contains the WAN IPv4 address | 2, 3, 4, 5 |
| E89 | `router_states/iot_lan_before_and_after/` | 26.2 KiB | see appendix | IPv4/IPv6 FORWARD (`fw4`/`fw6`) and INPUT (`in4`/`in6`) rule counters (`iptables`/`ip6tables -vnL … --line-numbers`), taken just before (`_2157`) and after (`_2212`) the active test from the IoT VLAN (8 files). Deltas: IoT → main-LAN DROP +58,771 (v4) / +598 (v6); `IOT_TO_WAN_NEW` +466 / +152; INPUT `tcp dpt:22` ACCEPT (any interface) +24. | 2026-10-11 21:57 and 22:12 (from filenames) | Medium | 3, 5 |
| E88 | `firewall_logs/FW_iot_active.log` | 264.2 KiB | `df88c04c257cfa94…` | Router syslog filtered to `IOT_TO_WAN_NEW` / `IOT_TO_LAN_DROP`, covering the active test: 1,111 entries (898 WAN, 213 LAN drop), 767 of them inside the test window. Test host (`192.168.107.8`, private MAC `b2:1c:d7:ba:85:9d`): 411 WAN incl. the DNS-bypass probes to `1.1.1.1` UDP 53 and TCP 853, 197 LAN drops. Also contains two of the owner's other Apple devices, which joined via a Keychain-synced passphrase (randomised MACs `1e:b2:de:92:90:28` at `.18`, `c2:c0:9a:ec:14:36` at `.19`; not analysed) and the first 20 entries stamped `Jan 1` (router clock before NTP sync after a reboot). | 2026-10-11 21:52:11 → 22:12:05 (plus pre-sync boot entries) | Medium–High: internal addresses, device MACs, one `<PD>` address (redact) | 1, 2, 3, 5 |
| E92 | `router_states/hardening_before_and_after/` | 120.9 KiB | see appendix | Router state for the **state E re-test**, taken just before (`hardening_before/*_2355`, state after boot) and after (`hardening_after/*_0002`) the test, 18 files each: IPv4/IPv6 FORWARD and INPUT counters (`fw4`/`fw6`/`in4`/`in6`), `IOT_INPUT` v4/v6, firmware sub-chains `SDN_FI`, `PTCSRVWAN`, `PTCSRVLAN` (v4/v6; the v6 `PTCSRV*` chains don't exist), nat PREROUTING v4/v6, `brctl show` + `stp_state`, `ip -6 addr`, the `ntpd_vlan` cron job, IoT conntrack. A `restart_wireless` ran between the two (bridge ifindexes change). Deltas: `IOT_INPUT` v4 DROP 43 → ~131k; v4 TCP/UDP 53 DNAT +19/+3, v6 UDP +1, v6 TCP 0; FORWARD TCP 853 DROP +3. | 2026-10-11 23:55:10 and 2026-10-12 00:02:36 (file times) | High: `conntrack_iot_*` and `nat4_prerouting_*` contain the WAN IPv4; `ipv6_addr_*` contains `<PD>` and `<WAN-RA>` addresses (redact) | 3, 4, 5 |
| E91 | `firewall_logs/FW_hardening.log` | 108.7 KiB | `fd851583a8f11400…` | Router syslog filtered to `IOT_TO_(ROUTER_DROP|LAN_DROP|WAN_NEW)` and `IOT_DNS_REDIRECT` during the state E re-test: 447 entries (291 WAN, 97 router drop, 53 LAN drop, 6 DNS redirect). Router-drop and redirect entries come only from the test host (`b2:1c:d7:ba:85:9d`); also present: the owner's Apple devices `.18` and `.13` (`ac:bc:b5:d3:d1:dd`, not analysed) and Hue public NTP. Starts at 23:58:01, so r1 (23:56) isn't in it. | 2026-10-11 23:58:01 → 2026-10-12 00:02:54 | Medium–High: internal addresses, device MACs; 48 entries carry the router's WAN-side IPv6 address (`<WAN-RA>`, zero-padded form; redact) | 1, 3, 5 |
| E94 | `router_states/hardening_dns6_ont_retest_2_before_and_after/` | 3.2 KiB | see appendix | Router counters just before and after the second follow-up (2 files): IPv4 FORWARD rows for DoT (853) and the ONT rules (`br52`/`br56` DROP, `br0` ACCEPT to `192.168.255.0/30`), IPv6 nat PREROUTING (DNS redirect), and the head of IPv6 FORWARD. Deltas: `br52` ONT DROP 23 → 49, `br0` ONT ACCEPT 26 → 55, v6 TCP 53 DNAT 2 → 4, v6 IoT WAN LOG 30 → 59. The v6 TCP 853 DROP row isn't included. | 2026-10-12 ~01:00 (around the probes at 01:00:09; file times are upload times) | Low: internal addresses only | 3, 5 |
| E95 | `firewall_logs/FW_hardening_dns6_ont_retest_2.txt` | 9.1 KiB | `8fa6db33f60d1c15…` | Router syslog filtered to the IoT prefixes around the second follow-up: 34 entries, all from the test host (`b2:1c:d7:ba:85:9d`). ICMP to the ONT (00:48:31); an earlier DNS/DoT run (00:58:24: 2 v6 TCP `IOT_DNS_REDIRECT`, 8 SYNs to `[2606:4700:4700::1111]:853`); the saved run: 10 SYNs to `192.168.255.1:80` (00:58:54–00:59:29), 2 v6 TCP `IOT_DNS_REDIRECT` (01:00:09), 9 SYNs to Cloudflare 853 (to 01:01:16). No IoT device appears. | 2026-10-12 00:48:31 → 01:01:16 | Low–Medium: test-host addresses and MAC | 3, 5 |
| E106 | `firewall_logs/FW_upload.log` | 86.7 KiB | `56e0593985348b18…` | Router syslog filtered to the IoT prefixes after the upload run: 347 entries, all `IOT_TO_WAN_NEW` (test host 215 v4 + 98 v6, Hue 29, SwitchBot 4 (3 to `255.2.0.0`), Meross 1). **Starts at 17:59:45**: the quiet period, Run A and the first 13 min of Run B fell into a syslog rotation. | 2026-10-31 17:59:45 → 18:31:43 | Medium: test-host addresses and MAC, cloud endpoints | 1, 2, 5 |
| E107 | `router_states/upload_before_and_after/` | 51.9 KiB | see appendix | Router state before (17:25:52) and after (18:28:37) the upload capture, 6 files each: FORWARD v4/v6 and `IOT_INPUT` counters, IoT conntrack, `wl0.2` rx/tx byte counters, time. Deltas: `wl0.2` rx +149.86 MB, tx +18.97 MB; IoT → WAN NEW LOG v4 +699 / v6 +267; IoT → main-LAN DROP +184 (test-host SMB retries); ONT drops 0. | 2026-10-31 17:25:52 and 18:28:37 | High: conntrack contains the WAN IPv4 | 1, 3, 5 |
| E23 | `pihole_export.csv` | 2.6 GiB | `3758837d7375bddd…` | Full Pi-hole FTL `queries` table export (`sqlite3 -header -csv pihole-FTL.db "SELECT * FROM queries;"`): 26,019,795 rows, **all networks**. VLAN 114 is unfiltered, VLAN 107 and the main LAN are filtered (blocking active). Re-exported after the tapo capture; supersedes the first export (ended 13:54:28). | 2026-07-12 03:48:00 → 2026-10-11 17:51:28 | **Restricted / never share:** full browsing history of every household client incl. the roommate. Kept only as the source of the trimmed extract. | 5 (source) |
| E24 | `derived/pihole_iot_trimmed.csv` | 534.7 KiB | `8e25b85f1280d80b…` | Trimmed Pi-hole extract: **IoT clients only, experiment windows only**, 3,509 rows. Original columns kept, plus `window`, `time_local`, `device`. Produced by `tools/trim_pihole.py` (see "Pi-hole extract" below). | W1 flat capture, W2 segmented capture, W3 2026-10-11 09:00 → 14:05, W4 tapo capture (export ends 17:51:28) | Low–Medium: IoT client addresses and IoT cloud domains only | 2, 5 (domains behind WAN connections) |
| E25 | `Settings_RT-BE88U.CFG` | 118.0 KiB | `e77d1d2d216e668b…` | Web-UI settings backup: the only nvram record of state A (flat). Trivially reversible encoding (`HDR2`). | state A | **Secret:** router admin credentials, Wi-Fi passphrases. Never share. | 5 (lab configuration) |
| E26 | `nvram_flat.txt` | 117.8 KiB | `834d7243b5cb5485…` | Decoded `.CFG` (5468 entries) | state A | **Secret** (as above) | 5 (lab configuration) |
| E27 | `nvram.txt` | 118.3 KiB | `a6a4a5218ffe8bff…` | nvram dump, state B (VLAN 107 created in GUI) | state B | **Secret:** Wi-Fi passphrases (`*_wpa_psk`, `apg*_security`), public addresses | 5 (lab configuration) |
| E28 | `nvram_seg.txt` | 118.0 KiB | `fe0380973c00830d…` | nvram dump, state C (segmented) | state C | **Secret** (as above) | 5 (lab configuration) |
| E29 | `nvram_tweak.txt` | 118.0 KiB | `b0bdd63aec0aa9c9…` | nvram dump, state D (UDP timeout 1800 s, `ct_expect_max` 8192). Every later change (the rest of D, and E) is scripts-only, so this is also the current nvram. | state D (and E) | **Secret** (as above) | 5 (lab configuration) |
| E30 | `asuswrt-configs/ (git repo)` | — | `904f54de74ed` (git HEAD) | Router scripts and configs. Content-addressed by git: **HEAD `904f54de74ed`** ("ONT: config in ont_config.env, block ONT management from every VLAN"), 34 tracked files, working tree clean. | commits `c3684e6` → `904f54d` | Local only, never pushed. **Contains a secret:** `scripts/ddns-start` holds a plaintext DDNS credential. Redact it only in the copy that goes into the shared bundle. | 5 (codebase, rules) |
| E52 | `derived/active/nmap_main_to_iot_tcp.xml` | 28.3 KiB | `be366b37e8398cbd…` | Active test, main LAN → IoT, TCP top-1000 + version detection (nmap 7.95, 2026-10-11 15:29–15:31) | 2026-10-11 | Low: IoT addresses/services | 3, 5 |
| E53 | `derived/active/nmap_main_to_iot_tcp.nmap` | 1.9 KiB | `c80bd240b277270c…` | Same, human-readable output | 2026-10-11 | Low | 3, 5 |
| E54 | `derived/active/nmap_main_to_iot_tcp.gnmap` | 1.4 KiB | `c882054a287d1f5a…` | Same, greppable output | 2026-10-11 | Low | 3, 5 |
| E55 | `derived/active/nmap_main_to_iot_udp.xml` | 8.3 KiB | `6cf7915466ba894d…` | Active test, main LAN → IoT, selected UDP ports | 2026-10-11 | Low | 3, 5 |
| E56 | `derived/active/nmap_main_to_iot_udp.nmap` | 2.0 KiB | `afcfa4e7b5f5c50c…` | Same, human-readable output | 2026-10-11 | Low | 3, 5 |
| E57 | `derived/active/nmap_main_to_iot_udp.gnmap` | 1.8 KiB | `73d44aacb2e1a728…` | Same, greppable output | 2026-10-11 | Low | 3, 5 |
| E58 | `derived/active/hue_api0_config.json` | 229 B | `50c3423448a6b744…` | Unauthenticated `GET /api/0/config` response from the Hue Bridge (model, firmware, API version, bridge ID, MAC) | 2026-10-11 | Low: own device identifiers | 3, 5 |
| E59 | `derived/active/nmap_main_to_iot.started` | 26 B | `24922fd60b11f244…` | Active test start timestamp (UTC) | 2026-10-11 | Low | 3, 5 |
| E60 | `derived/active/nmap_main_to_iot.finished` | 26 B | `d74d4f5eab23878e…` | Active test end timestamp (UTC) | 2026-10-11 | Low | 3, 5 |
| E90 | `iot_active/` | 632.6 KiB | see appendix | Active test **from the IoT VLAN**: nmap 7.99 from a MacBook on `I0N_IoT` (`wifi.txt`: `192.168.107.8`, `fd00:d:e:6b:4b0:2628:1856:4090`, private MAC). `1_lan_ping` (ICMP sweep of the main LAN), `2_lan_tcp` (main LAN /24, TCP top-100), `3_lan_udp` (key hosts, selected UDP), `4_router_tcp`/`_udp` (router at `192.168.107.1` and `192.168.0.1`, all TCP ports + versions, selected UDP), `5_v6_tcp` (router and main-LAN ULAs), `6_rm_gw` (router address `192.168.114.1` only), each as `.nmap`/`.gnmap`/`.xml`; `context.txt` (interface, routes, resolvers), `iot2lan.started`/`.finished` (UTC), `terminal_history.txt` (full session incl. `sntp`, `ping6`, DNS-bypass probes). | 2026-10-11 21:57:08 → 22:11:48 | Medium: test-host MAC/addresses, internal service inventory, laptop host name in the shell prompt | 1, 3, 5 |
| E93 | `iot_retest/` | 32.1 KiB | see appendix | **State E re-test from the IoT VLAN** (same MacBook as E90): `r1_router_tcp` (router TCP select ports on `192.168.107.1`, `192.168.0.1`, `192.168.114.1`), `r2_router_alltcp` (all TCP on `192.168.107.1`), `r3_router_udp` (selected UDP), `r4_v6` (`fd00:d:e:6b::1`), each as `.nmap`/`.gnmap`/`.xml` (nmap 7.99, commands in the XML `args`); `retest.started`/`.finished` (UTC); `terminal_history.txt` (outputs only: nmap, `dig` redirect probes and an `example.com` control, `nc` to `1.1.1.1:853` and `192.168.0.1:22`, `sntp`, `ping`); `router_term_out.txt` (router side: STP before and after `service restart_wireless`, IoT ULA, INPUT/`IOT_INPUT`/nat PREROUTING/FORWARD dump right after the restart); `hardening_dns6_retest.txt` (IPv6 DNS follow-up: `nslookup diag.meethue.com` against Pi-hole, Cloudflare v6, the router's main-LAN ULA and a nonexistent ULA; all answered with Pi-hole's block answers; UDP only, no counters); `hardening_dns6_ont_test_2.txt` (second follow-up, 2026-10-12 01:00:09: `nc 192.168.255.1 80` and `nc -6` to Cloudflare 853 time out; `dig +tcp` over IPv6 to Cloudflare and the router returns Pi-hole's block answer with EDE 15). | 2026-10-11 23:55 → 2026-10-12 00:02:30; follow-ups 00:28 (file time) and 01:00:09 | Medium: test-host addresses, router service inventory; laptop host name in the shell prompt (`hardening_dns6_retest.txt`) | 1, 3, 4, 5 |
| E108 | `upload_run/` | 228.6 KiB | see appendix | Upload-scenario run files: `timeline.txt` (capture, Run A, Run B, capture end; epoch + local time), `wifi.txt` (test host interface/DHCP info; `ifconfig` masks the MAC), `dnsmasq-1.leases` (IoT leases at the start: 8 clients incl. the test host `42:e3:fe:60:6c:d9` at `.13`), `disabled_services.txt` (what was quieted on the test host), `pihole_upload_window.csv` (Pi-hole queries from `192.168.107.0/27`, 2,137 rows; MEGA API/storage names, `reqstat.api.mega.co.nz` blocked), `mega-ls.txt` (MEGAcmd `mega-ls -l upload_run/`: `bulk.bin` 104,857,600 B + `s_1.bin` … `s_30.bin` at 16,384 B with dates; recorded after the run and added to the folder later on 2026-10-31, first as a names-only listing, then replaced the same day by this `-l` version). | 2026-10-31 17:25 → 18:28 | Medium: test-host identity, its DNS history for the hour (incl. main-LAN service names); no MEGA credentials | 1, 2, 5 |
| E110 | `function_check/function_checklist_20261102.md` | 22.6 KiB | `fe906c7bf874399c…` | Filled function checklist for state E (from `planning/function_checklist_template.md`), run by the owner: run details, preconditions P1–P4 (lease lines for the HomePod and all seven IoT devices, `IOT_INPUT` head, redirect count), checks A1–A9, B1–B4, C1–C4, D1–D3, E1–E4 with result, time and evidence (command outputs, remarks), summary table, and the end-of-run snapshot: IPv4 FORWARD counters, `IOT_INPUT` counters (taken a little after the run), IoT conntrack (14 entries), and the `IOT_TO_LAN_DROP` entries of the run (25: 20 v4, 5 v6; all Matter reports, source port 5540). Overall: metric 4 met. **Revised by the owner on 2026-11-02** (E1 counter reading, the `IOT_INPUT` snapshot and the overall line added) before it was hashed in this form; image links point to `screenshots/`, renamed by row ID. | 2026-11-02 00:17 → 01:21 | High: the conntrack lines contain the WAN IPv4 (redact); tester's name; internal addresses, device MACs, the iPhone ULA | 4, 5 |
| E111 | `function_check/screenshots/` | 8.1 MiB | see appendix | Screenshots for the function checklist, named after the row ID: `A1_home_app_hue`, `A7_homekit_scene`, `A8_homekit_automation`, `A9_eve_room`, `B1_hue_app_local`, `B2_hue_bridge_status` (bridge ID scribbled out by the owner; software 6.3.1978545030, IP `192.168.107.26`), `B3_tapo_app`, `B4_switchbot_app`, `C1_home_hubs_remote` (on 5G, Wi-Fi off): iPhone screenshots, 00:27–00:44. `E2_pihole_query_log`: Pi-hole web UI, query log filtered on `192.168.107.` (1,955 of 217,254 entries; last query 01:07:40). | 2026-11-02 00:27 → 01:09 | Low–Medium: room, scene and automation names, device names | 4, 5 |
| E61 | `tools/setup_env.sh` | 791 B | `31fba5358c540e5d…` | Re-installs tshark, Zeek 8.0 (OBS repo), nmap, jq after a terminal reset | — | Low | 5 (reproducibility) |
| E62 | `tools/run_zeek.sh` | 539 B | `30b816674f431c32…` | Runs Zeek over every capture | — | Low | 5 (reproducibility) |
| E63 | `tools/zeek/iot-local.zeek` | 944 B | `3a62544e67abe5dc…` | Zeek site policy (JSON, MAC logging, cert validation, known hosts/services) | — | Low | 5 (reproducibility) |
| E64 | `tools/tls_fingerprints.sh` | 641 B | `4209b2365c200ac8…` | tshark JA4/JA3/SNI extraction | — | Low | 5 (reproducibility) |
| E65 | `tools/pcap_inventory.py` | 2.8 KiB | `b9e23cec04bc8693…` | Dependency-free pcap summariser (classic pcap, Ethernet, 802.1Q aware) | — | Low | 5 (reproducibility) |
| E66 | `tools/analyze_pcaps.py` | 10.4 KiB | `0c115a5f01f9b27f…` | Per-device flow / DNS / TLS-SNI / mDNS analysis of the captures (VLAN-tagged frames skipped) | — | Low | 5 (reproducibility) |
| E67 | `tools/summarize_flows.py` | 3.4 KiB | `a8da9d0c57d756a0…` | Aggregates flows and summaries into per-device baselines | — | Low | 5 (reproducibility) |
| E68 | `tools/trim_pihole.py` | 3.9 KiB | `e1a8490f2c2c5548…` | Pi-hole extract filter (windows × IoT addresses) | — | Low | 5 (reproducibility) |
| E109 | `tools/volume_eval.py` | 7.3 KiB | `4e70620caef53909…` | Volume-upload evaluation: IP-layer bytes per device per minute from the upload capture, MEGA attribution from its Zeek logs, R3-seg/R3-dev against the segmented baseline (→ `derived/analysis/upload_eval.json`) | — | Low | 5 (reproducibility) |
| E112 | `pipeline/iotpipe.py` | 46.7 KiB | `a85d963d1a06f0ff…` | **Splunk pipeline** (`iotpipe` 0.1, Python standard library): `check`, `zeek`, `prepare` (pcaps, Zeek logs, firewall logs, Pi-hole export and annotations → 11 sourcetypes of device-attributed events + lookups), `app` (Splunk app), `send` (HEC). Attribution by MAC, home-interface counting, Zeek direction fix, own public prefixes masked. Guide: `pipeline_guide.md`; reproduces the analysis numbers (guide §5.2, analysis §18) | 2026-11-03 (dashboard deliverable) | Low | 2, 5 (dashboard) |
| E113 | `pipeline/dashboard.py` | 35.2 KiB | `21498332ec094960…` | Detection macros (R1–R12, FW, DEV; recommendations 20 and 22 built in) and the overview dashboard (Simple XML, dark theme), written into the app by `iotpipe app` | 2026-11-03 (dashboard deliverable) | Low | 2, 5 (dashboard) |
| E114 | `pipeline/zeek/iot-local.zeek` | 1.1 KiB | `12133308ecbcf27a…` | Zeek site policy for the pipeline (a copy of `tools/zeek/iot-local.zeek` with a header comment) | 2026-11-03 (dashboard deliverable) | Low | 2, 5 (dashboard) |
| E115 | `pipeline/site.toml` | 3.8 KiB | `e91abfef52442c38…` | Site description for this project: networks, device inventory by MAC, controllers, capture metadata (baseline flags), inputs. No secrets; the own public prefixes live in `site.private.toml`, which is neither hashed nor shared | 2026-11-03 (dashboard deliverable) | Medium: internal addresses, device MACs, controller addresses | 2, 5 (dashboard) |
| E116 | `pipeline/site.example.toml` | 5.1 KiB | `b2cff3a14d0eb538…` | Commented template for other sites | 2026-11-03 (dashboard deliverable) | Low | 2, 5 (dashboard) |
| E117 | `pipeline/annotations.csv` | 2.3 KiB | `fc2621129794f085…` | Ground-truth markers for the dashboard timeline (24 lines), compiled from E16, E108, E110 and the analysis | 2026-11-03 (dashboard deliverable) | Low | 2, 5 (dashboard) |
| E118 | `pipeline/guide_images/` | 2.5 MiB | see appendix | Dashboard screenshots on Splunk Enterprise 10.6.1.1 (2026-11-03), cropped (browser bar, account menu and side menu removed): full page in two halves, each dashboard section, and two filter examples (upload recording; VFD recording with real devices only). Used in `pipeline_guide.md` §7.3 | 2026-11-03 (dashboard deliverable) | Low–Medium: device names, internal addresses, cloud endpoints; the router's public IPv6 shown masked | 2, 5 (dashboard) |
| E119 | `dashboard_screenshots/` | 5.3 MiB | see appendix | Original dashboard screenshots (owner, Splunk Enterprise 10.6.1.1): 10 browser-window screenshots and the full page in two halves (`full_1.png`, `full_2.png`). The two taken at 16:17 and 21:58 show the dashboard before the label fixes of 2026-11-03 (rule names hidden on the rule chart, a time chart instead of the per-recording chart). E118 holds the cropped versions used in the guide | 2026-11-03 16:17 → 22:36 (file names) | **High:** the browser bar shows the household's DDNS host name and port, and Splunk's bar the account name. Share only the cropped E118 images | 2, 5 (dashboard, provenance of E118) |

Metric numbers refer to the Learning Contract evaluation metrics: 1 scenarios executed, 2 suspicious-behaviour detections, 3 inter-segment reachability blocked, 4 device functions preserved, 5 reproducible evidence.

### Moved files (since the first manifest)

| ID | Current path | Path in the first manifest | Content |
|---|---|---|---|
| E16 | `interaction_timeline.txt` | `app_int_timeline.txt` | extended (old SHA-256 `cc64e0c797b9fcef…`) |
| E17 | `firewall_logs/FW_log_3h.log` | `FW_log_3h.log` | unchanged (same SHA-256) |
| E18 | `firewall_logs/FW_log_app_interaction.log` | `FW_log_app_interaction.log` | unchanged (same SHA-256) |
| E19 | `firewall_logs/FW_matter-5540-iot-lan-drop.log` | `matter-5540-iot-lan-drop.log` | unchanged (same SHA-256) |
| E20 | `router_states/after_app/fw4_counters_1401.txt` | `Router state after app interaction/fw4_counters_1401.txt` | unchanged (same SHA-256) |
| E21 | `router_states/after_app/fw6_counters_1401.txt` | `Router state after app interaction/fw6_counters_1401.txt` | unchanged (same SHA-256) |
| E22 | `router_states/after_app/conntrack_iot_1401.txt` | `Router state after app interaction/conntrack_iot_1401.txt` | unchanged (same SHA-256) |

## Regenerable outputs (not hashed, no IDs)

Produced from the hashed captures by the hashed tools; rebuild them instead of verifying them. They change whenever a tool is improved or a capture is added, which is why they sit outside `SHA256SUMS`. The analysis cites them by path.

| Output | Command (from the working folder) | Former IDs | Sensitivity |
|---|---|---|---|
| `derived/pcap_inventory.json`: per-pcap packet counts, first/last timestamps, VLAN-tagged frames, source MAC → IP map. Also an input to `trim_pihole.py` and to this manifest. | `python3 tools/pcap_inventory.py derived/pcap_inventory.json 2026*/*.pcap` | E31 | Medium: every MAC/address seen, incl. main LAN and VLAN 114 (flat capture) |
| `derived/analysis/`: `flows_<cap>_<iface>.csv` (per-device flow tables, Splunk-ingestible), `summary_<cap>_<iface>.json` (DNS, TLS SNI, mDNS exposure, odd destinations, hourly cloud volume), `baselines.json` | `python3 tools/analyze_pcaps.py && python3 tools/summarize_flows.py` | E32–E44, E82–E85 | Medium: main-LAN hosts and `<PD>` GUA entries (class `mainlan_gua`); remap before sharing |
| `derived/zeek/<cap>_<iface>/`: Zeek 8.0 JSON logs (BPF `not vlan`) | `sh tools/run_zeek.sh` (Zeek from `tools/setup_env.sh`) | E45–E50, E86–E87 | **High:** `flat_eth7`/`seg_eth7` `http.log` hold the Hue `sso` token; flat-state logs hold main-LAN host names |
| `derived/tls/clienthello_fingerprints.tsv`: JA4/JA3 + SNI of every TLS ClientHello | `sh tools/tls_fingerprints.sh` | E51 | Low–Medium: device addresses, cloud endpoints |
| `pipeline_out/`: Splunk events (`splunk/*.ndjson`, 64,721 events), lookups, the Splunk app (`iot_segmentation.tgz`), Zeek logs (`zeek/`), `prepare_report.json` | `python3 pipeline/iotpipe.py all` (E112–E117; Zeek and tshark from `tools/setup_env.sh`) | — | Medium: device-attributed traffic metadata; own public addresses masked. `zeek/` is raw and unmasked (High, like `derived/zeek/`) |
| `derived/analysis/upload_eval.json`: upload-scenario volumes per window and clock hour, MEGA attribution, control devices (analysis §16) | `python3 tools/volume_eval.py` (after `run_zeek.sh` has processed `20261031-172658_upload/`) | — | Medium: test-host and cloud addresses |

Order matters only for the inventory: run `pcap_inventory.py` before `trim_pihole.py`.

## Capture set overview

| Capture | State | Interfaces | Duration | Packets (wl0.2 / eth7) | Kernel drops | Offload |
|---|---|---|---|---|---|---|
| `20261006-215327_flat` | A: flat (IoT on `br0`) | `wl0.2`, `eth7` (trunk: untagged `br0` + tagged 107/114) | 24 h | 858,199 / 958,030 | 0 / 0 | fc + runner disabled for the run |
| `20261010-002759_seg` | C → D (UDP timeout fix applied during the run, ~12:35 on 10-10) | `wl0.2`, `eth7` (access port, VLAN 107) | 24 h | 434,540 / 508,423 | 0 / 0 | fc + runner disabled for the run |
| `20261011-134542_app_interaction` | D + `IOT_TO_WAN_NEW` logging | `wl0.2`, `eth7` | 7 min 4 s (stopped manually) | 2,435 / 3,065 | 0 / 0 | fc + runner disabled for the run |
| `20261011-164338_tapo` | D at `d0c3085`: IoT NTP and reflector filter (`75807a2`, `d0c3085`) | `wl0.2`, `eth7` | `eth7` 70 min (stopped manually); **`wl0.2` 19 min 33 s** (interface disappeared at 17:03:11) | 8,694 / 17,401 | 0 / 0 | fc + runner disabled for the run |

## IoT device address map (from the captures)

| MAC | Device (working name) | State A address (main LAN) | State C–E IPv4 | State C–E IPv6 (SLAAC) | Port |
|---|---|---|---|---|---|
| `ec:b5:fa:bc:52:10` | Hue Bridge (Philips Lighting / Signify OUI) | `192.168.0.50` | `192.168.107.26` | `fd00:d:e:6b:eeb5:faff:febc:5210` | `eth7` |
| `0c:4e:a0:30:22:54` | SwitchBot Hub 2 | `192.168.0.48` | `192.168.107.15` | — (no IPv6 seen) | `wl0.2` |
| `8c:87:d0:09:0d:6b` | Matter switch (likely Zemismart; vendor unverified) | `192.168.0.21` | `192.168.107.17` | `fd00:d:e:6b:8e87:d0ff:fe09:d6b` | `wl0.2` |
| `8c:87:d0:09:0d:6e` | Matter switch (likely Zemismart; vendor unverified) | `192.168.0.19` | `192.168.107.20` | `fd00:d:e:6b:8e87:d0ff:fe09:d6e` | `wl0.2` |
| `7c:f1:7e:10:03:a0` | Tapo smart plug | `192.168.0.207` | `192.168.107.23` | `fd00:d:e:6b:7ef1:7eff:fe10:3a0` | `wl0.2` |
| `c4:e7:ae:20:54:57` | Meross smart plug (joined 2026-10; not baselined) | — | `192.168.107.2` | link-local only seen | `wl0.2` |
| `d8:f1:5b:90:ee:b3` | LGL VFD clock VCK 0658-L (joined 2026-10; not baselined) | — | `192.168.107.22` (`169.254.180.238` link-local while DHCP failed, upload capture) | — | `wl0.2` |

Test host on the IoT VLAN (not an IoT device): MacBook, private MAC `b2:1c:d7:ba:85:9d` at `192.168.107.8` (2026-10-11 tests) and `42:e3:fe:60:6c:d9` at `192.168.107.13` (upload scenario, 2026-10-31). `.13` was the HomePod's address in the state E re-test, so attribution is by MAC.

Apple Matter controllers seen talking to IoT devices (main LAN): the **HomePod** `192.168.0.22` / `fd00:d:e:f:183e:4f13:4044:5684` (`ac:bc:b5:…`, home hub, the destination in the Matter drop log), and the **iPhone** `192.168.0.221` (`94:89:78:…`), which held Matter sessions (UDP 5540) to the Matter switch `.17`, the Hue Bridge `.26` and the SwitchBot hub `.15` in the post-interaction conntrack snapshot. The phone acts as a controller directly while the Home app is in use. The owner's **Mac Studio** `192.168.0.2` does the same while its Home app is open (Matter session to the Tapo plug in the function-checklist conntrack, E110); it also queried the VFD clock's NTP service in the VFD boot capture.

Transient addresses in the tapo capture (also in `derived/pcap_inventory.json`): the **Tapo plug** announces `192.168.1.80` by gratuitous ARP before taking its DHCP lease (16:45:15 after the firmware-update reboot, 17:10:45 on a Wi-Fi rejoin); no IP traffic uses it. The **Hue Bridge** used the IPv4 link-local address `169.254.11.47` for ~18 s after its power cycle (16:46:37 → DHCP ACK 16:46:55).

## Pi-hole extract (`derived/pihole_iot_trimmed.csv`)

**Command:** `python3 tools/trim_pihole.py` (defaults: `pihole_export.csv`, `derived/pcap_inventory.json` → `derived/pihole_iot_trimmed.csv`). Odd bytes in domain names are preserved (`surrogateescape`). Re-running it on the current export reproduces the file byte for byte.

**A row is kept only if both conditions hold:**

| Window | From | To | Client must be |
|---|---|---|---|
| W1_flat_capture | 2026-10-06 21:53:27 | 2026-10-07 21:53:29 | one of the IoT devices' **main-LAN** addresses during state A (mapped by MAC from the flat capture) |
| W2_seg_capture | 2026-10-10 00:27:59 | 2026-10-11 00:28:02 | in `192.168.107.0/27` or `fd00:d:e:6b::/64`, or a mapped IoT address from the later captures |
| W3_fwlog_app_interaction | 2026-10-11 09:00:00 | 2026-10-11 14:05:00 | in `192.168.107.0/27` or `fd00:d:e:6b::/64`, or a mapped IoT address from the later captures |
| W4_tapo_capture | 2026-10-11 16:43:38 | 2026-10-11 17:53:44 | in `192.168.107.0/27` or `fd00:d:e:6b::/64`, or a mapped IoT address from the later captures |

Everything else is dropped: all main-LAN hosts (homelab, phones, computers), all of VLAN 114 (roommate), and all other periods. 26,019,795 rows → **3,509 rows**.

| Window | Hue Bridge | SwitchBot Hub 2 | Tapo smart plug | Matter switches | Notes |
|---|---|---|---|---|---|
| W1_flat_capture | 935 | 29 | 6 | 0 |  |
| W2_seg_capture | 1,966 | 29 | 5 | 0 |  |
| W3_fwlog_app_interaction | 354 | 5 | 1 | 0 | complete now; the first export ended at 13:54:28 (Hue 345 then) |
| W4_tapo_capture | 161 | 5 | 13 | 0 | the export ends at 17:51:28, 2 min before the window ends |

**Column codes** (Pi-hole FTL schema): `type` 1 = A, 2 = AAAA. `status` 1 = blocked (gravity), 2 = forwarded, 3 = answered from cache, 17 = answered from stale cache; 0 = unknown. `reply_type`, `dnssec`, `list_id` and `ede` are left as exported.

**Caveats:** in W1 the IoT devices used dynamic main-LAN DHCP addresses. A reused address within the 24 h window would be misattributed. The 24 h lease time makes this unlikely, but it hasn't been ruled out. The later-window address map also contains the Tapo's transient `192.168.1.80`; no Pi-hole row has that client.

## Observations noted while building the manifest (to verify in analysis, not conclusions)

### From the first manifest (2026-10-11 15:34; since examined in `analysis.md`)

- **SwitchBot Hub 2 sends mDNS (UDP 5353) to `255.2.0.0` through the WAN:** 91 of its 94 `IOT_TO_WAN_NEW` entries in `FW_log_3h.log` and all 9 in the app window. That isn't a valid multicast or broadcast destination. It looks like a firmware bug, and it uses up the log rate limit. Candidate anomaly / scenario.
- **No IoT IPv6 traffic to the WAN:** the IPv6 `IOT_TO_WAN_NEW` rule counter is 0, and every logged WAN connection is IPv4. NAT6 appears unused by these devices.
- **Matter switches made no DNS queries in any window:** consistent with local-only (Matter) operation with no cloud dependency.
- **Hue Bridge blocked (status 1) queries rose from 58 (W1) to 1,066 (W2).** Its total query count roughly doubled while forwarded/cached counts stayed similar. Needs a per-domain look; possibly retries of a blocked domain.
- **The app-interaction capture ran for only 7 min** and the timeline has start times only for the app sessions. Eve traffic isn't expected on the IoT network at all (Eve Room uses Thread via the HomePod on the main LAN, and the Eve app runs on the phone).
- **Router state for the app-interaction window was captured after the interaction only (14:01),** so rule counters can't be diffed for that window. The tapo capture has before/after snapshots (below).
- **The iPhone (`.221`) is a direct Matter controller during app use,** in addition to the HomePod hub. Its sessions are main LAN → IoT, which the policy allows. Its Home-app cloud traffic stays on the main LAN and isn't in the IoT captures; same for the Eve, Hue and SwitchBot apps.
- **Thread-related traffic in the flat capture** (reported during initial analysis): consistent with a Thread border router's traffic flooding `br0` while the IoT SSID was bridged into it. For example, `6c:a6:04:b5:39:28` (`192.168.0.15`) uses the separate ULA `fd05:37e5:64c4::1`.
- **The flat `eth7` capture contains 89,336 VLAN 114-tagged frames** (roommate network): `eth7` was a trunk in state A. Out of scope; must be removed in the sanitised bundle.

### From the tapo capture (2026-10-11 16:43–17:53; since examined in `analysis.md` §13)

- **`wl0.2` stopped at 17:03:11, and Wi-Fi clients rejoined twice.** tcpdump reported `pcap_loop: The interface disappeared`; the last `wl0.2` frames are Broadcom driver event frames (EtherType `0x886c`) from the router. `eth7` still sees the VLAN's flooded broadcast/multicast: the SwitchBot hub and the Tapo plug rejoin (DHCP DISCOVER/REQUEST, ARP probes) at **17:03:26** and again at **17:10:45–17:10:51**, consistent with two wireless restarts. Unicast Wi-Fi traffic after 17:03:11 isn't captured.
- **Matter switches absent until 17:10:54.** Neither switch sent a frame on either interface from the capture start. Both rejoin together at 17:10:54–17:11:02 (DHCP), with the second Wi-Fi rejoin and ~1.5 min before the logged switch power cycle (17:12:29). At 14:01 the iPhone still had a session to `.17` (E22). Explained afterwards: the owner had restarted wireless before the capture, and there was no recurrence after a power cycle (`analysis.md` §13.7).
- **No Matter sessions at 16:43.** The before snapshot (E78) holds no UDP 5540 session for any IoT device, although the Hue Bridge, SwitchBot hub and Tapo plug were online; the after snapshot (E81) has HomePod sessions to all five Matter devices. The firewall had been reloaded minutes before 16:43 (only ~11k packets through FORWARD in E76). Possible explanation, to confirm: connection tracking was cleared or had expired, and the HomePod re-established the sessions later. The `br52 → br0` DROP rule stayed at 0 packets in both snapshots, so no IoT → main-LAN packet was dropped in the window.
- **Router state is bracketed:** before (16:43, E76–E78) and after (17:51, E79–E81). The IPv4 `IOT_TO_WAN_NEW` LOG counter rose 60 → 326 (+266), against 247 entries in E75, so ~19 entries fell into the 17:14:30 → 17:31:07 syslog gap (~1.2/min; the log runs at ~1.5–2/min either side of it). A firewall restart inside the window would need 100+ lost entries (≥6/min), so the delta is valid. The IPv6 LOG counter and both `IOT_TO_LAN_DROP` LOG counters stayed at 0.
- **Hue public NTP volume is up:** 185 of the Hue's 210 `IOT_TO_WAN_NEW` entries (16:43–17:50; ~50 min of log excluding the gap) are NTP to public servers (Google, Cloudflare, Apple, Alibaba), against 77 in ~3 h of `FW_log_3h.log`. Possible contributors: boot-time sync after the 16:46:04 power cycle, and fallback because its NTP requests to `192.168.107.1` get ICMP port unreachable (`segmentation_report.md` §1.9).
- **Tapo firmware update** (16:43:50 → 16:45:36): 13 Pi-hole queries in W4 (1–6 in each earlier window) and 10 `IOT_TO_WAN_NEW` entries in three clusters: update and reboot (16:44–16:45), then each Wi-Fi rejoin (17:03, 17:10). Domains, JA4 and download volume are in `analysis.md` §13.2.
- **SwitchBot `255.2.0.0` leak persists** after the reflector filter: 23 of its 27 `IOT_TO_WAN_NEW` entries.

## Sanitised bundle plan (after analysis)

- **Never include:** `Settings_RT-BE88U.CFG`, `nvram_flat.txt`, raw nvram dumps, `pihole_export.csv`, raw conntrack (`router_states/*/conntrack_iot_*.txt`, which contain the WAN IPv4).
- **pcaps:** drop VLAN-tagged frames (`not vlan`). Keep only frames to/from IoT MACs and the router (removes main-LAN hosts' multicast and hostnames from the flat capture). Remap `<PD>` and the WAN IPv4 (`tcprewrite`). Truncate main-LAN controller flows to headers if needed. The flat and segmented `eth7` pcaps contain the Hue `sso` token in cleartext HTTP (port 80): drop or truncate those payloads.
- **nvram:** share as redacted diffs (`segmentation_report.md` section 2) or with `*_psk`, `*_security`, `http_passwd`, `acc_list`, `wan0_ipaddr` and prefix keys removed.
- **Logs (`firewall_logs/`) and rule counters:** keep as-is apart from replacing the WAN IPv4, `<PD>` and `<WAN-RA>` if present (also in zero-padded IPv6 form, e.g. in `FW_hardening.log`). In `router_states/hardening_before_and_after/`, `nat4_prerouting_*` carry the WAN IPv4 and `ipv6_addr_*` carry `<PD>`/`<WAN-RA>`. Device MACs may stay (own devices).
- **Zeek logs:** redact the Hue `sso` token in `http.log`; drop main-LAN host names from the flat-state logs.
- **Repo:** it stays local. If scripts go into the bundle, include `firewall-start`, `dnsmasq-sdn.postconf`, `avahi-daemon.postconf`, `iot-capture.sh` and the VLAN helpers, and leave `ddns-start` out (or redact it).
- **Bundle integrity:** produce a fresh `SHA256SUMS` for the bundle, and record in it the hash of each raw source file it was derived from.
- **Team bundle (built 2026-10-12, internal):** `team_bundle/`, made by `tools/make_team_bundle.py` (not hashed: it holds the real values; never share it). Lighter redactions for teammates' analysis: public addresses remapped to documentation ranges, the Hue token overwritten, VLAN-tagged frames dropped, the roommate router MAC remapped, checksums recomputed. Internal addresses, MACs and host names stay. Secrets, nvram, the full Pi-hole export, `ddns-start` and the git history are left out. It has its own `SHA256SUMS` and `PROVENANCE.tsv` (source file, source SHA-256, transformation). Rebuilt 2026-10-14 in the submission layout (below) and frozen read-only. The submission bundle (next item) replaces it in the shared repo.
- **Submission bundle (built 2026-11-03):** `submission_bundle/`, made by `tools/make_submission_bundle.py` (not hashed: it holds the real values; never share it). It carries out the stricter plan above. On top of the team bundle's redactions: pcaps keep only frames to or from an IoT device or a test host, plus the router's own broadcast and multicast, so the other household hosts' frames are gone; the router's ASUS discovery broadcasts (UDP 9999 and 7788, which announce its DDNS name) are dropped; the nvram dumps are replaced by allow-listed extracts of the segmentation keys (`nvram_extract/`); `derived/zeek/`, `derived/tls/`, `derived/analysis/` and `derived/pcap_inventory.json` are regenerated inside the bundle from the sanitised pcaps with the hashed tools; E119 and `pipeline_out/zeek/` are left out. The conntrack snapshots in `router_states/` are included with the WAN IPv4 remapped, not raw. Its `README.md` lists every redaction and the small differences from the working folder; `SHA256SUMS` and `PROVENANCE.tsv` work as in the team bundle. `submission_bundle.obsolete.txt` lists the team-bundle files it no longer has, to delete when it is copied over the team bundle.
- **Submission layout:** both bundles are overlays of the main project repo (`01-Subject Report/`, `02-Code/`, `03-Result/`, `04-Contribution Table/`, `05-Work Summary/`) and only add this part's subfolder `IoT-Segmentation/` under `02-Code/` and `03-Result/`. In the submission bundle, `02-Code/IoT-Segmentation/` holds `tools/` (without the two bundle builders), `pipeline/` (without `site.private.toml`), `pipeline_guide.md` and the router repo export `asuswrt-configs/` (without `ddns-start`, with `GIT_LOG.txt`). `03-Result/IoT-Segmentation/` holds the bundle's `README.md`, `SHA256SUMS` (paths relative to the repo root) and `PROVENANCE.tsv`, the intermediate reports (`segmentation_report.md`, `analysis.md`, this manifest, `results_to_evidence.md`), all evidence with their working-folder paths (so the evidence paths in the reports resolve inside it), `derived/`, `planning/` and `pipeline_out/`. The intermediate reports never go into `01-Subject Report/`, which holds the team's main report.

## Appendix: full SHA-256

```
c8b3350e0ba17f5d5f5ae82a94d57d21c5e1e171e5d5f8555cd49964d32e22d7  20261006-215327_flat/eth7.log
e64ae52115b3c30f0137e38687e4afe6bc2e3e613b3a3677d7363cc1365a96df  20261006-215327_flat/eth7_20261006-215327.pcap
4dc4c87985baa7f98e90f3fa178e4c6aa79c46ca0dcdbf7fce51d86978e4f9fb  20261006-215327_flat/run.log
a48e61d665f044ea281d9964126e71e6abf20fbb377f746f9fa3336113d9e651  20261006-215327_flat/wl0.2.log
88be144e5f5727887bfb8e60544624d663fd1aa0ea73fa6fcddafeb79b74e492  20261006-215327_flat/wl0.2_20261006-215327.pcap
f24a72a2bcb51a5ddf75b1569307fdb8c1e6e67f1ac8e23a8116d9b85c28343d  20261010-002759_seg/eth7.log
de3b9eacbb0a58edd7725765d4ddca6dd8b7287dd36da5fd9ade3c9f6fd2f109  20261010-002759_seg/eth7_20261010-002759.pcap
8432ebb9500aa1c5823391135c992cd76ca161a9f5c8fd97b58996a77a960a2d  20261010-002759_seg/run.log
318dff6d2e3c2b3a0d91d748e5ded5213a9effbfd44279c852ad266a263aebde  20261010-002759_seg/wl0.2.log
a5b3131c4bb484151af48b8b5cb23ff1d511188d0911f1bc617cbe946ab0c63a  20261010-002759_seg/wl0.2_20261010-002759.pcap
1869c22b81884efe7bbdda1e28f4e74d43080905964ce556b2c479af014bb819  20261011-134542_app_interaction/eth7.log
2a0c9219ce754ce1d4373a045db6858fec5cf92701a6e0d84a3745143526a972  20261011-134542_app_interaction/eth7_20261011-134542.pcap
07ad4528b0f78c073a0c33def01ae11da48614f12a8b092b1d0f382dc2d9dde9  20261011-134542_app_interaction/run.log
3e39edecae24e244b07a0de418af3eeaa17f7af4dba92a5dd05d671aa0dcbf08  20261011-134542_app_interaction/wl0.2.log
1111d5f856d138e29a9bd436a074c8cf62d16a73489d576367a4021b6cdcecd9  20261011-134542_app_interaction/wl0.2_20261011-134542.pcap
85006ea310461820dc8db4ba0a6e5bbef177a7835b458e713fd086e1574984e0  20261011-164338_tapo/eth7.log
8d264317c428c8a5f2d7d3ec8eef9261796fcbb88aac88fe32fa1d9eb71d0d78  20261011-164338_tapo/eth7_20261011-164338.pcap
ccf1e0d8fa3be34a51abdc3fa5192ef000cf079501e58db464ce879600bb93aa  20261011-164338_tapo/run.log
64da1d9d4dd0e3c7e16de0ed42ceb782918960b573c19a7e4accf95d089bf187  20261011-164338_tapo/wl0.2.log
ba3877d247a6ebb58870833f98bce59722f15bf0c128d968dd27e042403f58de  20261011-164338_tapo/wl0.2_20261011-164338.pcap
c0f312c9cd3c51db53a5dcee96da84281620f4b52446b37fd887bebed017223a  20261031-172658_upload/eth7.log
0dfa4e742065e1c2323a51c0a8951891d7ee65782801ee542ab616549e34fab7  20261031-172658_upload/eth7_20261031-172658.pcap
e5fd5d77720743192ee740cef53e53d77e4e0e209e2110980248756b84d4d3fe  20261031-172658_upload/run.log
91d9269ef550ca2c1eec1c7ad8f54292b5891b8ec20658ab1ae0542184f9e49d  20261031-172658_upload/wl0.2.log
fcad949847cfe29bc3736070728a60f41bb25cfd71a723633cee6285736867e1  20261031-172658_upload/wl0.2_20261031-172658.pcap
ba5021b0266b79d4f637428ddb8d5b18fe109156ec3c40ea421f40d64379de8b  20261031-184353_vfd/eth7.log
f45dc0109500f0720f2c0fa8d2ac3d86d8472f54b264a71684eec9868a5e1126  20261031-184353_vfd/eth7_20261031-184353.pcap
5b5e4cae44be67ede295e1bb80690c58cda25a2ded4c2b1ca5ceaab593137fd6  20261031-184353_vfd/run.log
d6c00d20c582228f95a58c7c5470036caf1ab163d1fb9118be48f5dd5b234624  20261031-184353_vfd/wl0.2.log
5044ba85e681a425613c74581d7a3c6b783b8caa5eceb776e7d980f8ae80e1f2  20261031-184353_vfd/wl0.2_20261031-184353.pcap
e77d1d2d216e668ba982f1efba0c0fd63762db8a0a094ced51400fd0c4a0314d  Settings_RT-BE88U.CFG
03d104cd65d5ca17be0da0b07aa6199e08e08213026f7ae798fde6a9d9e321e2  dashboard_screenshots/Screenshot 2026-11-03 at 16.17.05.png
8df9acd4b014f6a9c2e961d849e8578ecde258ca4958065cfec4c276b43438f1  dashboard_screenshots/Screenshot 2026-11-03 at 21.58.37.png
66d0c80d829f5dbc1ae8c41a51e5063bcf69245dc16d8b625fc0a423204c505a  dashboard_screenshots/Screenshot 2026-11-03 at 22.30.40.png
fe1bcd2bc23871765d0eb7ac2ac28d786ec854481f1bbdbd7c0ed15e39968987  dashboard_screenshots/Screenshot 2026-11-03 at 22.30.51.png
6ad202e3aa5726beb1b1f1b817d67c4c00f03b549ed62da090ea75bf1acbdd6a  dashboard_screenshots/Screenshot 2026-11-03 at 22.32.15.png
120559099410c3b8ab13657a033778c83a7cccf38173c709c764f9379bcd7f48  dashboard_screenshots/Screenshot 2026-11-03 at 22.32.29.png
4a52bc530122bdf588f29ea6b7019dd9cbcc55a49709db1a127bbfb5fea3276c  dashboard_screenshots/Screenshot 2026-11-03 at 22.32.56.png
30ad05c5b0341f78ac1f67763ea95dc2ef2e0fcc410c01adb0e61262b4acd6b2  dashboard_screenshots/Screenshot 2026-11-03 at 22.34.13.png
10f532e86322c2601643f3f0f2f28bccb49b9820d96e357ceffa78212243c785  dashboard_screenshots/Screenshot 2026-11-03 at 22.34.24.png
87991c8eb2428509e7e9adb4ee1ae6e98d6e4e8ba10bc2ba66828126b5466c92  dashboard_screenshots/Screenshot 2026-11-03 at 22.35.18.png
1781b347fd892317c2a0beee3df8eebc6182f2181e3f67f9dfcf628fc7480efd  dashboard_screenshots/full_1.png
48bb5a3bc6381791481688830f5f75a427da98d291cd389bede50db0943ded53  dashboard_screenshots/full_2.png
50c3423448a6b744f422455e25df5683228231f95228a00ce721f6d5a4571ca9  derived/active/hue_api0_config.json
d74d4f5eab23878e82b54cc0e3b671470c0944e9bb6140def61ac95725768fa0  derived/active/nmap_main_to_iot.finished
24922fd60b11f244050164c0147e821d85e67c45d40cfb232e6b31a425a80e03  derived/active/nmap_main_to_iot.started
c882054a287d1f5a03ecc0ed21a09e2619735fe3831f63f376362c8b3741ffb6  derived/active/nmap_main_to_iot_tcp.gnmap
c80bd240b277270cf18defbd68092c3cbd8caee6dbdeeca1db0380815f031483  derived/active/nmap_main_to_iot_tcp.nmap
be366b37e8398cbd77c8480d085bfa3fab13f6cd08f131be00cbba941d27d33d  derived/active/nmap_main_to_iot_tcp.xml
73d44aacb2e1a7287b1a1238ac73325c4a0c5b4dfad0ff72afcef6b777b3d769  derived/active/nmap_main_to_iot_udp.gnmap
afcfa4e7b5f5c50c75dd110996627d216eeb4f30f9438d77005e349e75c10ebf  derived/active/nmap_main_to_iot_udp.nmap
6cf7915466ba894df12174bb1dfba7baa9284fb9e99f0d59d9f2f9287587371a  derived/active/nmap_main_to_iot_udp.xml
8e25b85f1280d80ba931a8c94767978ffc0d07d1760d8ff1055209326043c344  derived/pihole_iot_trimmed.csv
fd851583a8f11400f34d99b1b2c7becce82759153b0743f51c5bad37e2c6d991  firewall_logs/FW_hardening.log
8fa6db33f60d1c15db2fe2e0e7ec8b7cd6ff26bb61a171206c03287857736af0  firewall_logs/FW_hardening_dns6_ont_retest_2.txt
df88c04c257cfa94dbf71a6b7d1a0c273be511a2d61f06fea460fe8ab0043c62  firewall_logs/FW_iot_active.log
03ed44db52a10097ffd1d44396293157c6860084298d25b1de1f462e68c62a3c  firewall_logs/FW_log_3h.log
e548b20c515f079dc7ceb7384951ec366f222a9f21a2aa1a6cfba62f8f810eda  firewall_logs/FW_log_app_interaction.log
eb7fc30c9075b35806bf22c19976a77c8b9368adc6f26a2e599869460f715e9a  firewall_logs/FW_matter-5540-iot-lan-drop.log
33db6f96e6c18f52210953bd6768677d42e25a4a461aa31a377ec69d8bedcdd9  firewall_logs/FW_tapo_capture.log
56e0593985348b18f65c67924aa395bec6c5405fa833e3c4d021f4537e2e0e05  firewall_logs/FW_upload.log
fe906c7bf874399cd0978d0d31e383b7e6cdd8134807e0b462d0a923a93442e5  function_check/function_checklist_20261102.md
8b4f240b371c616ce8402f05c77275ffb45425ed865c4dc3f2bd3a481c721f09  function_check/screenshots/A1_home_app_hue.png
5db2741d59788fb7781c5fa59358d357ec37d99984870a57799585d3a6395091  function_check/screenshots/A7_homekit_scene.png
53463800ce625726ab049fb63974b6f399defec6001863c6f9e89bb777d54706  function_check/screenshots/A8_homekit_automation.png
27469572e73a9495c2d6fd08e3e0843f358cd182f5b06775f0cdebd0b55abc02  function_check/screenshots/A9_eve_room.png
7f948ddb4b5fcdcd9e0acfeda62198402a9449f5b3def1b8fa158269576bb535  function_check/screenshots/B1_hue_app_local.png
552167691d5eadf1f90dabf17dea6d4233724d9c71cb8413bae1b536df04926f  function_check/screenshots/B2_hue_bridge_status.png
2846460e8d4eb5ce58d485297422faaefaa063f8af045e2a0604220186ee35aa  function_check/screenshots/B3_tapo_app.png
010a7218a590b517a3b2e2f62d708a9e565980f36dd642c46523d6a40d2a78df  function_check/screenshots/B4_switchbot_app.png
bfc33266da3cb24290c39aed71e1ae2c90b4e459aec25aad679157b5efb63caf  function_check/screenshots/C1_home_hubs_remote.png
39b17ca8c30fd41306fd9a1ce216d48c8e7a2b7320c81b7b39c8e3d4c6d4e8de  function_check/screenshots/E2_pihole_query_log.png
c980a6072040c6bcb769687bb4b7906843cccadaf5a6622aae85cf4335817dd6  interaction_timeline.txt
b4d69b5407fbd4779465534bcf84e91681e5efcb9d2635b930e683d36dfa90bb  iot_active/1_lan_ping.gnmap
44aa861fe0ffdef7d4a880fbfc5832c7cdb50a374f21f9303caff174ab052c8c  iot_active/1_lan_ping.nmap
b9e27e45ae80ca82c09555ea1769ae681603d74cf070b9a25f4fc3293a9660b1  iot_active/1_lan_ping.xml
bbe162a39478d6d9db05d376e59be8353dedff66289181fb8b24b18ea674ac7f  iot_active/2_lan_tcp.gnmap
ec1b2cb71b3e7cbe54093a620aefa2db5e1a8a82f1d80f2c843cb5183255d9b6  iot_active/2_lan_tcp.nmap
c832e4a4f0e116000edd290930c790bfb6924c76d596220b332a401c2d4f36ad  iot_active/2_lan_tcp.xml
7e65d161a9bdfe9b9defbbcb5296de131b14309f2d3b95b92f29cdeabe91741e  iot_active/3_lan_udp.gnmap
735cc94e0fd52f9c6bf292e29ece0a254bb062025e0c7343193b747b7f49835c  iot_active/3_lan_udp.nmap
953c4a11497ab9aa17cb6620b5581a7182591fe63b55cc19ba9acb672f7e7a9f  iot_active/3_lan_udp.xml
8ad606beff098e8d213c910047d80e40dbd38de149e406f6a8bc049a06948f9f  iot_active/4_router_tcp.gnmap
68d293bafd960f8582543330eb43b7182a3aa77668de525a66026706d40c4e8a  iot_active/4_router_tcp.nmap
7078aaa6882c0672fbb082fec144c378dad49290dc5ab0289ac5449603fe39e5  iot_active/4_router_tcp.xml
298873e8823e06d27aad0c0e1c77c3a99e0b860d9610588f8264b6e92609e9cc  iot_active/4_router_udp.gnmap
24e7097dd8e357a8184146d4246c1cae5ca4498912ff2346618d81259b1de0f9  iot_active/4_router_udp.nmap
27be90f3d9dd9b4527d644e69c27bf090d611385446f2080086c9e036d8d11c7  iot_active/4_router_udp.xml
cc393b46b47c3b926c6efe9964daccc130ac9274a4188ffe62349c17d17509dc  iot_active/5_v6_tcp.gnmap
b376f4f4241b457504bd53d3e867302dd2f5285ee63934e95c4429c1343e56fd  iot_active/5_v6_tcp.nmap
62e454e9d429ba14a85c5e977b596e0a61f496000ab7147d5e843a2ecb9ffc4e  iot_active/5_v6_tcp.xml
0e06f8ecbcfef56b745767d2e15c247829eeb509b24d7599c0c7c5b5e3c0e637  iot_active/6_rm_gw.gnmap
3b82de87cd9959b1458edab618772afc4b59685e224e99724dbd8061d15f310c  iot_active/6_rm_gw.nmap
a1a23bd9e8d85f0736124a771d4a0b35919916021a9d6774d804adfd7469b4ca  iot_active/6_rm_gw.xml
686095bfcb617fc83571ac53b0a74febfa6d447d9a290860a3b8bdf2aa09e09b  iot_active/context.txt
5dbff55d60e49c745352511b646e0eaeee8b21ceb8c970bcaab1506cf5d0258d  iot_active/iot2lan.finished
22607fddac08e98a89aa764f1df9fd422f6a928b54e018776f81bcf4d12f5c3d  iot_active/iot2lan.started
40f3ba2a149157b52cfe6068a53afa8fa634964712f566550a52a574aa2e02f0  iot_active/terminal_history.txt
941cad8a4487a14bc0befe3da733a6001ecac8e72aa97be78703dc92f65a964a  iot_active/wifi.txt
73e290f13cf24054e8ecc35db0206933ca4934b9a64fb48bf37c8a3b715b4195  iot_retest/hardening_dns6_ont_test_2.txt
9359fc7c0735d5c9600447a525ffdf54024c1c993c86a67b81a6e856d8fc9d29  iot_retest/hardening_dns6_retest.txt
9232dc6bccb6b88a0abfe19a54cac1c5a507ca19573613dc91e308afc2f3d665  iot_retest/r1_router_tcp.gnmap
87ef1775181f82390477feaeb245ac2da312b6b1a12789fb7a745b596a3ec0bf  iot_retest/r1_router_tcp.nmap
eeeb9d5e2da541aac71e8498355eab4c0d39a4d9155caf9f62a018d1da1b7db8  iot_retest/r1_router_tcp.xml
7496c65575f7e1600279f991745b0d347bef00749486bdc5c8b8037c4d270a09  iot_retest/r2_router_alltcp.gnmap
a382ab50b4b72bac2d1ce06f7f4ea081b671b12d7638dd4e17919bef9c3600d4  iot_retest/r2_router_alltcp.nmap
e0e8b5719f0432e98003427ea1bd284e38997a606827e9b2c1c717ca1f564ffb  iot_retest/r2_router_alltcp.xml
80483996f4791ac8bb16efdf23e3bc92e6fde2af6537ac7b29720d2b240d7a4f  iot_retest/r3_router_udp.gnmap
54d2220b34c802d378b32c23c710da8ddd1a29abddc9f0eaaae1b74a93278704  iot_retest/r3_router_udp.nmap
88f5146e71d0aa2fb256161063ba757d6ad0adfa5eac77b5089f47bbcd0352ea  iot_retest/r3_router_udp.xml
5799c068710e276c6b082b7e23c768703d3efa017be97b18200603c8363b26ec  iot_retest/r4_v6.gnmap
488485b453d729e3a133834e58a17044c0aca59cad3a2566e6dc9f61f0ce0726  iot_retest/r4_v6.nmap
1737d6974a8b5f6f13868f3d38bd48161c3d601d19b28e028da57f6747afabd4  iot_retest/r4_v6.xml
1fd02e975083ac55d930e73d29505bc958afabab62d6db7428e326a8895045bd  iot_retest/retest.finished
7d8156096115f9df92fe2825b69bd5b53fa62976de5c793dd0772e0de41eadb9  iot_retest/retest.started
02fa56c655ee0f31a307c5be5e7a33c0fdb0c6e82655a76cb01174ed6c7bd1b8  iot_retest/router_term_out.txt
948021ca340b91a10a6095162f17dcd517fdecd749e7fb20bfe34a887b0de3fe  iot_retest/terminal_history.txt
a6a4a5218ffe8bff7168c75984aacf1df11fe2795763caa3a9c942f17f067a32  nvram.txt
834d7243b5cb54852bd0a34167ee28642b4d3d1fa830abef95a3aa9513eae819  nvram_flat.txt
fe0380973c00830df450e7822386ef60e84c59420a1f43d171fb3c9f1cd63748  nvram_seg.txt
b0bdd63aec0aa9c91992f26692c6df58fd670a278de7f527a4ebef1f2fc24362  nvram_tweak.txt
3758837d7375bdddac2b0f7a665f6f0e2b689c952bd9ad5902a1e23c6ba113e6  pihole_export.csv
fc2621129794f0858abc544ea50df8734282b7f9c81b6540da5807686d1b25d9  pipeline/annotations.csv
21498332ec094960298ea3b78d623a37f33bdf3ec7444d4bb5646521c09b9e73  pipeline/dashboard.py
34a1de47f0b5e52d95591d0ad7a1ed4c0f440e5f981e391dd845a288c8e1c92a  pipeline/guide_images/01a_full_page_top.png
ca7e69dfc0ffff282ace88c36a257e08383d0ef457efd80dffc800cc7f45c18e  pipeline/guide_images/01b_full_page_bottom.png
68cd5c44c77ab4e80b715dc8f958a065d4bc146ff74ad28d184f05fdcd9d8ac7  pipeline/guide_images/02_header_filters_counters.png
f445187d190825a04be9603aa7f716599cc187942a17dbd11687cae4cd2b2a74  pipeline/guide_images/03_detections.png
b88819bdc216ffc955a351b3c061d4fab2c4bf7ffee61d89b7a94f03149513ae  pipeline/guide_images/04_detection_details_baselines.png
36acd19584bb17d6ec0eeb6116aee7efa7d6cebd44d759c14d25ec7378438d8c  pipeline/guide_images/05_profiles_separation.png
d51d911e4af508ffd610eb84f6675473c37d65969a206abe2cb976707e568445  pipeline/guide_images/06_blocked_attempts_device_functions.png
b33624faf9422a79376d53bc61112c767b57a7da9df5d791a51fbcf294cfec82  pipeline/guide_images/07_data_quality_rules.png
8b1c3814e25103b278281c8841cc98763402735c7ab0f105f84e049ae15522ff  pipeline/guide_images/08_example_upload_detections.png
fd99de149380143042bebe76ec1aea262933c681bd1a7b4b2f8c5fc2f27cc33c  pipeline/guide_images/09_example_upload_details.png
72f677638e7d612976392b60a66ebded2d637f222d7b29e5dea73b41e32d3bca  pipeline/guide_images/10_example_vfd_real_only.png
a85d963d1a06f0ffc23c25a78eb10d1aab32f1ccf86595f8da74b76b713af97a  pipeline/iotpipe.py
b2cff3a14d0eb538381099f7ff9dfec7d9dc69840f5efc6ffed517d0e95307c8  pipeline/site.example.toml
e91abfef52442c389529875d88b536129bb4005a5e2473a1f31735f351a98cec  pipeline/site.toml
12133308ecbcf27a9f8732448c32528621d6b6b78e100688e1c59c45e29e3c1a  pipeline/zeek/iot-local.zeek
a65198aebb6eff2530dc3d3b51ec41495ddc10e65331cb0aad1e3f08a292532e  router_states/after_app/conntrack_iot_1401.txt
733a29ef5124dad336929fabb6b95bef811d2119bae6fdd66b75fde1e1336073  router_states/after_app/fw4_counters_1401.txt
8a9fdba993d4c8e4dea47ca687cf30f6ef0642304b386bf9d5c9a999263f503a  router_states/after_app/fw6_counters_1401.txt
1ff1e9f12c40b45570481009dc64a1d812443f160dd80d605c4c1c06e042cfa1  router_states/after_tapo_capture/conntrack_iot_1751.txt
8e5d3f8db6d2a88318e21c6a77f64637105e1dd4d8c07b1917c164f18514e2a2  router_states/after_tapo_capture/fw4_counters_1751.txt
95e3c91279d0a951054b2ade244e3b95b693b61f1b65627b6f1813e6a5f1e8da  router_states/after_tapo_capture/fw6_counters_1751.txt
a728f02ca3e1319ff1d04c4e08bb773225af1e8b27d1ee8880a19ada44ed1788  router_states/before_tapo_capture/conntrack_iot_1643.txt
933aa8e9fcef3b77657eac41ee7eb8e841487df29b500f584d8d58e856612dbd  router_states/before_tapo_capture/fw4_counters_1643.txt
0b3c30e1ba46f3b7b9e20cfada645cb97e2148b1f34f97115b7f9ca554abebfc  router_states/before_tapo_capture/fw6_counters_1643.txt
885201762373a9492c9a362f93efdc2719cb27b6851c44a1b1a4739b88b3089b  router_states/hardening_before_and_after/hardening_after/PTCSRVLAN4_0002.txt
f0b506fbc06549b3c45f127f28ec5137e4b07f57153ef22d2a35be8d34fd5d15  router_states/hardening_before_and_after/hardening_after/PTCSRVLAN6_0002.txt
72a6e821534973b3cf41a287077ad76abd0c0188e4cfa23bdca0fa510d20af8f  router_states/hardening_before_and_after/hardening_after/PTCSRVWAN4_0002.txt
f0b506fbc06549b3c45f127f28ec5137e4b07f57153ef22d2a35be8d34fd5d15  router_states/hardening_before_and_after/hardening_after/PTCSRVWAN6_0002.txt
52e978561266d0cd12b93e743d0b0fa8ce8ce92da5e99283859fc582f0d2f305  router_states/hardening_before_and_after/hardening_after/SDN_FI4_0002.txt
226777180cef2cab20cbce0aae8b845de054a8a9ddf147e3e0db7c893c5ca1ef  router_states/hardening_before_and_after/hardening_after/SDN_FI6_0002.txt
2da6d818b43796e26f78012f06728db92efd3cc9935216bd7a1170af3bf63a1b  router_states/hardening_before_and_after/hardening_after/bridges_0002.txt
da0969bd54a2752f0a30d698492877b325b7922b9bf99a7a95d5b204412d8fbe  router_states/hardening_before_and_after/hardening_after/conntrack_iot_0002.txt
7681fa8c99a38a23dbe40849e3b2c7e61992709eea33e089e919ac2be13c851e  router_states/hardening_before_and_after/hardening_after/fw4_counters_0002.txt
b8fd12c5969530922c3724f6d18480f0aef9b217395cd8a5647cbb3c93ff33e7  router_states/hardening_before_and_after/hardening_after/fw6_counters_0002.txt
b8627db24942d6b12d05246b8dd15362dbe4c56bc0f6fe223267d67b5d9b37a9  router_states/hardening_before_and_after/hardening_after/in4_counters_0002.txt
c366d22a8edf92e15fdbb26ad873e3657990210163609000c89a571560f744f6  router_states/hardening_before_and_after/hardening_after/in6_counters_0002.txt
646c00b662f6890a2b045987df831c5e6e8fa47d5b209baeea1c3843b2640345  router_states/hardening_before_and_after/hardening_after/iot_input4_0002.txt
b8f1e6fd0b3060fe7838ab950286d91266d26e61a7f8969a1a923fdefdaa2ca0  router_states/hardening_before_and_after/hardening_after/iot_input6_0002.txt
70223550ee3e450b8b6921b3faf86f738012f1e5846ad90afc3e82a64757d244  router_states/hardening_before_and_after/hardening_after/ipv6_addr_0002.txt
9a772d12619e851680040593b6acececb3624df091edc1c751ae4bbb5af06a5c  router_states/hardening_before_and_after/hardening_after/nat4_prerouting_0002.txt
2a5d6fbefb747e65e5ca551cebeea2548348029635a614a9c9f7271c0031f8e5  router_states/hardening_before_and_after/hardening_after/nat6_prerouting_0002.txt
944f80bd84dbcf8940449cbef706deda66063a921a09425c73ccd88be5e53dc4  router_states/hardening_before_and_after/hardening_after/ntp_cron_0002.txt
885201762373a9492c9a362f93efdc2719cb27b6851c44a1b1a4739b88b3089b  router_states/hardening_before_and_after/hardening_before/PTCSRVLAN4_2355.txt
f0b506fbc06549b3c45f127f28ec5137e4b07f57153ef22d2a35be8d34fd5d15  router_states/hardening_before_and_after/hardening_before/PTCSRVLAN6_2355.txt
72a6e821534973b3cf41a287077ad76abd0c0188e4cfa23bdca0fa510d20af8f  router_states/hardening_before_and_after/hardening_before/PTCSRVWAN4_2355.txt
f0b506fbc06549b3c45f127f28ec5137e4b07f57153ef22d2a35be8d34fd5d15  router_states/hardening_before_and_after/hardening_before/PTCSRVWAN6_2355.txt
09e3354e446afce08343a4938e60268c4febb5d42b9186a9a66a2ad758372ad9  router_states/hardening_before_and_after/hardening_before/SDN_FI4_2355.txt
226777180cef2cab20cbce0aae8b845de054a8a9ddf147e3e0db7c893c5ca1ef  router_states/hardening_before_and_after/hardening_before/SDN_FI6_2355.txt
2da6d818b43796e26f78012f06728db92efd3cc9935216bd7a1170af3bf63a1b  router_states/hardening_before_and_after/hardening_before/bridges_2355.txt
dec41eefd7bffbb2ddc16e44f7ce7a884f1bfe902648c165029ba1918d995165  router_states/hardening_before_and_after/hardening_before/conntrack_iot_2355.txt
29932a7b2848729c50a7d6d1552ce099f4cab248e81cc97cbac1e63fb0e5bfd3  router_states/hardening_before_and_after/hardening_before/fw4_counters_2355.txt
5fa1618696462af8588ecbddf859fc6d7173652e177ba480647f774d0f22b9ed  router_states/hardening_before_and_after/hardening_before/fw6_counters_2355.txt
960d9842a6727fe6ed119961f8e8829d556c72a6c612947dace16fac1bd53ef4  router_states/hardening_before_and_after/hardening_before/in4_counters_2355.txt
ec5ff97896c7569971c1adf1672dff3d05d644c13d61b72b0fc38fd89521fc75  router_states/hardening_before_and_after/hardening_before/in6_counters_2355.txt
3cb76280852c6a6b30fb45b6dc6867e2e4e87feba3981989c39e5e51cac3ce11  router_states/hardening_before_and_after/hardening_before/iot_input4_2355.txt
9d62d674e716b9594aa984d1395b42b3c0239c9f80c074b166b716b2771d1de6  router_states/hardening_before_and_after/hardening_before/iot_input6_2355.txt
388f8f4c4f9e9d305873425633073f023d6b779aca384f280b9e350886b67ea5  router_states/hardening_before_and_after/hardening_before/ipv6_addr_2355.txt
29b6bd03a932864fd889503eeeb07fbe2dffbab16aef88dc9b8f715d6d047c22  router_states/hardening_before_and_after/hardening_before/nat4_prerouting_2355.txt
6c854c43e9c27cd3aab387a3331f3d83bde98e84370ae982c46ce5fe776380cd  router_states/hardening_before_and_after/hardening_before/nat6_prerouting_2355.txt
944f80bd84dbcf8940449cbef706deda66063a921a09425c73ccd88be5e53dc4  router_states/hardening_before_and_after/hardening_before/ntp_cron_2355.txt
704187536a5c39ea1fa39116c7133f87141bc11fc79fd5b8dc60c92b7840a822  router_states/hardening_dns6_ont_retest_2_before_and_after/hardening_dns6_ont_retest_2_after.txt
2247a6a55eb44fc8a2cb45304afe6bd4b4a35b2d18785810f05d1ca246a8cb93  router_states/hardening_dns6_ont_retest_2_before_and_after/hardening_dns6_ont_retest_2_before.txt
03fc2f5e84597292118e339053e7cb60f0d7b9cc66cb35376c169a86d737101b  router_states/iot_lan_before_and_after/fw4_counters_2157.txt
cb55c2a1ca32809107bba6e2cb63d9013862c930c27121ae836e0097e09f4f05  router_states/iot_lan_before_and_after/fw4_counters_2212.txt
c123cfc460c12f8e6d93a936601e001bd3cbbea889cbdac8e400905d2864ed43  router_states/iot_lan_before_and_after/fw6_counters_2157.txt
2df5084efb921299afbe66f08fa63e68dab4e779a9e74e31abff17297f99beb7  router_states/iot_lan_before_and_after/fw6_counters_2212.txt
f63cfd226bd9e6d9feb4b844f458bd90ee30ac180f6997c5b118fd78c2580a3f  router_states/iot_lan_before_and_after/in4_counters_2157.txt
837b55e18430742d01ee93c744682890bef0b0565cae1c576d1f0d172f6ff0e9  router_states/iot_lan_before_and_after/in4_counters_2212.txt
2e27a0a13a565172e52739e53ce53aa1c47df9af935e8b3822d68184ef3eb9c4  router_states/iot_lan_before_and_after/in6_counters_2157.txt
f1a79f51ad1c96626da205d692c1e6413ffbc35f904336d5573b366d44e6da16  router_states/iot_lan_before_and_after/in6_counters_2212.txt
dca076eec4b101aecc297fdf4b7f8fa2351b7ffc5259126d08580c8e10805484  router_states/upload_before_and_after/upload_after/conntrack_iot_1828.txt
7411f1a25fe1bc5e038f4f039f35a4ea7f73c2e78779b998a3b49ad5b64d503d  router_states/upload_before_and_after/upload_after/fw4_1828.txt
29ddd278a63f1d29f46a5966b8341ea545cdad1e2e0500bd37bcc786efb9afbe  router_states/upload_before_and_after/upload_after/fw6_1828.txt
67a95fe41d293cef70bb396c6efc4cf8ab64977b913368c60d6a12a081b7e8a3  router_states/upload_before_and_after/upload_after/iot_input4_1828.txt
68381ab11f1a643d0c9fa7604b52a76e94dc217a218b3092c2d6f692bed9b953  router_states/upload_before_and_after/upload_after/time_1828.txt
0221a2bb55844da18f8c6d848b8719f936bceb06ddc1b69cc6258b189da04706  router_states/upload_before_and_after/upload_after/wl02_1828.txt
69162db67c838f989a6d423ccfab407f03b82ffef42ccede8b82f39641b94da2  router_states/upload_before_and_after/upload_before/conntrack_iot_1725.txt
2e8e2c8bdeb9d279e030e7ad43b130e85e8b42c5461deafd1caa0880059f98e9  router_states/upload_before_and_after/upload_before/fw4_1725.txt
4f2a4cfd1beca3b9ce958a406e0b5b4d9383531621ddb6ca4c7bee830a29fdd7  router_states/upload_before_and_after/upload_before/fw6_1725.txt
6b142113c607d770a37c33d31b372b66c8e5750bbc09c4440167b843ccc369b3  router_states/upload_before_and_after/upload_before/iot_input4_1725.txt
3d4c3759bddc80074b44aff2d09a663ad143174b0915dc919f199baf02379474  router_states/upload_before_and_after/upload_before/time_1725.txt
eeb4a912309866333c47586a990585fa76548b598f5cbba016f56707bb0ed268  router_states/upload_before_and_after/upload_before/wl02_1725.txt
0c115a5f01f9b27f278d291481d91267903437e17d0255b47303be4928fa8a4d  tools/analyze_pcaps.py
b9e23cec04bc86935fe50b9447cba8ee6b9b0c9419de0737262fc8b5d6244e55  tools/pcap_inventory.py
30b816674f431c323dc857c20fc45e8486c6046a8f07f82761223877289bf8a6  tools/run_zeek.sh
31fba5358c540e5d46781508006e5012ef1edb06fa9a5391e14f86851a70749c  tools/setup_env.sh
a8da9d0c57d756a0fa272ea6ec7d0ba348aee2e272d3ead0bfe3762d2403cd80  tools/summarize_flows.py
4209b2365c200ac82bad9ff8ac06f042ca93e53810cd3d978ad488f42b1f915c  tools/tls_fingerprints.sh
e1a8490f2c2c5548bf763dd12a0dde471655cf087da2ae1491dbb11bf3b687c6  tools/trim_pihole.py
4e70620caef5390915b9ad309b018b9148815c93bb1015edad76feee6cb768ce  tools/volume_eval.py
3a62544e67abe5dcf3cf92f133744ebbab9fc6999be9e144572b9b6ef6711ede  tools/zeek/iot-local.zeek
45bf239e9b99e6b9d94264bd0b3bf8fcf28bf293231abaa70398ef4f140c86ce  upload_run/disabled_services.txt
1418f41efedae483fd8f18cabaf804357ad54e7d9eaa28ff3b499060ac219eb5  upload_run/dnsmasq-1.leases
5235b074f69af93b442bbb8472527701ea0a746416981cda58a263f9cc61cf99  upload_run/mega-ls.txt
49d9a7e980b99563bc572e4829dc1c23dfde22e44588615f772f4be959419e7f  upload_run/pihole_upload_window.csv
7a91c319a19ebbe05277eb653970f952bef03b304699b083b8e6cda7611e14d5  upload_run/timeline.txt
369ba7bb9d6c7692a48b0bdfebd17cb634211b970458b44f407d64bec31c3b9e  upload_run/wifi.txt
```

Git repo `asuswrt-configs`: HEAD `904f54de74edd7c2f5bdc41527dbf6f724023db0`.
