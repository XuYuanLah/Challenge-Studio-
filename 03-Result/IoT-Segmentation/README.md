# IoT Segmentation: team bundle (internal, not for submission)

Sanitised copy of the evidence for teammates' analysis work, built by the owner's
`tools/make_team_bundle.py` from the working folder (git HEAD `904f54de74ed`). Keep it inside the team.
It is an overlay of the main project repo: this part lives in `02-Code/IoT-Segmentation/` and `03-Result/IoT-Segmentation/`;
the final submission bundle uses the same layout.

## Redactions (light on purpose)
| What | Handling |
|---|---|
| Public IPv4 of the household (`<WAN-IPv4>` in the reports) | remapped to `198.51.100.55` everywhere (pcaps: headers and ASCII payloads) |
| Delegated IPv6 prefix (`<PD>`) | remapped to `2001:db8:100::/48` (pcaps: wherever the 6-byte prefix occurs, incl. RA prefix options and DNS answers; text: `2001:db8:100` / `2001:0db8:0100`) |
| ISP-side /64 (`<WAN-RA>`) | remapped to `2001:db8:200:c::/64` |
| Hue Bridge `sso` token (cleartext HTTP to `diag.meethue.com`) | overwritten with `X` in pcaps (same length), `REDACTED-HUE-SSO-TOKEN` in text |
| Roommate VLAN 114 | every 802.1Q-tagged frame dropped from the pcaps (only the flat `eth7` capture had any); the roommate router's MAC (`<RM-MAC>`) remapped to `02:00:00:00:01:14` in pcaps, text and `dnsmasq-sdn.postconf` |
| Kept as is | internal addresses, MACs, host names (incl. the test laptop's), main-LAN multicast in the flat capture |

Every modified frame has its IPv4 header and TCP/UDP/ICMPv6 checksums recomputed, so Wireshark and
Zeek (even without `-C`) accept them. A 4-byte match of the WAN IPv4 inside an encrypted payload would
also be rewritten; that only touches ciphertext.

## Not included
- `Settings_RT-BE88U.CFG`, `nvram*.txt`: router admin credentials and Wi-Fi passphrases. The nvram
  differences that matter are in `segmentation_report.md` section 2.
- `pihole_export.csv`: DNS history of every household client, incl. the roommate. Use
  `03-Result/IoT-Segmentation/derived/pihole_iot_trimmed.csv` (IoT clients, experiment windows only).
- `asuswrt-configs/scripts/ddns-start` (DDNS credential) and the repo's git history (it contains that
  file). `02-Code/IoT-Segmentation/asuswrt-configs/GIT_LOG.txt` has the full commit log with file stats.

## Layout
| Folder | Content |
|---|---|
| `02-Code/IoT-Segmentation/tools/` | Analysis tools: pcap inventory/flow analysis (Python, standard library only), Zeek runner and site policy, tshark JA4/JA3 extraction, Pi-hole trimmer, environment setup |
| `02-Code/IoT-Segmentation/asuswrt-configs/` | Router scripts and configs at git HEAD (firewall policy, VLAN/IPv6, NTP, STP, ONT, mDNS reflector, capture script), minus `ddns-start`; `GIT_LOG.txt` |
| `03-Result/IoT-Segmentation/` | This README, `SHA256SUMS`, `PROVENANCE.tsv`; the intermediate reports (`segmentation_report.md`, `analysis.md`, `evidence_manifest.md`); all evidence: captures (`2026*/`), `firewall_logs/`, `router_states/`, active tests (`iot_active/`, `iot_retest/`), `interaction_timeline.txt`, `derived/` (Pi-hole extract, nmap results, Zeek/flow/TLS outputs) |

The intermediate reports stay here; the main subject report (`01-Subject Report/` in the project repo) is
the team's.

**Paths in the reports** are relative to the old working folder. Evidence paths (`firewall_logs/…`,
`router_states/…`, `derived/…`, the capture folders) resolve inside `03-Result/IoT-Segmentation/`; `tools/…` and
`asuswrt-configs/…` resolve inside `02-Code/IoT-Segmentation/`. The E-numbers refer to `evidence_manifest.md` here.

## Integrity
`SHA256SUMS` covers both subfolders, with paths relative to the repo root: run
`sha256sum -c "03-Result/IoT-Segmentation/SHA256SUMS"` from there. `PROVENANCE.tsv` maps
each bundle file to its working-folder source, the source's SHA-256 (the working folder's `SHA256SUMS`,
which `evidence_manifest.md` lists) and the transformation applied. Files under `derived/zeek/`,
`derived/analysis/`, `derived/tls/` and `derived/pcap_inventory.json` were computed from the original
pcaps and then text-redacted; re-running the tools on these pcaps gives the same results apart from the
remapped addresses (VLAN-tagged frames were already excluded by the tools).

## Re-running the tools
The tools expect the evidence next to `tools/`. From the repo root:
```sh
cd "03-Result/IoT-Segmentation" && ln -s "../../02-Code/IoT-Segmentation/tools" tools   # or copy the tools folder here
tools/setup_env.sh                                 # tshark, Zeek 8.0, nmap, jq (Debian)
tools/run_zeek.sh; tools/tls_fingerprints.sh       # write derived/zeek/, derived/tls/
python3 tools/analyze_pcaps.py; python3 tools/summarize_flows.py
```
`tools/trim_pihole.py` needs the full Pi-hole export, which isn't included. `tools/build_manifest.py`
renders `evidence_manifest.md` from the working folder's hashes and needs the excluded originals, so it
won't run here; use this bundle's `SHA256SUMS` instead.
