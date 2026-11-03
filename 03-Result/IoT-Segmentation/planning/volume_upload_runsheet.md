# Run sheet: simulated volume-upload scenario (detection test)

Closes **Learning Contract metric 1** (the last planned scenario; `analysis.md` §9 and §11). The test host is the MacBook on `I0N_IoT`, standing in for a misbehaving IoT device, as in §14/§15. The upload target is **the owner's own MEGA account**, containing only random test data. No IoT device, no third-party data and no one else's account is involved.

**Why MEGA:** cloud storage like MEGA is a documented, real-world staging point for stolen data (e.g. ransomware and APT operators uploading with `rclone` or MEGA's own tools). Using it makes the scenario realistic: TLS to a large, legitimate cloud service, not to an obviously odd server.

**Duration:** about 75 min (60 min capture plus setup and saving). The function checklist's restarts (D1/D2) must **not** fall inside the capture window.

---

## 1. Pre-registered detection criteria (fix these before the run)

The MacBook has no per-device baseline, so R3 ("hourly external bytes out > 10× the device's median") can't be applied to it unchanged. Both variants are fixed now, from the segmented 24 h capture (`derived/analysis/summary_seg_*.json`, IP-layer bytes):

| Variant | Baseline | Threshold (10×) | Meaning |
|---|---|---|---|
| **R3-seg** (primary) | highest device median hourly upload in the segment: Hue Bridge, **206,309 B/h** | **≈ 2.06 MB/h** for any IoT-VLAN host | more than ten times what the busiest device normally uploads |
| **R3-dev** (comparison) | as if the traffic came from the Tapo plug: median **76 B/h** | **760 B/h** | how much tighter a per-device baseline is for quiet devices |

**The test host is noisier than any IoT device.** It's a general-purpose laptop that also runs services; §15.6 already noted its background pings, sync traffic and an app retrying a homelab service. Its own background could cross R3-seg with no upload at all. So every run is evaluated two ways, both fixed now:
- **Host total:** all external bytes from the MacBook per hour. This is what the rule would see in practice.
- **Scenario-attributed:** only flows to MEGA (identified by TLS SNI / DNS: `*.mega.nz`, `*.mega.co.nz`, `*.userstorage.mega.co.nz`). This isolates the scenario from the laptop's noise.
- The **10-minute quiet period** before Run A measures the background rate. If the background alone exceeds 2.06 MB/h, that's recorded as a finding: an IoT-tuned volume rule flags general-purpose hosts on the IoT VLAN, which also ties in with the Keychain side finding (§14.5, §15.6).

Also expected:
- **R1:** a new destination domain for the host (Pi-hole query, TLS SNI).
- **`IOT_TO_WAN_NEW`:** every new connection logged with the host's own address.

Expected outcome (judged on the **scenario-attributed** bytes):

| Run | Volume | R3-seg | R3-dev | Purpose |
|---|---|---|---|---|
| **A: bulk** | 100 MB in one upload | fires | fires | the scenario as planned |
| **B: slow** | 16 kB/min for 30 min (≈ 0.96 MB/h plus MEGA API overhead) | **doesn't fire** (below 2.06 MB/h by design) | fires | a limit of segment-wide thresholds, for the report |

## 2. Preparation

| # | Step | Notes |
|---|---|---|
| 2.1 | **MEGA:** use a separate or throwaway account (the free tier is enough). Install **MEGAcmd** on the MacBook. | `rclone`'s `mega` backend is the "actor-realistic" alternative, but MEGAcmd is more reliable. Don't put the account e-mail in any shared file; write `<MEGA-ACCOUNT>`. |
| 2.2 | **Log in before the capture** (`mega-login <email>`) and create the folder: `mega-mkdir /upload_run`. | Keeps login traffic out of the run windows; the session stays in MEGAcmd's server process. |
| 2.3 | **Pi-hole check:** `pihole -q mega.nz` and `pihole -q userstorage.mega.co.nz` (or the web UI). | If MEGA is blocked, the upload fails; don't allowlist it for the run. A blocked upload is itself a result (R5-type), but then decide whether to rerun with an owned endpoint. |
| 2.4 | **Payloads:**<br>`mkdir -p ~/upload_run && cd ~/upload_run`<br>`dd if=/dev/urandom of=bulk.bin bs=1m count=100` | Random data: MEGA encrypts client-side anyway, and random data can't compress. |
| 2.5 | **Router capture disk:** `df -h /tmp/mnt/opt` | ≥ 1 GB free. |

### 2.6 Keep other Apple devices off `I0N_IoT` (Keychain)
**Starting point (2026-10-28): clean.** `I0N_IoT` is no longer in iCloud Keychain, and no Apple device is on it. The steps below keep it that way: joining from the MacBook with Keychain on would sync the password to every device again.

| # | Where | Step |
|---|---|---|
| a | (done) | `I0N_IoT` removed from Keychain on all devices (recommendation 17). |
| b | MacBook | System Settings → Apple Account → iCloud → Passwords (Keychain) → **off**, keep the local items. |
| c | MacBook | Join `I0N_IoT` by typing the password. It isn't synced now. |
| d | Router | Before starting the capture, check the IoT leases: `grep 192.168.107. /var/lib/misc/dnsmasq-1.leases`. Expect exactly these eight: Hue `.26`, SwitchBot `.15`, Tapo `.23`, Matter switches `.17` / `.20`, **Meross plug `.2` (`c4:e7:ae:20:54:57`)**, **VFD clock `.22` (`d8:f1:5b:90:ee:b3`)**, and the MacBook. Note anything else, and any changed address. |
| e | after the run | MacBook: **forget `I0N_IoT` first, then** turn Keychain back on. Otherwise the password syncs to every device again. |

### 2.7 Quiet the MacBook (reduces, doesn't remove, the noise)
Quit or pause before the capture, and note what was left running:
- cloud sync: iCloud Drive (Optimize/sync pause), Dropbox/OneDrive/Google Drive, Photos;
- backups and updates: Time Machine, software and App Store updates;
- browsers, messaging and mail clients;
- the app that retried the homelab service on 38443, and the background ping monitor (§15.6);
- the services you host on it, if they talk outward.

Leave Wi-Fi and MEGAcmd running.

## 3. Run

Times are local. Log every step to the MacBook timeline with
`t(){ echo "$1: $(date +%s) $(date)" >> ~/upload_run/timeline.txt; }`.

**Router (SSH from the main LAN).** Define the snapshot helper once per session:
```sh
snap() { d=/tmp/upload_$1; mkdir -p $d; t=$(date +%H%M)
  iptables  -vnL FORWARD --line-numbers > $d/fw4_$t.txt
  ip6tables -vnL FORWARD --line-numbers > $d/fw6_$t.txt
  iptables  -vnL IOT_INPUT --line-numbers > $d/iot_input4_$t.txt
  grep -E '192\.168\.107\.|fd00:d:e:6b:' /proc/net/nf_conntrack > $d/conntrack_iot_$t.txt
  for f in rx_bytes tx_bytes; do echo "wl0.2 $f $(cat /sys/class/net/wl0.2/statistics/$f)"; done > $d/wl02_$t.txt
  date > $d/time_$t.txt; }
```

| # | Where | Step |
|---|---|---|
| 3.1 | MacBook | Record `ifconfig en0` and `networksetup -getinfo Wi-Fi` to `~/upload_run/wifi.txt`. Check the address is `192.168.107.8` with private MAC `b2:1c:d7:ba:85:9d` (if not, just record the new values). Note which services from 2.7 are still running. |
| 3.2 | Router | `snap before` |
| 3.3 | Router | `/jffs/scripts/iot-capture.sh -b -d 60m` (both `wl0.2` and `eth7`, offload disabled automatically). Note the output folder it prints. |
| 3.4 | MacBook | `t "Capture started"`; **wait 10 min without touching the Mac** (quiet period, used to measure the background rate). |
| 3.5 | MacBook | **Run A:** `t "Run A start"`; `mega-put ~/upload_run/bulk.bin /upload_run/`; `t "Run A end"`. |
| 3.6 | MacBook | Wait 5 min. **Optional (side discovery, not part of the scenario):** power-cycle the VFD clock (VCK 0658-L) now and `t "VFD clock power cycle"`, so its boot, DHCP and NTP exchange land in the capture (MAC `d8:f1:5b:90:ee:b3`, last seen at `.22`). |
| 3.7 | MacBook | **Run B:** `t "Run B start"`;<br>`for i in $(seq 30); do head -c 16384 /dev/urandom > ~/upload_run/s_$i.bin; mega-put ~/upload_run/s_$i.bin /upload_run/; rm ~/upload_run/s_$i.bin; sleep 60; done`;<br>`t "Run B end"` |
| 3.8 | MacBook | Wait until the capture stops by itself (60 min from 3.3). `t "Capture ended"`. |
| 3.9 | Router | `snap after` |
| 3.10 | Router | Firewall log for the window, both files (the log rotates):<br>`grep -hE 'IOT_TO_WAN_NEW\|IOT_TO_LAN_DROP\|IOT_TO_ROUTER_DROP\|IOT_DNS_REDIRECT' /tmp/syslog.log-1 /tmp/syslog.log > /tmp/FW_upload.log` |
| 3.11 | Pi-hole | Export the window:<br>`sqlite3 -header -csv /etc/pihole/pihole-FTL.db "SELECT * FROM queries WHERE timestamp BETWEEN <start_epoch> AND <end_epoch> AND client LIKE '192.168.107.%';" > pihole_upload_window.csv` |
| 3.12 | MacBook | `mega-ls -l /upload_run` (expect 100 MB plus 30 × 16 kB) and save the output to `~/upload_run/mega_ls.txt`; then `mega-rm -r -f /upload_run`, empty the MEGA rubbish bin, `mega-logout`. |

## 4. What to bring back (into the working folder)

| Destination | Content |
|---|---|
| `<YYYYMMDD-HHMMSS>_upload/` | the capture folder from 3.3 as is (`wl0.2_*.pcap`, `eth7_*.pcap`, `run.log`, `*.log`). Same naming as the other captures, so `tools/run_zeek.sh` picks it up. |
| `router_states/upload_before_and_after/` | the two `snap` folders (`/tmp/upload_before`, `/tmp/upload_after`) |
| `firewall_logs/FW_upload.log` | from 3.10 |
| `upload_run/` | `timeline.txt`, `wifi.txt` (plus the list of services still running), `pihole_upload_window.csv`, `mega_ls.txt`, the lease check from 2.6 d. No MEGA credentials. |

Also append the run's timeline lines to `interaction_timeline.txt`, in the same format as the existing lines.

## 5. Evaluation (I'll do this once the files are in)

1. Hash the new evidence (new E-IDs; `python3 tools/build_manifest.py --sums`).
2. Zeek over the new capture (`tools/run_zeek.sh`). From `conn.log` (`orig_ip_bytes`, IP layer, the same unit as the baseline), compute hourly external upload for the MacBook, both the **host total** and **MEGA-attributed** (flows matched via `ssl.log` SNI / `dns.log`). Get the background rate from the quiet period. Cross-check against the router's `wl0.2` byte counters and `mega_ls.txt`.
3. Apply R3-seg and R3-dev per hour and per run window, to both totals. Check R1 (Pi-hole, SNI) and match the `IOT_TO_WAN_NEW` entries.
4. **Control:** check that the five baselined IoT devices' hourly upload stays within baseline in the same window. The two new devices (Meross plug, VFD clock) have no baseline yet; their traffic is described as first observations, not used as a control. They're added to the device map in `tools/analyze_pcaps.py` for this capture (a tool change, rehashed).
5. Write `analysis.md` §16, update metric 1 (expected: **met**) and the limitations (slow exfiltration; noisy general-purpose hosts on an IoT VLAN), then run the consistency check.

## 6. Abort and cleanup

- **Stop the capture early:** `kill "$(cat /tmp/mnt/opt/captures/current.pid)"` (offload is restored automatically).
- **Check offload is back on** after the run: `fc status`, `runner status`.
- Delete the payloads locally and in MEGA (3.12), log out of MEGAcmd, and leave `I0N_IoT`.
- **Keychain:** forget `I0N_IoT` on the MacBook *before* turning iCloud Keychain back on (2.6 e). To keep the other devices off the IoT SSID for good (recommendation 17), leave it removed from Keychain.
