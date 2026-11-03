# Function checklist: state E (template)

Closes **Learning Contract metric 4** ("all documented required device functions continue after segmentation"; `analysis.md` §9, gap: *a written function checklist, including remote access via the HomePod while away*).

**How to use:** copy this file to `function_check/function_checklist_<YYYYMMDD>.md`, fill it in during the run, and put the screenshots in `function_check/screenshots/`, named after the row ID (e.g. `A3_tapo_home_app.png`). The filled copy and the screenshots become evidence (new E-IDs). This template stays in `planning/` and isn't evidence.

**Result codes:** ✅ pass · ⚠️ pass with a remark · ❌ fail · n/a not applicable (say why)

---

## 0. Run details

| Item | Value |
|---|---|
| Date |  |
| Tester | |
| Router state | E (repo `904f54d`; confirm no undeployed changes: `md5sum /jffs/scripts/firewall-start` vs the repo copy) |
| Router uptime at start (`uptime`) | |
| iPhone | on main Wi-Fi (`ASUS_BE88U_I0N*`), *not* on `I0N_IoT` |
| Start / end time | |

## P. Preconditions (check before anything else)

| ID | Check | How | Expected | Result | Time | Evidence |
|---|---|---|---|---|---|---|
| P1 | HomePod is on the **main LAN** | router: `grep -i ac:bc:b5:d3:d1:dd /var/lib/misc/dnsmasq.leases` (or the web UI client list) | address `192.168.0.22`, **not** `192.168.107.x` (it drifted onto the IoT SSID once; analysis §15.6) | | | |
| P2 | All IoT devices hold IoT leases | router: `grep 192.168.107. /var/lib/misc/dnsmasq-1.leases` | Hue `.26`, SwitchBot `.15`, Tapo `.23`, switches `.17` / `.20`; plus the two newer devices: Meross plug `.2` (`c4:e7:ae:20:54:57`), VFD clock `.22` (`d8:f1:5b:90:ee:b3`) | | | |
| P3 | No other personal device on `I0N_IoT` | same lease file, plus the web UI client list | only the seven devices in P2 (and the MacBook if it's in use for the upload scenario). Keychain is clean since 2026-10-28. | | | |
| P4 | Hardening active | router: `iptables -nL IOT_INPUT \| head -3`; `iptables -t nat -nL PREROUTING \| grep -c IOT_DNS_REDIRECT` | chain present; 2 redirect LOG rules | | | |

## A. Local control (Apple Home / Matter)

| ID | Function | Test step | Expected | Result | Time | Evidence |
|---|---|---|---|---|---|---|
| A1 | Hue lights via Matter | Home app: toggle one Hue light on → off | changes within ~2 s, state shown correctly | | | |
| A2 | SwitchBot Bot via Matter bridge | Home app: press one Bot | Bot actuates; tile updates | | | |
| A3 | Tapo plug | Home app: toggle the plug on → off | relay clicks; power reading updates | | | |
| A4 | Matter switch `0d6b` | Home app: toggle | switch actuates, no "No Response" | | | |
| A5 | Matter switch `0d6e` | Home app: toggle | as A4 | | | |
| A6 | Status reports (the Matter fix, analysis §5.4) | leave the Home app closed ≥ 5 min, then change a device **physically** (switch button / plug button), open the app | new state shown without a manual refresh; router: `grep IOT_TO_LAN_DROP /tmp/syslog.log \| grep -c 5540` = 0 for the window | | | |
| A7 | HomeKit scene | run a scene that includes ≥ 2 IoT devices | all included devices change | | | |
| A8 | HomeKit automation | trigger an automation that includes an IoT device (time-based: set it 2 min ahead) | runs on time (executed by the HomePod) | | | |
| A9 | Eve Room (Thread, via the HomePod) | Home app: Eve Room readings | values current (timestamp within minutes); confirms the hub's Thread side is fine | | | |

## B. Vendor apps

| ID | Function | Test step | Expected | Result | Time | Evidence |
|---|---|---|---|---|---|---|
| B1 | Hue app, local | iPhone on main Wi-Fi: Hue app, toggle a light | works (local HTTPS to the bridge) | | | |
| B2 | Hue app, bridge status | Hue app → Settings → Hue Bridges | bridge "connected", software up to date (or update available) | | | |
| B3 | Tapo app | toggle the plug; open energy usage | works; usage data present | | | |
| B4 | SwitchBot app | open the hub; press a Bot | works; hub online | | | |

## C. Remote access (the explicit gap)

Turn **Wi-Fi off** on the iPhone (cellular only) for the whole section.

| ID | Function | Test step | Expected | Result | Time | Evidence |
|---|---|---|---|---|---|---|
| C1 | Home app remote control via the HomePod | toggle a Hue light, the Tapo plug and one Matter switch | each changes; Home app shows "home hub connected" | | | |
| C2 | Remote status | change a device physically (someone at home, or use C1's result) and watch the Home app | state updates remotely | | | |
| C3 | Hue app remote | toggle a light in the Hue app (cloud path) | works | | | |
| C4 | Tapo / SwitchBot apps remote | one action each | works | | | |

## D. Resilience (state E fixes under load)

Run D1 first, then D2 only if you're fine with a full reboot.

| ID | Function | Test step | Expected | Result | Time | Evidence |
|---|---|---|---|---|---|---|
| D1 | Wireless restart | router: `service restart_wireless`; wait 3 min; then `for b in br0 br52 br56; do echo $b $(cat /sys/class/net/$b/bridge/stp_state); done`; `ip -6 addr show dev br52 \| grep fd00:d:e:6b::1`; repeat A1, A3, A4, A5 | STP 1 / 0 / 1; IoT ULA present; all four controls work within 3 min (note any device that needs longer) | | | |
| D2 | Router reboot | reboot; note the time the web UI is back; then P2 and A1–A5 | all devices leased and controllable; note the slowest device's recovery time | | | |
| D3 | Matter sessions after D1/D2 | router: `grep -E 'port=5540' /proc/net/nf_conntrack \| grep -cE '192\.168\.107\.\|fd00:d:e:6b:'` | ≥ 5 (HomePod ↔ each Matter device) | | | |

## E. Background services

| ID | Function | Test step | Expected | Result | Time | Evidence |
|---|---|---|---|---|---|---|
| E1 | NTP for IoT | router: `ps w \| grep '[n]tp -n -l -I br52'`; the counter `iptables -vnL IOT_INPUT \| grep 'dpt:123'` rises over 15 min | VLAN ntpd running; requests served | | | |
| E2 | DNS via Pi-hole | Pi-hole query log, filtered on `192.168.107.` | queries from the devices in the last hour, all answered | | | |
| E3 | Firmware-update path | Hue / Tapo / SwitchBot apps: "check for updates" | check succeeds (an update needn't be available) | | | |
| E4 | Newer devices (informative; not in the documented function set) | Meross plug: toggle in its app; VFD clock: shows the correct time after its NTP sync | both work; record anything unusual | | | |

---

## Summary (fill in last)

| Section | Pass | Remarks | Fail |
|---|---|---|---|
| P preconditions | | | |
| A local control | | | |
| B vendor apps | | | |
| C remote access | | | |
| D resilience | | | |
| E background | | | |

**Overall:** metric 4 met / not met. List every ⚠️ / ❌ with a cause and a follow-up.

**Router snapshot at the end** (saved with the evidence): `iptables -vnL FORWARD --line-numbers`, `iptables -vnL IOT_INPUT`, `grep -E '192\.168\.107\.|fd00:d:e:6b:' /proc/net/nf_conntrack`, and `grep -hE 'IOT_(TO_LAN_DROP|TO_ROUTER_DROP)' /tmp/syslog.log-1 /tmp/syslog.log` for the run window (expect no real-device entries).
